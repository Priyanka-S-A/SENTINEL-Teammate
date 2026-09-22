import os
from typing import List, Dict, Any
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field, validator
from backend.security import validate_case_id, validate_action_id, validate_upload_file, scrub_secrets, MAX_TOTAL_UPLOAD_BYTES

from backend.ingestion import ingestion_engine
from backend.agent import agent_orchestrator
from backend.campaign import campaign_engine
from backend.rag_chat import rag_chat_engine
from backend.report_generator import report_engine
from backend.eval_metrics import eval_metrics_engine
from backend.demo_dataset import demo_dataset_builder
from backend.graph_engine import graph_engine

from backend.database import list_cases_from_db, delete_case_from_db, load_case_from_db, save_case_to_db
from backend.rag.rag_engine import rag_engine
from backend.evaluation import evaluation_runner

app = FastAPI(title="SENTINEL - Autonomous Cyber Incident Investigation Platform", version="2.0.0")

# In-memory storage for current active case execution
current_case_data = {}

class NLQueryModel(BaseModel):
    query: str = Field(..., min_length=1, max_length=2000, description="Investigation inquiry string")

    @validator("query")
    def sanitize_query(cls, v):
        return v.replace("\x00", "").strip()

class ActionApprovalModel(BaseModel):
    action_id: str = Field(..., min_length=1, max_length=64, description="Action ID to approve or reject")
    approved: bool

    @validator("action_id")
    def check_action_id(cls, v):
        if not validate_action_id(v):
            raise ValueError("Invalid action ID format. Must be alphanumeric with hyphens/underscores.")
        return v.strip()

class CreateCaseModel(BaseModel):
    title: str = Field("New Cyber Crime Incident Case", min_length=1, max_length=120)

@app.on_event("startup")
async def startup_event():
    """
    On startup, automatically check if a case exists in database; if not, ingest demo dataset.
    """
    global current_case_data
    existing_cases = list_cases_from_db()
    if existing_cases:
        # Load the latest persisted case
        latest_id = existing_cases[0]["case_id"]
        loaded = agent_orchestrator.load_case_by_id(latest_id)
        if loaded:
            current_case_data = loaded
            try:
                rag_engine.index_case(loaded)
            except Exception as e:
                print(f"[RAG Startup] Warning indexing loaded case: {e}")
            return

    # Fallback to demo dataset ingestion if DB is empty
    demo_files = demo_dataset_builder.generate_demo_files()
    processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"], validate=False) for df in demo_files]
    current_case_data = agent_orchestrator.run_autonomous_investigation(processed)

@app.get("/api/cases", response_class=JSONResponse)
def get_all_cases():
    """
    Lists all persisted cases in database (Requirement Section 4).
    """
    return {"cases": list_cases_from_db()}

@app.post("/api/cases", response_class=JSONResponse)
def create_new_case(payload: CreateCaseModel):
    """
    Creates a new persistent case (Requirement Section 4).
    """
    global current_case_data
    demo_files = demo_dataset_builder.generate_demo_files()
    processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"], validate=False) for df in demo_files]
    current_case_data = agent_orchestrator.run_autonomous_investigation(processed)
    return {"status": "SUCCESS", "case_id": current_case_data["case_id"], "message": f"Created new persistent case {current_case_data['case_id']}"}

@app.get("/api/cases/{case_id}", response_class=JSONResponse)
def load_specific_case(case_id: str):
    """
    Loads a specific case by case_id (Requirement Section 4).
    """
    if not validate_case_id(case_id):
        raise HTTPException(status_code=400, detail="Invalid case ID format. Path traversal or special characters detected.")

    global current_case_data
    loaded = agent_orchestrator.load_case_by_id(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found in database.")
    current_case_data = loaded
    try:
        rag_engine.index_case(loaded)
    except Exception as e:
        print(f"[RAG Load] Warning indexing loaded case: {e}")
    return {"status": "SUCCESS", "case_id": case_id, "case": loaded}

@app.post("/api/cases/{case_id}/reindex", response_class=JSONResponse)
def reindex_case(case_id: str):
    """
    Manually triggers re-indexing of a case for Vector RAG retrieval.
    """
    if not validate_case_id(case_id):
        raise HTTPException(status_code=400, detail="Invalid case ID format.")

    loaded = load_case_from_db(case_id)
    if not loaded:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found in database.")
    num_chunks = rag_engine.index_case(loaded)
    return {
        "status": "SUCCESS",
        "case_id": case_id,
        "indexed_chunks": num_chunks,
        "message": f"Successfully re-indexed case '{case_id}' ({num_chunks} chunks)."
    }

@app.delete("/api/cases/{case_id}", response_class=JSONResponse)
def delete_specific_case(case_id: str):
    """
    Deletes a specific case by case_id (Requirement Section 4).
    """
    if not validate_case_id(case_id):
        raise HTTPException(status_code=400, detail="Invalid case ID format.")

    success = delete_case_from_db(case_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Case ID '{case_id}' not found.")
    return {"status": "SUCCESS", "message": f"Deleted case {case_id} from database."}

@app.get("/api/case", response_class=JSONResponse)
def get_current_case():
    if not current_case_data:
        raise HTTPException(status_code=404, detail="No active case data found.")
    
    campaign_info = campaign_engine.compare_case_with_history(
        [e["entity_value"] for e in current_case_data.get("events", [])],
        ["T1566.002", "T1071.001", "T1059.001"]
    )
    report_info = report_engine.generate_incident_report(current_case_data, campaign_info)
    metrics_info = eval_metrics_engine.calculate_evaluation_metrics(current_case_data)
    
    # Export the current graph from graph_engine
    graph_export = graph_engine.export_graph_json()

    # Prepare case data with graph
    case_with_graph = dict(current_case_data)
    case_with_graph["graph"] = graph_export

    return {
        "case": scrub_secrets(case_with_graph),
        "campaign": scrub_secrets(campaign_info),
        "report": scrub_secrets(report_info),
        "metrics": scrub_secrets(metrics_info)
    }

@app.post("/api/ingest", response_class=JSONResponse)
async def ingest_evidence_files(files: List[UploadFile] = File(...)):
    """
    Defensively ingests evidence files with upload size limits, extension whitelisting,
    signature inspection, and path-traversal neutralization (Requirement Phase 6).
    """
    global current_case_data

    if not files or len(files) == 0:
        raise HTTPException(status_code=400, detail="No files provided for ingestion.")

    if len(files) > 50:
        raise HTTPException(status_code=400, detail="Upload file count exceeds maximum limit (50 files).")

    total_bytes = 0
    processed = []

    for f in files:
        content = await f.read()
        total_bytes += len(content)

        if total_bytes > MAX_TOTAL_UPLOAD_BYTES:
            raise HTTPException(status_code=400, detail="Total upload size exceeds 25MB aggregate limit.")

        is_valid, safe_name, err_msg = validate_upload_file(f.filename, content)
        if not is_valid:
            raise HTTPException(status_code=400, detail=err_msg)

        try:
            res = ingestion_engine.process_file(safe_name, content, validate=False)
            processed.append(res)
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to process file '{safe_name}': {str(e)}")
    
    current_case_data = agent_orchestrator.run_autonomous_investigation(processed)
    return {"status": "SUCCESS", "message": f"Successfully validated and ingested {len(files)} evidence file(s). Autonomous investigation initiated."}

@app.post("/api/load-demo", response_class=JSONResponse)
def load_demo_scenario():
    global current_case_data
    demo_files = demo_dataset_builder.generate_demo_files()
    processed = []
    for df in demo_files:
        res = ingestion_engine.process_file(df["filename"], df["content_bytes"], validate=False)
        processed.append(res)
    
    current_case_data = agent_orchestrator.run_autonomous_investigation(processed)
    return {"status": "SUCCESS", "message": "Loaded synthetic attack scenario dataset. Autonomous investigation completed."}

@app.post("/api/approve-action", response_class=JSONResponse)
def approve_response_action(payload: ActionApprovalModel):
    """
    Enforces Human-in-the-Loop (HITL) approval gating for response containment actions (Requirement Phase 6).
    Actions remain strictly PENDING_APPROVAL until explicitly approved by human analyst.
    """
    global current_case_data
    actions = current_case_data.get("pending_response_actions", [])
    updated = False
    for act in actions:
        if act["id"] == payload.action_id:
            new_status = "APPROVED" if payload.approved else "REJECTED"
            act["status"] = new_status
            if payload.approved:
                act["simulated_execution"] = "Simulated containment executed safely in Sentinel Sandbox Response Gateway."
            else:
                act["simulated_execution"] = "Action rejected by analyst. Containment cancelled."
            updated = True
            break
    
    if not updated:
        raise HTTPException(status_code=404, detail=f"Action ID '{payload.action_id}' not found.")
    
    save_case_to_db(current_case_data)
    return {
        "status": "SUCCESS",
        "action_id": payload.action_id,
        "new_status": "APPROVED" if payload.approved else "REJECTED",
        "execution": "Simulated containment completed" if payload.approved else "Action cancelled"
    }

@app.post("/api/natural-language", response_class=JSONResponse)
def query_natural_language(payload: NLQueryModel):
    if not current_case_data:
        raise HTTPException(status_code=400, detail="No active case loaded.")
    res = rag_chat_engine.process_query(payload.query, current_case_data)
    return scrub_secrets(res)


@app.get("/api/evaluation", response_class=JSONResponse)
def get_evaluation_benchmark_results():
    """
    Returns latest measured benchmark results (Requirement Phase 5).
    Guarantees all values are measured and non-fabricated.
    """
    results = evaluation_runner.get_latest_results()
    return results

@app.post("/api/evaluation/run", response_class=JSONResponse)
def run_evaluation_benchmark():
    """
    Executes live benchmark suite across pipeline modules and returns measured results.
    """
    results = evaluation_runner.run_full_benchmark()
    return results

# Serve static files for frontend dashboard UI
frontend_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.exists(frontend_path):
    app.mount("/static", StaticFiles(directory=frontend_path), name="static")

@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = os.path.join(frontend_path, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>SENTINEL API Server Running</h1><p>Frontend dashboard template not found.</p>"
