import sys
import os
import uvicorn

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

print("=" * 80)
print("[+] STARTING SENTINEL - AUTONOMOUS CYBER INCIDENT INVESTIGATION PLATFORM")
print("=" * 80)

# Verify python dependencies
try:
    import fastapi
    import networkx
    import pydantic
    print("✅ All required Python packages detected (FastAPI, NetworkX, Pydantic).")
except ImportError as e:
    print(f"❌ Missing dependency: {e}. Installing packages...")
    os.system("pip install fastapi uvicorn networkx pydantic python-multipart jinja2")

# Run self-check on backend modules
from backend.ingestion import ingestion_engine
from backend.agent import agent_orchestrator
from backend.demo_dataset import demo_dataset_builder

print("🧪 Running self-verification test on autonomous pipeline...")
demo_files = demo_dataset_builder.generate_demo_files()
processed = [ingestion_engine.process_file(df["filename"], df["content_bytes"]) for df in demo_files]
case_res = agent_orchestrator.run_autonomous_investigation(processed)

print(f"✅ Self-Verification Complete! Case ID: {case_res['case_id']}")
print(f"   • Risk Rating: {case_res['risk']['risk_severity']} ({case_res['risk']['risk_score']}/100)")
print(f"   • Confidence Score: {case_res['risk']['confidence_score']}%")
print(f"   • Graph Nodes: {case_res['graph']['total_nodes']} | Edges: {case_res['graph']['total_edges']}")
print(f"   • Audit Steps Executed: {len(case_res['audit_trail'])}")
print(f"   • Response Actions Recommended: {len(case_res['pending_response_actions'])}")

print("\n🚀 Launching SENTINEL Web Dashboard on http://localhost:8000 ...")
if __name__ == "__main__":
    uvicorn.run(
    "backend.app:app",
    host="0.0.0.0",
    port=int(os.environ.get("PORT", 8000)),
    reload=False
)
