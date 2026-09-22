"""
SENTINEL Phase 4 End-to-End Natural Language QA Endpoint Verification Script
Tests POST /api/natural-language with query: "What evidence connects the phishing email to the endpoint?"
Verifies Phase 4 Vector RAG response fields and citation payload structure.
"""

import os
import sys
import json

# Force UTF-8 stdout for Windows console compatibility
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from backend.agent import agent_orchestrator
from backend.demo_dataset import demo_dataset_builder
from backend.ingestion import ingestion_engine
from backend.app import app
from fastapi.testclient import TestClient

client = TestClient(app)

def main():
    print("Initializing active case via /api/load-demo endpoint...")
    demo_resp = client.post("/api/load-demo")
    print(f"Load demo status: {demo_resp.status_code}")

    test_query = "What evidence connects the phishing email to the endpoint?"
    print(f"\nSubmitting POST /api/natural-language query: '{test_query}'...")
    
    response = client.post("/api/natural-language", json={"query": test_query})
    print(f"HTTP Status Code: {response.status_code}")
    
    if response.status_code != 200:
        print(f"[FAILED] HTTP error: {response.text}")
        return 1

    data = response.json()
    print("\n--- RECEIVED API RESPONSE JSON ---")
    print(json.dumps(data, indent=2))

    # Verification Checks
    checks = []
    
    # 1. Retrieval Method
    method = data.get("retrieval_method")
    if method == "vector":
        print(f"[PASSED] retrieval_method: '{method}'")
        checks.append(True)
    else:
        print(f"[FAILED] Unexpected retrieval_method: '{method}'")
        checks.append(False)

    # 2. Answer Text Present
    ans = data.get("answer", "")
    if ans and len(ans) > 20:
        print(f"[PASSED] Answer generated ({len(ans)} chars)")
        checks.append(True)
    else:
        print("[FAILED] Missing or empty answer")
        checks.append(False)

    # 3. Sources / Citations Present
    sources = data.get("sources", [])
    citations = data.get("citations", [])
    if len(sources) > 0 and len(citations) > 0:
        print(f"[PASSED] Returned {len(sources)} source citations")
        print(f"Top citation: ID={sources[0].get('chunk_id')}, Source={sources[0].get('source_file')}, Score={sources[0].get('relevance_score')}")
        checks.append(True)
    else:
        print("[FAILED] Missing citations in response payload")
        checks.append(False)

    # 4. Retrieved Chunks
    ret_chunks = data.get("retrieved_chunks", [])
    if len(ret_chunks) > 0:
        print(f"[PASSED] Returned {len(ret_chunks)} retrieved chunks")
        checks.append(True)
    else:
        print("[FAILED] Missing retrieved_chunks")
        checks.append(False)

    # 5. Model & Confidence
    model = data.get("model")
    conf = data.get("confidence")
    if model and conf is not None:
        print(f"[PASSED] Active Model: '{model}', Grounding Confidence: {conf}%")
        checks.append(True)
    else:
        print("[FAILED] Missing model or confidence score")
        checks.append(False)

    if all(checks):
        print("\n[SUCCESS] MANUAL QA END-TO-END VERIFICATION PASSED PERFECTLY!\n")
        return 0
    else:
        print("\n[FAILED] VERIFICATION CHECKS FAILED.\n")
        return 1

if __name__ == "__main__":
    sys.exit(main())
