import requests
import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

queries = [
    "What evidence connects the phishing email to the compromised endpoint?",
    "Show me the evidence supporting the PowerShell execution.",
    "Which users and systems were affected?"
]

for idx, q in enumerate(queries, 1):
    print("=" * 80)
    print(f"QUERY {idx}: {q}")
    print("=" * 80)
    res = requests.post("http://localhost:8000/api/natural-language", json={"query": q})
    print("HTTP Status:", res.status_code)
    data = res.json()
    print("Retrieval Method:", data.get("retrieval_method"))
    print("Retrieved Count:", data.get("retrieved_count"))
    print("Model:", data.get("model"))
    print("Confidence:", data.get("confidence"))
    print("Answer:", data.get("answer"))
    print("\nCitations List:")
    for c in data.get("citations", []):
        cid = c.get("chunk_id")
        cat = c.get("category")
        stype = c.get("source_type")
        prov = c.get("provenance")
        score = c.get("relevance_score")
        snip = c.get("snippet", "")[:80]
        pct = score * 100 if score is not None else 0.0
        print(f"  [{cid}] Cat: {cat} | Src: {stype} | Prov: {prov} | Rel: {score} ({pct:.1f}%)")
        print(f"         Snippet: {snip}...")
    print("\nFull JSON Response:")
    print(json.dumps(data, indent=2))
    print("\n")
