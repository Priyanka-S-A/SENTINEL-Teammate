import requests
import json
import sys

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

def show(q):
    res = requests.post('http://localhost:8000/api/natural-language', json={'query': q}).json()
    print(f"*** QUERY: {q}")
    print(f"METHOD: {res.get('retrieval_method')} | COUNT: {res.get('retrieved_count')} | CONFIDENCE: {res.get('confidence')}%")
    print(f"ANSWER: {res.get('answer')}")
    print("CITATIONS:")
    for c in res.get('citations', []):
        cid = c.get('chunk_id')
        cat = c.get('category')
        src = c.get('source_type')
        prov = c.get('provenance')
        score = c.get('score')
        pct = round(score * 100, 1)
        snip = c.get('snippet', '')[:70]
        print(f"  [{cid}] Cat: {cat} | Src: {src} | Prov: {prov} | Score: {score} ({pct}%)")
        print(f"      Snippet: {snip}...")
    print("\n" + "-" * 70 + "\n")

show("What evidence connects the phishing email to the compromised endpoint?")
show("Show me the evidence supporting the PowerShell execution.")
show("Which users and systems were affected?")
