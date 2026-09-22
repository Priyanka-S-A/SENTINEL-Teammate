from typing import List, Dict, Any, Optional, Tuple
from backend.rag.embeddings import embedding_engine
from backend.rag.vector_store import vector_store

class CaseRetriever:
    """
    Semantic Vector Retriever with Case Isolation & Metadata Filtering (Section 5 & 6).
    """

    def retrieve(self, case_id: str, query: str, top_k: int = 5, filter_dict: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        if not query or not case_id:
            return []

        # 1. Embed query vector
        query_vector = embedding_engine.encode(query)

        # 2. Case-isolated vector search
        raw_results = vector_store.search_case_vectors(case_id, query_vector, top_k=top_k * 2)

        retrieved = []
        for chunk, score in raw_results:
            # Check mandatory case isolation
            if chunk.get("case_id") != case_id:
                continue

            # Optional metadata filtering
            if filter_dict:
                match = True
                for k, v in filter_dict.items():
                    if chunk.get(k) != v:
                        match = False
                        break
                if not match:
                    continue

            # Normalize similarity score to 0.0 - 1.0
            norm_score = max(0.0, min(1.0, float(score)))

            item = dict(chunk)
            item["relevance_score"] = round(norm_score, 4)
            retrieved.append(item)

            if len(retrieved) >= top_k:
                break

        return retrieved

retriever = CaseRetriever()
