import os
import json
import logging
import numpy as np
import faiss
from typing import List, Dict, Any, Tuple, Optional

logger = logging.getLogger("sentinel.rag.vector_store")

VECTOR_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "vector_store")

class FAISSVectorStore:
    """
    Persistent FAISS Vector Store + Metadata Storage (Section 1 & 14).
    Stores per-case vector indexes under data/vector_store/{case_id}.index
    Guarantees 100% Case Isolation (Case A query never retrieves Case B vectors).
    """

    def __init__(self):
        os.makedirs(VECTOR_DIR, exist_ok=True)

    def _get_index_path(self, case_id: str) -> str:
        safe_id = "".join([c if c.isalnum() or c in ("-", "_") else "_" for c in case_id])
        return os.path.join(VECTOR_DIR, f"{safe_id}.index")

    def _get_meta_path(self, case_id: str) -> str:
        safe_id = "".join([c if c.isalnum() or c in ("-", "_") else "_" for c in case_id])
        return os.path.join(VECTOR_DIR, f"{safe_id}_meta.json")

    def create_and_save_index(self, case_id: str, chunks: List[Dict[str, Any]], embeddings: np.ndarray) -> bool:
        """
        Creates FAISS index and persists index file + metadata JSON.
        """
        if embeddings is None or len(embeddings) == 0:
            return False

        try:
            dim = embeddings.shape[1]
            index = faiss.IndexFlatIP(dim) # L2 normalized Inner Product = Cosine Similarity
            index.add(embeddings)

            idx_path = self._get_index_path(case_id)
            meta_path = self._get_meta_path(case_id)

            faiss.write_index(index, idx_path)
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(chunks, f, indent=2)

            logger.info(f"Saved FAISS index ({len(chunks)} vectors) for case '{case_id}' to {idx_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save FAISS index for case {case_id}: {e}")
            return False

    def load_index(self, case_id: str) -> Tuple[Optional[faiss.Index], Optional[List[Dict[str, Any]]]]:
        """
        Loads persistent FAISS index and metadata JSON for a case.
        """
        idx_path = self._get_index_path(case_id)
        meta_path = self._get_meta_path(case_id)

        if not (os.path.exists(idx_path) and os.path.exists(meta_path)):
            return None, None

        try:
            index = faiss.read_index(idx_path)
            with open(meta_path, "r", encoding="utf-8") as f:
                chunks = json.load(f)
            return index, chunks
        except Exception as e:
            logger.error(f"Failed to load FAISS index for case {case_id}: {e}")
            return None, None

    def search_case_vectors(self, case_id: str, query_emb: np.ndarray, top_k: int = 5) -> List[Tuple[Dict[str, Any], float]]:
        """
        Performs vector similarity search strictly isolated to the specified case_id (Section 4).
        """
        index, chunks = self.load_index(case_id)
        if index is None or chunks is None:
            return []

        try:
            # Ensure 2D array shape (1, 384)
            if query_emb.ndim == 1:
                query_emb = np.expand_dims(query_emb, axis=0)

            scores, indices = index.search(query_emb, min(top_k, len(chunks)))

            results = []
            for score, idx in zip(scores[0], indices[0]):
                if idx < len(chunks) and idx >= 0:
                    results.append((chunks[idx], float(score)))

            return results
        except Exception as e:
            logger.error(f"Error searching vector index for case {case_id}: {e}")
            return []

    def search(self, case_id: str, query_emb: np.ndarray, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Convenience method returning search results formatted as dictionary items with score and content.
        """
        raw_results = self.search_case_vectors(case_id, query_emb, top_k=top_k)
        formatted = []
        for chunk, score in raw_results:
            formatted.append({
                "chunk_id": chunk.get("chunk_id", ""),
                "category": chunk.get("category", chunk.get("source_type", "")),
                "content": chunk.get("text", str(chunk)),
                "score": round(float(score), 4),
                "metadata": chunk
            })
        return formatted

    def delete_case_index(self, case_id: str) -> bool:
        idx_path = self._get_index_path(case_id)
        meta_path = self._get_meta_path(case_id)
        deleted = False

        if os.path.exists(idx_path):
            os.remove(idx_path)
            deleted = True
        if os.path.exists(meta_path):
            os.remove(meta_path)
            deleted = True

        return deleted

vector_store = FAISSVectorStore()
