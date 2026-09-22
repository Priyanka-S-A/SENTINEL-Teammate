import os
import json
import logging
import numpy as np
from typing import List, Dict, Any, Tuple, Optional

# FAISS is optional. Render's 512 MB instance can run without it.
try:
    import faiss
    FAISS_AVAILABLE = True
except ImportError:
    faiss = None
    FAISS_AVAILABLE = False

logger = logging.getLogger("sentinel.rag.vector_store")

VECTOR_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    "data",
    "vector_store"
)


class FAISSVectorStore:
    """
    Persistent vector store.

    Uses FAISS when available.
    Falls back to NumPy cosine similarity when FAISS is unavailable,
    allowing deployment on low-memory environments such as Render Free.
    """

    def __init__(self):
        os.makedirs(VECTOR_DIR, exist_ok=True)

        if FAISS_AVAILABLE:
            logger.info("FAISS vector store enabled.")
        else:
            logger.info(
                "FAISS unavailable. Using lightweight NumPy vector search."
            )

    def _get_index_path(self, case_id: str) -> str:
        safe_id = "".join(
            c if c.isalnum() or c in ("-", "_") else "_"
            for c in case_id
        )
        return os.path.join(VECTOR_DIR, f"{safe_id}.index")

    def _get_meta_path(self, case_id: str) -> str:
        safe_id = "".join(
            c if c.isalnum() or c in ("-", "_") else "_"
            for c in case_id
        )
        return os.path.join(VECTOR_DIR, f"{safe_id}_meta.json")

    def _get_numpy_path(self, case_id: str) -> str:
        safe_id = "".join(
            c if c.isalnum() or c in ("-", "_") else "_"
            for c in case_id
        )
        return os.path.join(VECTOR_DIR, f"{safe_id}.npy")

    def create_and_save_index(
        self,
        case_id: str,
        chunks: List[Dict[str, Any]],
        embeddings: np.ndarray
    ) -> bool:

        if embeddings is None or len(embeddings) == 0:
            return False

        try:
            embeddings = np.asarray(
                embeddings,
                dtype=np.float32
            )

            idx_path = self._get_index_path(case_id)
            meta_path = self._get_meta_path(case_id)

            if FAISS_AVAILABLE:
                dim = embeddings.shape[1]

                index = faiss.IndexFlatIP(dim)
                index.add(embeddings)

                faiss.write_index(index, idx_path)

            else:
                # Lightweight NumPy fallback
                np.save(
                    self._get_numpy_path(case_id),
                    embeddings
                )

            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(chunks, f, indent=2)

            logger.info(
                f"Saved vector index ({len(chunks)} vectors) "
                f"for case '{case_id}'"
            )

            return True

        except Exception as e:
            logger.error(
                f"Failed to save vector index for case {case_id}: {e}"
            )
            return False

    def load_index(
        self,
        case_id: str
    ) -> Tuple[Optional[Any], Optional[List[Dict[str, Any]]]]:

        meta_path = self._get_meta_path(case_id)

        if not os.path.exists(meta_path):
            return None, None

        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                chunks = json.load(f)

            if FAISS_AVAILABLE:
                idx_path = self._get_index_path(case_id)

                if not os.path.exists(idx_path):
                    return None, chunks

                index = faiss.read_index(idx_path)
                return index, chunks

            else:
                numpy_path = self._get_numpy_path(case_id)

                if not os.path.exists(numpy_path):
                    return None, chunks

                embeddings = np.load(numpy_path)

                return embeddings, chunks

        except Exception as e:
            logger.error(
                f"Failed to load vector index for case {case_id}: {e}"
            )
            return None, None

    def search_case_vectors(
        self,
        case_id: str,
        query_emb: np.ndarray,
        top_k: int = 5
    ) -> List[Tuple[Dict[str, Any], float]]:

        index, chunks = self.load_index(case_id)

        if index is None or chunks is None:
            return []

        try:
            query_emb = np.asarray(
                query_emb,
                dtype=np.float32
            )

            if query_emb.ndim == 1:
                query_emb = np.expand_dims(
                    query_emb,
                    axis=0
                )

            # FAISS search
            if FAISS_AVAILABLE and not isinstance(index, np.ndarray):

                scores, indices = index.search(
                    query_emb,
                    min(top_k, len(chunks))
                )

                results = []

                for score, idx in zip(
                    scores[0],
                    indices[0]
                ):
                    if 0 <= idx < len(chunks):
                        results.append(
                            (chunks[idx], float(score))
                        )

                return results

            # NumPy cosine similarity fallback
            embeddings = np.asarray(
                index,
                dtype=np.float32
            )

            query_norm = np.linalg.norm(
                query_emb,
                axis=1,
                keepdims=True
            )

            embedding_norms = np.linalg.norm(
                embeddings,
                axis=1,
                keepdims=True
            )

            query_norm[query_norm == 0] = 1.0
            embedding_norms[embedding_norms == 0] = 1.0

            query_normalized = query_emb / query_norm
            embeddings_normalized = (
                embeddings / embedding_norms
            )

            scores = np.dot(
                embeddings_normalized,
                query_normalized[0]
            )

            top_indices = np.argsort(scores)[::-1][
                :min(top_k, len(chunks))
            ]

            results = []

            for idx in top_indices:
                if 0 <= idx < len(chunks):
                    results.append(
                        (
                            chunks[idx],
                            float(scores[idx])
                        )
                    )

            return results

        except Exception as e:
            logger.error(
                f"Error searching vector index "
                f"for case {case_id}: {e}"
            )
            return []

    def search(
        self,
        case_id: str,
        query_emb: np.ndarray,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:

        raw_results = self.search_case_vectors(
            case_id,
            query_emb,
            top_k=top_k
        )

        formatted = []

        for chunk, score in raw_results:
            formatted.append({
                "chunk_id": chunk.get("chunk_id", ""),
                "category": chunk.get(
                    "category",
                    chunk.get("source_type", "")
                ),
                "content": chunk.get(
                    "text",
                    str(chunk)
                ),
                "score": round(float(score), 4),
                "metadata": chunk
            })

        return formatted

    def delete_case_index(self, case_id: str) -> bool:

        idx_path = self._get_index_path(case_id)
        numpy_path = self._get_numpy_path(case_id)
        meta_path = self._get_meta_path(case_id)

        deleted = False

        for path in [idx_path, numpy_path, meta_path]:
            if os.path.exists(path):
                os.remove(path)
                deleted = True

        return deleted


vector_store = FAISSVectorStore()