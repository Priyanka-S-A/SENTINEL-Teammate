import os
import logging
import numpy as np
from typing import List, Union

logger = logging.getLogger("sentinel.rag.embeddings")

class SentenceEmbeddingEngine:
    """
    Local Embedding Engine using sentence-transformers (all-MiniLM-L6-v2).
    Loaded ONCE per process for maximum performance (Section 1 & 17).
    """
    _instance = None
    _model = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SentenceEmbeddingEngine, cls).__new__(cls)
            cls._instance._init_model()
        return cls._instance

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            model_name = os.environ.get("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            logger.info(f"Loading local embedding model '{model_name}'...")
            self._model = SentenceTransformer(model_name)
            logger.info(f"Local embedding model '{model_name}' loaded successfully.")
        except Exception as e:
            logger.error(f"Failed to load sentence-transformers model: {e}")
            self._model = None

    def encode(self, text: str) -> np.ndarray:
        """
        Embeds a single string into a 384-dimensional normalized float32 vector.
        """
        if self._model is None:
            return np.zeros(384, dtype=np.float32)
        emb = self._model.encode([text], normalize_embeddings=True, convert_to_numpy=True)
        return emb[0].astype(np.float32)

    def embed_text(self, text: str) -> np.ndarray:
        """
        Alias for encode(). Embeds a single text string into a 384-dim vector.
        """
        return self.encode(text)

    def encode_batch(self, texts: List[str], batch_size: int = 32) -> np.ndarray:
        """
        Embeds a list of strings into 384-dimensional normalized float32 vectors in batches.
        """
        if self._model is None or not texts:
            return np.zeros((len(texts), 384), dtype=np.float32)
        embs = self._model.encode(texts, batch_size=batch_size, normalize_embeddings=True, convert_to_numpy=True)
        return embs.astype(np.float32)

embedding_engine = SentenceEmbeddingEngine()
