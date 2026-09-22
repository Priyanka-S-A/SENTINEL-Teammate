import os
import logging
import numpy as np
from typing import List

logger = logging.getLogger("sentinel.rag.embeddings")


class SentenceEmbeddingEngine:
    """
    Lightweight embedding engine.

    By default, local sentence-transformers is DISABLED so the
    application can run within Render's 512 MB memory limit.

    Set RAG_USE_LOCAL_EMBEDDINGS=true only on a machine with
    sufficient memory.
    """

    _instance = None
    _model = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SentenceEmbeddingEngine, cls).__new__(cls)
        return cls._instance

    def _init_model(self):
        if self._initialized:
            return

        self._initialized = True

        # Disabled by default for low-memory deployments
        use_local = os.environ.get(
            "RAG_USE_LOCAL_EMBEDDINGS", "false"
        ).lower() == "true"

        if not use_local:
            logger.info(
                "Local sentence-transformer embeddings disabled. "
                "Using lightweight fallback."
            )
            self._model = None
            return

        try:
            from sentence_transformers import SentenceTransformer

            model_name = os.environ.get(
                "RAG_EMBEDDING_MODEL",
                "all-MiniLM-L6-v2"
            )

            logger.info(
                f"Loading local embedding model '{model_name}'..."
            )

            self._model = SentenceTransformer(model_name)

            logger.info(
                f"Local embedding model '{model_name}' loaded successfully."
            )

        except Exception as e:
            logger.error(
                f"Failed to load sentence-transformers model: {e}"
            )
            self._model = None

    def encode(self, text: str) -> np.ndarray:
        """
        Return a 384-dimensional float32 vector.
        """

        self._init_model()

        if self._model is None:
            return np.zeros(384, dtype=np.float32)

        emb = self._model.encode(
            [text],
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        return emb[0].astype(np.float32)

    def embed_text(self, text: str) -> np.ndarray:
        return self.encode(text)

    def encode_batch(
        self,
        texts: List[str],
        batch_size: int = 32
    ) -> np.ndarray:

        self._init_model()

        if self._model is None or not texts:
            return np.zeros(
                (len(texts), 384),
                dtype=np.float32
            )

        embs = self._model.encode(
            texts,
            batch_size=batch_size,
            normalize_embeddings=True,
            convert_to_numpy=True
        )

        return embs.astype(np.float32)


embedding_engine = SentenceEmbeddingEngine()