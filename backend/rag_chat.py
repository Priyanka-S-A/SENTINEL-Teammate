"""
Backward compatibility bridge module for backend/rag_chat.py.
Delegates Natural Language QA queries to the semantic vector RAG engine package in backend.rag.
"""

from typing import Dict, Any
from backend.rag.rag_engine import rag_engine

class NaturalLanguageInvestigationChat:
    """
    Bridge wrapper for backward compatibility with existing API routes.
    """
    def process_query(self, query: str, case_data: Dict[str, Any]) -> Dict[str, Any]:
        return rag_engine.process_query(query, case_data)

rag_chat_engine = NaturalLanguageInvestigationChat()
