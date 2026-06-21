# devsecops_radar/core/rag.py
from typing import Any

from loguru import logger
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError

from devsecops_radar.core.database import get_session
from devsecops_radar.core.models import Finding


def _escape_like_wildcards(text: str) -> str:
    """Escape LIKE wildcards so they are treated as literal characters."""
    text = text.replace("\\", "\\\\")
    text = text.replace("%", "\\%")
    text = text.replace("_", "\\_")
    return text


def rag_search(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """
    Retrieves historical findings to augment the AI context (RAG placeholder).

    NOTE: Currently utilizes a standard SQL text search (ILIKE).
    For a production-grade Semantic RAG, this should be upgraded to use
    Vector Embeddings (e.g., pgvector, FAISS, or ChromaDB).
    """
    if not query or not isinstance(query, str):
        logger.debug("Empty or invalid query provided to RAG search.")
        return []

    sanitized_query = query.strip()[:100]
    safe_query = _escape_like_wildcards(sanitized_query)
    safe_limit = max(1, min(limit, 50))

    try:
        with get_session() as session:
            like_pattern = f"%{safe_query}%"
            results = (
                session.query(Finding)
                .filter(
                    or_(
                        Finding.title.ilike(like_pattern, escape='\\'),      # type: ignore[call-arg]
                        Finding.description.ilike(like_pattern, escape='\\'),  # type: ignore[call-arg]
                    )
                )
                .order_by(Finding.id.desc())
                .limit(safe_limit)
                .all()
            )

            findings = [
                {
                    "tool": f.tool,
                    "id": f.rule_id,
                    "severity": f.severity,
                    "target": f.target,
                    "title": f.title,
                    "description": f.description,
                    "line": getattr(f, "line", None),
                }
                for f in results
            ]

            logger.info(
                f"RAG Search found {len(findings)} results for query: "
                f"'{sanitized_query}'"
            )
            return findings

    except SQLAlchemyError as e:
        logger.error(f"Database error during RAG search: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error during RAG search: {e}")
        return []
