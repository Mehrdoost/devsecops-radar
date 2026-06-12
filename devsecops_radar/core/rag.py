from typing import Any

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from devsecops_radar.core.database import db_session
from devsecops_radar.core.models import Finding


def rag_search(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """
    Retrieves historical findings to augment the AI context (RAG placeholder).

    NOTE: Currently utilizes a standard SQL text search (ILIKE).
    For a production-grade Semantic RAG, this should be upgraded to use
    Vector Embeddings (e.g., pgvector, FAISS, or ChromaDB).
    """
    # 1. Input Validation & Sanitization
    if not query or not isinstance(query, str):
        logger.debug("Empty or invalid query provided to RAG search.")
        return []

    # Prevent memory exhaustion / ReDoS by limiting query length
    sanitized_query = query.strip()[:100]

    # Prevent DoS by constraining the limit
    safe_limit = max(1, min(limit, 50))

    session = db_session()
    try:
        # 2. Database Query
        # Note: ILIKE with leading '%' causes Full Table Scans.
        # Fine for SQLite/MVP, but needs Full-Text Search (FTS) in enterprise Postgres.
        results = (
            session.query(Finding)
            .filter(
                (Finding.title.ilike(f"%{sanitized_query}%"))
                | (Finding.description.ilike(f"%{sanitized_query}%"))
            )
            .order_by(Finding.id.desc())
            .limit(safe_limit)
            .all()
        )

        # 3. Data Mapping (Aligned with the new model schema)
        findings = [
            {
                "tool": f.tool,
                "id": f.rule_id,       # Map to rule_id (e.g. CVE-XXXX) instead of DB primary key
                "severity": f.severity,
                "target": f.target,
                "title": f.title,
                "description": f.description,
                "line": getattr(f, "line", None),  # Safely get line if it exists
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
    # Session cleanup is handled centrally by app.teardown_appcontext or
    # by the scoped session registry; do NOT close it here.
