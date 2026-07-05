# devsecops_radar/core/rag.py
"""
Semantic Retrieval‑Augmented Generation (RAG) engine with fallback to
full‑text search when ChromaDB is not installed.

Uses local Ollama embeddings + ChromaDB for offline semantic search.
When ChromaDB is missing, falls back to SQLite FTS5 (or ILIKE).
All output is sanitised and redacted.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import re
from html import escape as html_escape
from pathlib import Path
from typing import Any

from loguru import logger
from sqlalchemy import text as sa_text

from devsecops_radar.core.models import Finding, SessionLocal
from devsecops_radar.core.reporting import redact_sensitive


# ---------------------------------------------------------------------------
# Optional dependency checks (without top‑level imports)
# ---------------------------------------------------------------------------
def _has_chroma() -> bool:
    return importlib.util.find_spec("chromadb") is not None


def _has_fts5() -> bool:
    """Return True if the SQLite connection supports FTS5."""
    try:
        session = SessionLocal()
        session.execute(sa_text("SELECT 1 FROM sqlite_master LIMIT 1"))
        session.execute(sa_text("CREATE VIRTUAL TABLE IF NOT EXISTS _fts5_test USING fts5(content)"))
        session.execute(sa_text("DROP TABLE IF EXISTS _fts5_test"))
        session.commit()
        return True
    except Exception:
        return False
    finally:
        session.close()


# ---------------------------------------------------------------------------
# FTS5 initialisation (only used when ChromaDB is unavailable)
# ---------------------------------------------------------------------------
_fts_initialized = False


def _init_fts() -> None:
    """Create the FTS5 virtual table if it does not already exist."""
    global _fts_initialized
    if _fts_initialized:
        return
    session = SessionLocal()
    try:
        row = session.execute(
            sa_text("SELECT name FROM sqlite_master WHERE type='table' AND name='findings_fts'")
        ).fetchone()
        if not row:
            session.execute(sa_text(
                "CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5("
                "  id, tool, target, title, description,"
                "  content='findings',"
                "  content_rowid='id'"
                ")"
            ))
            session.execute(sa_text(
                "INSERT INTO findings_fts(rowid, id, tool, target, title, description) "
                "SELECT id, rule_id, tool, target, title, description FROM findings"
            ))
            session.commit()
    except Exception as e:
        logger.warning(f"Could not initialise FTS5: {e}")
        session.rollback()
    finally:
        session.close()
        _fts_initialized = True


# ---------------------------------------------------------------------------
# ChromaDB collection singleton (dynamic imports to keep Pylance quiet)
# ---------------------------------------------------------------------------
_collection = None
_collection_lock = None


def _get_collection():
    """Return the ChromaDB collection, creating it if necessary."""
    global _collection, _collection_lock
    if not _has_chroma():
        return None

    # Dynamic imports – only executed if chromadb is installed
    chromadb = importlib.import_module("chromadb")
    config = importlib.import_module("chromadb.config")
    ChromaSettings = config.Settings    # noqa: N806

    if _collection is not None:
        return _collection

    import threading
    if _collection_lock is None:
        _collection_lock = threading.Lock()

    with _collection_lock:
        if _collection is not None:
            return _collection

        db_dir = Path.cwd() / ".sentinel" / "chroma"
        db_dir.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(
            path=str(db_dir),
            settings=ChromaSettings(anonymized_telemetry=False),
        )
        try:
            coll = client.get_collection("findings")
        except Exception:
            coll = client.create_collection(
                name="findings",
                metadata={"hnsw:space": "cosine"},
            )
        _collection = coll
        return coll


# ---------------------------------------------------------------------------
# Ollama embedding helper (httpx is a mandatory dependency)
# ---------------------------------------------------------------------------
async def _ollama_embed(texts: list[str], model: str = "nomic-embed-text") -> list[list[float]]:
    """Get embeddings from a local Ollama instance."""
    import httpx

    url = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434").rstrip("/")
    url = url.replace("/api/generate", "")  # strip chat endpoint
    embed_url = f"{url}/api/embeddings"
    vectors = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for text in texts:
            resp = await client.post(embed_url, json={
                "model": model,
                "prompt": text,
            })
            resp.raise_for_status()
            data = resp.json()
            vectors.append(data["embedding"])
    return vectors


# ---------------------------------------------------------------------------
# Indexing – call after a scan to add findings to the vector store
# ---------------------------------------------------------------------------
def index_findings(findings: list[dict[str, Any]]) -> int:
    """
    Embed and index *findings* into the vector database (if ChromaDB is available).
    Falls back to updating the FTS5 index.
    """
    if _has_chroma():
        coll = _get_collection()
        if coll is None:
            return 0

        ids: list[str] = []
        documents = []
        metadatas = []
        texts_to_embed = []

        for f in findings:
            fid = f.get("id") or f.get("rule_id") or f"UNKNOWN-{len(ids)}"
            title = f.get("title", "")
            description = f.get("description", "")

            doc_text = (
                f"Title: {title}\n"
                f"Tool: {f.get('tool', '')}\n"
                f"Severity: {f.get('severity', '')}\n"
                f"Target: {f.get('target', '')}\n"
                f"Description: {description}"
            )
            ids.append(fid)
            documents.append(doc_text)
            metadatas.append({
                "id": fid,
                "tool": f.get("tool", ""),
                "severity": f.get("severity", ""),
                "target": f.get("target", ""),
                "title": title,
                "description": description,
            })
            texts_to_embed.append(doc_text)

        if not texts_to_embed:
            return 0

        import asyncio
        try:
            embeddings = asyncio.run(_ollama_embed(texts_to_embed))
        except Exception as e:
            logger.error(f"Failed to generate embeddings: {e}")
            return 0

        try:
            coll.upsert(
                ids=ids,
                embeddings=embeddings,
                documents=documents,
                metadatas=metadatas,
            )
            logger.success(f"Indexed {len(ids)} findings into vector store.")
            return len(ids)
        except Exception as e:
            logger.error(f"Failed to upsert into ChromaDB: {e}")
            return 0
    else:
        # Fallback: update FTS5 index
        _init_fts()
        session = SessionLocal()
        try:
            session.execute(sa_text(
                "INSERT INTO findings_fts(rowid, id, tool, target, title, description) "
                "SELECT id, rule_id, tool, target, title, description FROM findings "
                "WHERE id NOT IN (SELECT rowid FROM findings_fts)"
            ))
            session.commit()
            return len(findings)
        except Exception as e:
            logger.warning(f"FTS indexing failed: {e}")
            session.rollback()
            return 0
        finally:
            session.close()


# ---------------------------------------------------------------------------
# Sanitisation helpers
# ---------------------------------------------------------------------------
def _sanitize_cell(value: Any) -> str:
    """Remove control characters, redact secrets, and HTML‑escape."""
    text = str(value) if value is not None else ""
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    text = redact_sensitive(text)
    return html_escape(text)


# ---------------------------------------------------------------------------
# Public search function
# ---------------------------------------------------------------------------
def rag_search(query: str, limit: int = 5) -> list[dict[str, Any]]:
    """
    Semantic search for findings similar to *query*.

    If ChromaDB is available, uses vector similarity.
    Otherwise falls back to FTS5 (or ILIKE) text search.

    Args:
        query: Natural language query or search phrase.
        limit: Max number of results.

    Returns:
        List of sanitised finding dicts ordered by relevance.
    """
    if not query or not isinstance(query, str):
        return []

    safe_query = query.strip()[:200]
    safe_limit = max(1, min(limit, 50))

    # ---------- ChromaDB vector search ----------
    if _has_chroma():
        coll = _get_collection()
        if coll is not None:
            import asyncio
            try:
                query_embedding = asyncio.run(_ollama_embed([safe_query]))[0]
            except Exception as e:
                logger.error(f"Failed to embed query: {e}")
                return []

            try:
                results = coll.query(
                    query_embeddings=[query_embedding],
                    n_results=safe_limit,
                    include=["metadatas", "distances"],
                )
            except Exception as e:
                logger.error(f"Semantic search failed: {e}")
                return []

            findings = []
            for metadata, distance in zip(
                results.get("metadatas", [[]])[0],
                results.get("distances", [[]])[0], strict=False,
            ):
                if metadata:
                    findings.append({
                        "id": _sanitize_cell(metadata.get("id", "")),
                        "tool": _sanitize_cell(metadata.get("tool", "")),
                        "severity": _sanitize_cell(metadata.get("severity", "")),
                        "target": _sanitize_cell(metadata.get("target", "")),
                        "title": _sanitize_cell(metadata.get("title", "")[:200]),
                        "description": _sanitize_cell(metadata.get("description", "")[:500]),
                        "similarity": round(1.0 - distance, 4),
                    })
            logger.info(f"RAG search returned {len(findings)} results for '{safe_query}'")
            return findings

    # ---------- FTS5 / ILIKE fallback ----------
    _init_fts()
    session = SessionLocal()
    try:
        if _has_fts5():
            try:
                rows = session.execute(
                    sa_text(
                        "SELECT f.id, f.rule_id, f.tool, f.target, f.title, f.description, f.severity, f.line "
                        "FROM findings f "
                        "JOIN findings_fts ft ON f.id = ft.rowid "
                        "WHERE findings_fts MATCH :q "
                        "ORDER BY rank "
                        "LIMIT :lim"
                    ),
                    {"q": safe_query, "lim": safe_limit},
                ).fetchall()
            except Exception:
                rows = None
                logger.warning("FTS5 query failed, falling back to ILIKE.")

            if rows is None:
                like_pattern = f"%{safe_query}%"
                rows = session.query(Finding).filter(
                    (Finding.title.ilike(like_pattern)) |
                    (Finding.description.ilike(like_pattern)) |
                    (Finding.tool.ilike(like_pattern)) |
                    (Finding.rule_id.ilike(like_pattern))
                ).order_by(Finding.id.desc()).limit(safe_limit).all()

        else:
            like_pattern = f"%{safe_query}%"
            rows = session.query(Finding).filter(
                (Finding.title.ilike(like_pattern)) |
                (Finding.description.ilike(like_pattern)) |
                (Finding.tool.ilike(like_pattern)) |
                (Finding.rule_id.ilike(like_pattern))
            ).order_by(Finding.id.desc()).limit(safe_limit).all()

        findings = []
        for row in rows:
            if hasattr(row, "_mapping"):
                r = row._mapping
                findings.append({
                    "id": _sanitize_cell(r.get("rule_id") or r.get("id", "")),
                    "tool": _sanitize_cell(r.get("tool", "")),
                    "severity": _sanitize_cell(r.get("severity", "")),
                    "target": _sanitize_cell(r.get("target", "")),
                    "title": _sanitize_cell(str(r.get("title", ""))[:200]),
                    "description": _sanitize_cell(str(r.get("description", ""))[:500]),
                    "line": r.get("line"),
                })
            else:
                findings.append({
                    "id": _sanitize_cell(row.rule_id or ""),
                    "tool": _sanitize_cell(row.tool or ""),
                    "severity": _sanitize_cell(row.severity or ""),
                    "target": _sanitize_cell(row.target or ""),
                    "title": _sanitize_cell(str(row.title or "")[:200]),
                    "description": _sanitize_cell(str(row.description or "")[:500]),
                    "line": row.line,
                })
        logger.info(f"Text search returned {len(findings)} results for '{safe_query}'")
        return findings
    except Exception as e:
        logger.error(f"Text search failed: {e}")
        return []
    finally:
        session.close()
