"""
CyberSleuth AI – RAG Retriever (Hybrid TF-IDF + Cosine Similarity)
Member 1: AI/ML & Agent Architecture Lead

Two-stage retrieval:
  1. TF-IDF keyword pre-filter (fast, O(n) candidates)
  2. Sentence-transformer vector cosine similarity ranking
  3. Returns top-k with source citations

Works offline (no pgvector required) by caching embeddings in memory.
"""
from __future__ import annotations
import numpy as np
from typing import List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .knowledge_base import KBChunk, get_knowledge_base

# Lazy import of sentence-transformers to avoid slow load at import time
_model = None
_chunk_embeddings: np.ndarray | None = None
_tfidf: TfidfVectorizer | None = None
_tfidf_matrix = None
_indexed_chunks: List[KBChunk] = []


def _get_embed_model():
    global _model
    if _model is None:
        try:
            from sentence_transformers import SentenceTransformer
            from app.core.config import settings
            _model = SentenceTransformer(settings.EMBED_MODEL)
        except Exception as e:
            print(f"[RAG] SentenceTransformer unavailable, falling back to TF-IDF only: {e}")
            _model = False
    return _model


def _ensure_index():
    """Build TF-IDF and embedding indexes on first call."""
    global _chunk_embeddings, _tfidf, _tfidf_matrix, _indexed_chunks

    if _indexed_chunks:
        return  # already built

    kb = get_knowledge_base()
    _indexed_chunks = kb.chunks

    texts = [c.text for c in _indexed_chunks]

    # TF-IDF index
    _tfidf = TfidfVectorizer(ngram_range=(1, 2), max_features=10_000)
    _tfidf_matrix = _tfidf.fit_transform(texts)

    # Dense embedding index (optional fallback)
    model = _get_embed_model()
    if model:
        try:
            _chunk_embeddings = model.encode(texts, batch_size=32, show_progress_bar=False)
        except Exception:
            _chunk_embeddings = None
    else:
        _chunk_embeddings = None


# ── Public API ────────────────────────────────────────────────────────────────

def retrieve(
    query: str,
    top_k: int = 5,
    tfidf_weight: float = 0.3,
    embed_weight: float = 0.7,
) -> List[Tuple[KBChunk, float]]:
    """
    Hybrid retrieve: returns list of (chunk, combined_score) sorted descending.
    Combined score = tfidf_weight * tfidf_sim + embed_weight * cosine_sim
    """
    _ensure_index()

    # TF-IDF scores
    q_tfidf = _tfidf.transform([query])
    tfidf_scores = cosine_similarity(q_tfidf, _tfidf_matrix).flatten()

    def _norm(arr):
        mn, mx = arr.min(), arr.max()
        if mx == mn:
            return np.zeros_like(arr)
        return (arr - mn) / (mx - mn + 1e-9)

    norm_tfidf = _norm(tfidf_scores)

    model = _get_embed_model()
    if model and _chunk_embeddings is not None:
        try:
            q_embed = model.encode([query], show_progress_bar=False)
            embed_scores = cosine_similarity(q_embed, _chunk_embeddings).flatten()
            norm_embed = _norm(embed_scores)
            combined = tfidf_weight * norm_tfidf + embed_weight * norm_embed
        except Exception:
            combined = norm_tfidf
    else:
        combined = norm_tfidf

    top_indices = combined.argsort()[::-1][:top_k]

    return [(
        _indexed_chunks[i],
        float(combined[i]),
    ) for i in top_indices]


def retrieve_for_techniques(technique_ids: List[str]) -> List[KBChunk]:
    """Return all chunks matching any of the given MITRE technique IDs."""
    _ensure_index()
    results = []
    for chunk in _indexed_chunks:
        if chunk.technique_id and any(
            chunk.technique_id.startswith(tid) for tid in technique_ids
        ):
            results.append(chunk)
    return results


def reset_index():
    """Force a full re-index (useful after KB is updated)."""
    global _chunk_embeddings, _tfidf, _tfidf_matrix, _indexed_chunks, _model
    _chunk_embeddings = None
    _tfidf = None
    _tfidf_matrix = None
    _indexed_chunks = []
    _model = None
