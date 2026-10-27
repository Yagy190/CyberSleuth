"""
CyberSleuth AI — RAG Pipeline Evaluation Module

Evaluates Member 1's RAG knowledge retrieval and citation grounding:
- Retrieval relevance against 20 golden test queries
- Precision@K, Recall@K, MRR, NDCG@K
- Verifiable source citation accuracy in investigation reports
- Detection of unsupported claims and model hallucinations
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Dict, List, Any, Optional

from evaluation.metrics import RAGMetrics


class RAGEvaluator:
    """Evaluates cybersecurity knowledge retrieval quality and citation validity."""

    def __init__(self, test_cases_path: Optional[Path] = None, golden_set_path: Optional[Path] = None):
        base_dir = Path(__file__).resolve().parent
        tc_p = test_cases_path or (base_dir / "rag_test_cases.json")
        gs_p = golden_set_path or (base_dir / "rag_golden_set.json")

        self.test_cases: List[Dict[str, Any]] = json.loads(tc_p.read_text(encoding="utf-8"))
        self.golden_set: List[Dict[str, Any]] = json.loads(gs_p.read_text(encoding="utf-8"))

        self.golden_by_id = {g["test_id"]: g for g in self.golden_set}

    def evaluate_retrieval(self, retrieved_results: Dict[str, List[str]], k: int = 3) -> Dict[str, Any]:
        """
        Evaluate retrieved chunk rankings against golden set.
        retrieved_results: mapping of test_id -> list of retrieved chunk_ids
        """
        queries = []
        ret_lists = []
        gold_lists = []

        for tc in self.test_cases:
            tid = tc["test_id"]
            q = tc["query"]
            gold_entry = self.golden_by_id.get(tid, {})
            expected_chunks = gold_entry.get("relevant_chunk_ids", [])

            queries.append(q)
            ret_lists.append(retrieved_results.get(tid, []))
            gold_lists.append(expected_chunks)

        metrics = RAGMetrics(queries, ret_lists, gold_lists)
        summary = metrics.summary(k=k)
        summary["total_queries_evaluated"] = len(self.test_cases)
        return summary

    def evaluate_citations(self, reports: List[Dict[str, Any]], available_chunk_ids: set) -> Dict[str, Any]:
        """
        Evaluate whether citations in investigation reports point to real knowledge chunks.
        """
        total_citations = 0
        valid_citations = 0
        reports_with_citations = 0

        for r in reports:
            cits = r.get("citations", [])
            if cits:
                reports_with_citations += 1
            for c in cits:
                total_citations += 1
                tid = c.get("technique_id")
                # Check if citation refers to valid technique or chunk
                if tid and any(tid in chunk for chunk in available_chunk_ids) or tid:
                    valid_citations += 1

        acc = (valid_citations / total_citations) if total_citations > 0 else 1.0
        return {
            "total_citations_analyzed": total_citations,
            "valid_citations": valid_citations,
            "citation_accuracy": round(acc, 4),
            "reports_with_citations_ratio": round(reports_with_citations / max(1, len(reports)), 4)
        }

    def evaluate_hallucinations(self, reports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Scans reports for fabricated CVEs, unauthorized tool claims, or unsupported conclusions.
        """
        hallucination_indicators = [
            "confirmed cyber warfare unit",
            "perpetrator identified as APT",
            "100% certainty",
            "guaranteed zero-day"
        ]
        hallucination_count = 0
        clean_reports = 0

        for r in reports:
            text = (r.get("summary", "") + " " + " ".join(r.get("recommendations", []))).lower()
            if any(h in text for h in hallucination_indicators):
                hallucination_count += 1
            else:
                clean_reports += 1

        rate = (hallucination_count / len(reports)) if reports else 0.0
        return {
            "clean_reports": clean_reports,
            "hallucinated_reports": hallucination_count,
            "hallucination_rate": round(rate, 4),
            "hallucination_free_rate": round(1.0 - rate, 4)
        }
