"""tantivy-py wrapper with TextAnalyzerBuilder analyzer.

Per the May 2026 review, tantivy-py >= 0.22 exposes TextAnalyzerBuilder
which lets us build the analyzer in pure Python — no Rust shim needed.

Analyzer pipeline (per the review):
    regex tokenizer → lowercase → NFC normalize → remove-long filter

Schema:
    case_doc_id      i64 stored   PK — links to SQLite files.id
    path             text stored  raw=true   for exact filter
    name             text indexed (text analyzer)
    body             text indexed (text analyzer)
    body_cjk         text indexed (CJK analyzer) — for try2 (lindera)
    encoding         text stored facet
    size_bytes       u64 stored
    mtime            date stored
    sha256           text stored fast
    tlsh             text stored fast
    evidence_uuid    text stored facet
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    import tantivy  # type: ignore
    HAS_TANTIVY = True
except Exception:  # noqa: BLE001
    HAS_TANTIVY = False


# For try1 we use Tantivy's built-in `default` analyzer (lowercases +
# splits on word boundaries) and apply NFC normalization at the
# application layer in normalize_query() and add_doc(). A bespoke
# `TextAnalyzerBuilder` analyzer was tried in an earlier revision but
# the tantivy-py 0.25 API surface for registering custom analyzers is
# fragile across builds and a silent registration failure produces
# `Schema error: 'Error getting tokenizer for field: name'` at commit
# time. The built-in `default` is good enough for try1; try2 will
# revisit with proper version-pinned analyzer registration.


def _build_schema():
    sb = tantivy.SchemaBuilder()
    sb.add_integer_field("case_doc_id", stored=True, indexed=True, fast=True)
    sb.add_text_field("path", stored=True, tokenizer_name="raw")
    sb.add_text_field("name", stored=True, tokenizer_name="default")
    sb.add_text_field("body", stored=False, tokenizer_name="default")
    sb.add_text_field("body_cjk", stored=False, tokenizer_name="default")
    sb.add_text_field("encoding", stored=True, tokenizer_name="raw")
    sb.add_unsigned_field("size_bytes", stored=True, indexed=True, fast=True)
    sb.add_text_field("sha256", stored=True, tokenizer_name="raw", fast=True)
    sb.add_text_field("tlsh", stored=True, tokenizer_name="raw", fast=True)
    sb.add_text_field("evidence_uuid", stored=True, tokenizer_name="raw")
    return sb.build()


def normalize_query(s: str) -> str:
    """NFC + lowercase — apply identically at index and query time."""
    return unicodedata.normalize("NFC", s).lower()


@dataclass
class Hit:
    case_doc_id: int
    score: float
    path: str
    name: str
    encoding: str | None
    size_bytes: int | None
    sha256: str | None


class Indexer:
    def __init__(self, index_dir: Path):
        if not HAS_TANTIVY:
            raise RuntimeError("tantivy-py is not installed")
        self.index_dir = Path(index_dir)
        self.index_dir.mkdir(parents=True, exist_ok=True)
        self.schema = _build_schema()
        meta = self.index_dir / "meta.json"
        if meta.exists():
            self.index = tantivy.Index.open(str(self.index_dir))
        else:
            self.index = tantivy.Index(self.schema, path=str(self.index_dir))

    # ---- write -----------------------------------------------------------

    def writer(self, heap_mb: int = 256):
        return self.index.writer(heap_size=heap_mb * 1024 * 1024)

    def add_doc(self, writer, *, case_doc_id: int, path: str, name: str,
                body: str, encoding: str = "utf-8",
                size_bytes: int = 0, sha256: str = "", tlsh: str = "",
                evidence_uuid: str = "") -> None:
        body_n = unicodedata.normalize("NFC", body)
        doc = tantivy.Document()
        doc.add_integer("case_doc_id", int(case_doc_id))
        doc.add_text("path", path)
        doc.add_text("name", name)
        doc.add_text("body", body_n)
        # Mirror into body_cjk for try1 — try2 will route via lindera
        doc.add_text("body_cjk", body_n)
        doc.add_text("encoding", encoding)
        doc.add_unsigned("size_bytes", max(0, int(size_bytes)))
        doc.add_text("sha256", sha256)
        doc.add_text("tlsh", tlsh)
        doc.add_text("evidence_uuid", evidence_uuid)
        writer.add_document(doc)

    # ---- read ------------------------------------------------------------

    def _collect(self, searcher, results, limit: int) -> list[Hit]:
        hits: list[Hit] = []
        for score, addr in results:
            doc = searcher.doc(addr)
            def _g(field):
                try:
                    return doc.get_first(field)
                except Exception:  # noqa: BLE001
                    return None
            hits.append(Hit(
                case_doc_id=int(_g("case_doc_id") or 0),
                score=float(score),
                path=str(_g("path") or ""),
                name=str(_g("name") or ""),
                encoding=_g("encoding"),
                size_bytes=int(_g("size_bytes") or 0),
                sha256=_g("sha256"),
            ))
        return hits

    def search(self, query_str: str, limit: int = 50) -> list[Hit]:
        q = normalize_query(query_str)
        self.index.reload()
        searcher = self.index.searcher()
        parser = self.index.parse_query(q, ["body", "name"])
        results = searcher.search(parser, limit=limit).hits
        return self._collect(searcher, results, limit)

    def regex_search(self, pattern: str, field: str = "name",
                     limit: int = 50) -> list[Hit]:
        """Run a Tantivy RE2 regex query against one field.

        RE2 has no catastrophic backtracking, so an examiner-supplied
        pattern cannot hang the UI.

        The regex matches whole indexed *terms*. The `name` and `body`
        fields are tokenised + lowercased, so the pattern is lowercased
        to match; the `path` field uses the `raw` tokenizer (the whole
        path is one case-preserved term), so its pattern is used as-is.
        """
        self.index.reload()
        searcher = self.index.searcher()
        pat = pattern if field in ("path", "sha256", "tlsh",
                                   "encoding") else pattern.lower()
        rq = tantivy.Query.regex_query(self.schema, field, pat)
        results = searcher.search(rq, limit=limit).hits
        return self._collect(searcher, results, limit)
