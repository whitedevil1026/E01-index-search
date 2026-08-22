"""tantivy-py wrapper with TextAnalyzerBuilder analyzer.

Per the May 2026 review, tantivy-py >= 0.22 exposes TextAnalyzerBuilder
which lets us build the analyzer in pure Python — no Rust shim needed.

Analyzer pipeline (per the review):
    regex tokenizer → lowercase → NFC normalize → remove-long filter

Schema:
    case_doc_id      i64 stored   stable id derived from the doc's identity
                                  (see stable_doc_id) — reproducible across runs
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

import hashlib
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

try:
    import tantivy  # type: ignore
    HAS_TANTIVY = True
except Exception:  # noqa: BLE001
    HAS_TANTIVY = False


# We use Tantivy's built-in `default` analyzer (lowercases + splits on
# word boundaries) and apply NFC normalization at the application layer
# in normalize_query() and add_doc(). A bespoke `TextAnalyzerBuilder`
# analyzer was tried in an earlier revision but the tantivy-py 0.25 API
# surface for registering custom analyzers is fragile across builds and
# a silent registration failure produces
# `Schema error: 'Error getting tokenizer for field: name'` at commit
# time. The built-in `default` is sufficient; a future revision may
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


def stable_doc_id(*parts) -> int:
    """Derive a reproducible positive i64 doc id from a doc's identity.

    Python's built-in hash() is salted per interpreter start, so ids
    built with it differ between runs and cannot be reproduced by a
    verifying examiner.
    """
    canon = "\x1f".join(str(p) for p in parts).encode("utf-8", "replace")
    return int.from_bytes(hashlib.blake2b(canon, digest_size=8).digest(),
                          "big") & 0x7FFFFFFFFFFFFFFF


@dataclass
class Hit:
    case_doc_id: int
    score: float
    path: str
    name: str
    encoding: str | None
    size_bytes: int | None
    sha256: str | None
    # Which evidence item produced this document. A case can hold
    # several images, and the same path (/$RECYCLE.BIN, /Boot …) exists
    # in more than one — without this a hit cannot be attributed to the
    # image it actually came from.
    evidence_uuid: str = ""


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

    @staticmethod
    def finalize(writer) -> bool:
        """Commit, then block until Tantivy's background merges finish.

        `commit()` alone does not settle the index: Tantivy merges
        segments on background threads afterwards, so segment files keep
        being written and deleted for some time. That matters here
        because the case manifest hashes the index directory and signs
        the result — hashing a directory that is still being rewritten
        produces a signed manifest that does not match the files on
        disk, i.e. a false tamper alarm on an untouched case.

        `wait_merging_threads()` consumes the writer, so the caller must
        drop its reference afterwards. Returns True if the index is
        settled.
        """
        if writer is None:
            return False
        try:
            writer.commit()
        except Exception:  # noqa: BLE001
            pass
        try:
            writer.wait_merging_threads()
            return True
        except Exception:  # noqa: BLE001
            # Older/newer bindings may not expose it; the index is still
            # committed, just possibly not yet merged.
            return False

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
        # Mirror into body_cjk for now — a future revision may route
        # CJK text through a dedicated analyzer (e.g. lindera).
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
                evidence_uuid=str(_g("evidence_uuid") or ""),
            ))
        return hits

    def search(self, query_str: str, limit: int = 50) -> list[Hit]:
        q = normalize_query(query_str)
        self.index.reload()
        searcher = self.index.searcher()
        parser = self.index.parse_query(q, ["body", "name"])
        results = searcher.search(parser, limit=limit).hits
        return self._collect(searcher, results, limit)

    @staticmethod
    def _substring_regex(pattern: str) -> str:
        """Give an examiner's regex grep-like (substring) semantics.

        Tantivy's regex query is fully **anchored**: the pattern must
        match a term end to end. So `\\$M.*` finds nothing against the
        path term `/$MFT`, even though the path plainly contains `$M` —
        a trap, because every examiner reads that box as grep.

        Unless the pattern is explicitly anchored with ^ / $, it is
        wrapped so it matches anywhere in the term. Explicit anchors are
        honoured and stripped, since RE2-in-Tantivy has no use for them.
        """
        p = pattern
        anchored_start = p.startswith("^")
        anchored_end = p.endswith("$") and not p.endswith("\\$")
        if anchored_start:
            p = p[1:]
        if anchored_end:
            p = p[:-1]
        if anchored_start and anchored_end:
            return p                      # exact whole-term match
        if anchored_start:
            return f"(?:{p}).*"
        if anchored_end:
            return f".*(?:{p})"
        return f".*(?:{p}).*"

    def regex_search(self, pattern: str, field: str = "name",
                     limit: int = 50) -> list[Hit]:
        """Run a Tantivy RE2 regex query against one field.

        RE2 has no catastrophic backtracking, so an examiner-supplied
        pattern cannot hang the UI.

        The regex matches indexed *terms*. The `name` and `body` fields
        are tokenised + lowercased, so the pattern is lowercased to
        match; the `path` field uses the `raw` tokenizer (the whole path
        is one case-preserved term), so its pattern is used as-is.
        Matching is substring-style — see `_substring_regex`.
        """
        self.index.reload()
        searcher = self.index.searcher()
        pat = pattern if field in ("path", "sha256", "tlsh",
                                   "encoding") else pattern.lower()
        rq = tantivy.Query.regex_query(self.schema, field,
                                       self._substring_regex(pat))
        results = searcher.search(rq, limit=limit).hits
        return self._collect(searcher, results, limit)
