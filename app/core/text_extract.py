"""Pure-Python text extraction for file-content indexing.

Routes a file (name + raw bytes) to the appropriate extractor and
returns the plain text for Tantivy indexing.

Design constraint: NO Apache Tika / no JVM. Everything here is either
the Python standard library or a wheel-installable pure/binary package
that is already a project dependency:

    PDF              PyMuPDF (fitz)            already a dependency
    .docx/.xlsx/.pptx  stdlib zipfile + ElementTree  (Office files are ZIPs of XML)
    .msg             extract-msg               already a dependency
    .eml             stdlib email
    .html/.htm/.xml  stdlib html.parser
    .rtf             inline control-word stripper
    plain text       charset-normalizer        already a dependency

Files that need a heavyweight parser (legacy .doc/.xls OLE streams,
encrypted archives, etc.) are reported with extractor='unsupported' so
the caller can still index the file name and tag it for a later pass.

Memory: every extractor accepts bytes already in RAM. The caller is
responsible for the size cap on how many bytes to read from the image;
this module additionally caps the returned text length.
"""
from __future__ import annotations

import io
import re
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Optional


# ---- limits ---------------------------------------------------------------

# Hard cap on returned text. 1 MiB of text is far more than enough for
# keyword search and keeps the Tantivy index from ballooning on a single
# huge document.
MAX_TEXT_CHARS = 1_000_000


# ---- file-type tables -----------------------------------------------------

PLAINTEXT_EXT = {
    "txt", "log", "csv", "tsv", "ini", "cfg", "conf", "md", "rst",
    "json", "yaml", "yml", "xml", "sql", "sh", "bat", "ps1", "ps",
    "py", "js", "ts", "java", "c", "cc", "cpp", "h", "hpp", "cs",
    "go", "rb", "php", "pl", "lua", "r", "m", "swift", "kt", "scala",
    "vb", "asm", "css", "scss", "less", "toml", "env", "properties",
    "reg", "url", "vbs", "wsf", "applescript", "gradle", "dockerfile",
    "makefile", "cmake", "diff", "patch", "srt", "vtt", "tex",
}
HTML_EXT = {"html", "htm", "xhtml", "mhtml"}
OFFICE_ZIP_EXT = {"docx", "xlsx", "pptx", "docm", "xlsm", "pptm"}
LEGACY_OLE_EXT = {"doc", "xls", "ppt"}


@dataclass
class ExtractResult:
    text: str = ""
    extractor: str = "none"     # which path produced the text
    error: str = ""             # populated on failure
    truncated: bool = False     # True if text was cut at MAX_TEXT_CHARS
    char_count: int = 0

    def ok(self) -> bool:
        return bool(self.text) and not self.error


# ---- helpers --------------------------------------------------------------

def _ext(name: str) -> str:
    name = name.lower().strip()
    if "." not in name:
        return ""
    return name.rsplit(".", 1)[-1]


def _finalize(text: str, extractor: str, error: str = "") -> ExtractResult:
    text = text or ""
    # collapse runs of whitespace so the index isn't full of blank tokens
    text = re.sub(r"[ \t ]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    truncated = len(text) > MAX_TEXT_CHARS
    if truncated:
        text = text[:MAX_TEXT_CHARS]
    return ExtractResult(text=text.strip(), extractor=extractor, error=error,
                         truncated=truncated, char_count=len(text))


def _looks_like_text(data: bytes, sample: int = 8192) -> bool:
    """Heuristic: is this blob mostly printable text?"""
    if not data:
        return False
    chunk = data[:sample]
    if b"\x00" in chunk:
        return False  # NUL byte -> almost certainly binary
    # count printable + common whitespace
    printable = sum(1 for b in chunk if 32 <= b < 127 or b in (9, 10, 13))
    return printable / len(chunk) > 0.85


# ---- individual extractors ------------------------------------------------

def _extract_plaintext(data: bytes) -> ExtractResult:
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(data).best()
        if best is not None:
            return _finalize(str(best), "plaintext")
    except Exception:
        pass
    # fallback: utf-8 then latin-1
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            return _finalize(data.decode(enc, errors="replace"), "plaintext")
        except Exception:
            continue
    return ExtractResult(extractor="plaintext", error="could not decode")


def _extract_pdf(data: bytes) -> ExtractResult:
    try:
        import fitz  # PyMuPDF
    except Exception:
        return ExtractResult(extractor="pdf", error="PyMuPDF not installed")
    try:
        doc = fitz.open(stream=data, filetype="pdf")
        try:
            parts = []
            total = 0
            for page in doc:
                t = page.get_text("text")
                if t:
                    parts.append(t)
                    total += len(t)
                    if total > MAX_TEXT_CHARS:
                        break
            return _finalize("\n".join(parts), "pdf")
        finally:
            doc.close()
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="pdf", error=f"{type(exc).__name__}: {exc}")


_W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
_S_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
_P_NS = "{http://schemas.openxmlformats.org/drawingml/2006/main}"


def _extract_office_zip(data: bytes, ext: str) -> ExtractResult:
    """docx / xlsx / pptx are ZIP archives of XML. Parse the relevant
    XML members with the stdlib — no python-docx / openpyxl needed.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="office", error=f"not a valid zip: {exc}")
    names = set(zf.namelist())
    parts: list[str] = []
    try:
        if ext in ("docx", "docm"):
            for member in ("word/document.xml",):
                if member in names:
                    root = ET.fromstring(zf.read(member))
                    for node in root.iter(_W_NS + "t"):
                        if node.text:
                            parts.append(node.text)
            # headers / footers
            for n in names:
                if re.match(r"word/(header|footer)\d*\.xml", n):
                    try:
                        root = ET.fromstring(zf.read(n))
                        for node in root.iter(_W_NS + "t"):
                            if node.text:
                                parts.append(node.text)
                    except Exception:
                        pass
            return _finalize(" ".join(parts), "docx")

        if ext in ("xlsx", "xlsm"):
            # shared strings hold most cell text
            if "xl/sharedStrings.xml" in names:
                root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
                for node in root.iter(_S_NS + "t"):
                    if node.text:
                        parts.append(node.text)
            # inline strings in each sheet
            for n in names:
                if re.match(r"xl/worksheets/sheet\d+\.xml", n):
                    try:
                        root = ET.fromstring(zf.read(n))
                        for node in root.iter(_S_NS + "t"):
                            if node.text:
                                parts.append(node.text)
                    except Exception:
                        pass
            return _finalize(" ".join(parts), "xlsx")

        if ext in ("pptx", "pptm"):
            for n in sorted(names):
                if re.match(r"ppt/slides/slide\d+\.xml", n):
                    try:
                        root = ET.fromstring(zf.read(n))
                        for node in root.iter(_P_NS + "t"):
                            if node.text:
                                parts.append(node.text)
                    except Exception:
                        pass
            return _finalize(" ".join(parts), "pptx")
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="office", error=f"{type(exc).__name__}: {exc}")
    finally:
        zf.close()
    return ExtractResult(extractor="office", error="no recognised office part")


def _extract_msg(data: bytes) -> ExtractResult:
    try:
        import extract_msg
    except Exception:
        return ExtractResult(extractor="msg", error="extract-msg not installed")
    try:
        # extract_msg accepts a path or a file-like / bytes stream
        msg = extract_msg.openMsg(io.BytesIO(data))
        parts = []
        for attr in ("subject", "sender", "to", "cc", "date"):
            v = getattr(msg, attr, None)
            if v:
                parts.append(str(v))
        body = getattr(msg, "body", None)
        if body:
            parts.append(str(body))
        try:
            msg.close()
        except Exception:
            pass
        return _finalize("\n".join(parts), "msg")
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="msg", error=f"{type(exc).__name__}: {exc}")


def _extract_eml(data: bytes) -> ExtractResult:
    try:
        import email
        from email import policy
        msg = email.message_from_bytes(data, policy=policy.default)
        parts = []
        for hdr in ("subject", "from", "to", "cc", "date"):
            v = msg.get(hdr)
            if v:
                parts.append(str(v))
        try:
            body = msg.get_body(preferencelist=("plain", "html"))
            if body is not None:
                content = body.get_content()
                if body.get_content_subtype() == "html":
                    content = _strip_html(content)
                parts.append(content)
        except Exception:
            # fall back to walking payloads
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        parts.append(part.get_content())
                    except Exception:
                        pass
        return _finalize("\n".join(parts), "eml")
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="eml", error=f"{type(exc).__name__}: {exc}")


class _HTMLTextExtractor:
    """Minimal HTML → text using the stdlib parser."""

    def __init__(self):
        from html.parser import HTMLParser

        outer = self
        outer.chunks: list[str] = []
        outer._skip = 0

        class _P(HTMLParser):
            def handle_starttag(self, tag, attrs):
                if tag in ("script", "style", "head"):
                    outer._skip += 1

            def handle_endtag(self, tag):
                if tag in ("script", "style", "head") and outer._skip > 0:
                    outer._skip -= 1

            def handle_data(self, data):
                if outer._skip == 0 and data.strip():
                    outer.chunks.append(data)

        self._parser = _P()

    def feed(self, text: str) -> str:
        try:
            self._parser.feed(text)
        except Exception:
            pass
        return " ".join(self.chunks)


def _strip_html(text: str) -> str:
    return _HTMLTextExtractor().feed(text)


def _extract_html(data: bytes) -> ExtractResult:
    try:
        from charset_normalizer import from_bytes
        best = from_bytes(data).best()
        raw = str(best) if best is not None else data.decode("utf-8", errors="replace")
    except Exception:
        raw = data.decode("utf-8", errors="replace")
    try:
        return _finalize(_strip_html(raw), "html")
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="html", error=f"{type(exc).__name__}: {exc}")


_RTF_CONTROL = re.compile(r"\\[a-zA-Z]+-?\d* ?")
_RTF_HEX = re.compile(r"\\'[0-9a-fA-F]{2}")


def _extract_rtf(data: bytes) -> ExtractResult:
    """Lightweight RTF text extraction — strip control words / groups.
    Not a full RTF parser, but good enough for keyword search.
    """
    try:
        raw = data.decode("latin-1", errors="replace")
        # drop hex escapes, control words, braces
        raw = _RTF_HEX.sub("", raw)
        raw = _RTF_CONTROL.sub(" ", raw)
        raw = raw.replace("{", " ").replace("}", " ").replace("\\", " ")
        return _finalize(raw, "rtf")
    except Exception as exc:  # noqa: BLE001
        return ExtractResult(extractor="rtf", error=f"{type(exc).__name__}: {exc}")


# ---- magic-byte sniffing --------------------------------------------------

def _sniff(data: bytes) -> str:
    """Return a best-guess type for content with no/wrong extension."""
    if not data:
        return ""
    if data[:5] == b"%PDF-":
        return "pdf"
    if data[:4] == b"PK\x03\x04":
        return "zip"   # could be office; caller peeks
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"   # legacy doc/xls/ppt or .msg
    if data[:5].lower() == b"{\\rtf":
        return "rtf"
    head = data[:1024].lstrip().lower()
    if head.startswith(b"<!doctype html") or head.startswith(b"<html"):
        return "html"
    if _looks_like_text(data):
        return "text"
    return ""


def _office_kind_from_zip(data: bytes) -> str:
    """Peek inside a ZIP to tell docx / xlsx / pptx apart."""
    try:
        names = set(zipfile.ZipFile(io.BytesIO(data)).namelist())
    except Exception:
        return ""
    if "word/document.xml" in names:
        return "docx"
    if any(n.startswith("xl/") for n in names):
        return "xlsx"
    if any(n.startswith("ppt/") for n in names):
        return "pptx"
    return ""


# ---- public entry point ---------------------------------------------------

def extract_text(name: str, data: bytes) -> ExtractResult:
    """Extract plain text from a file given its name and raw bytes.

    Never raises — every failure path returns an ExtractResult with an
    `error` string so the caller can still index the file name.
    """
    if not data:
        return ExtractResult(extractor="empty", error="zero-length file")

    ext = _ext(name)

    # 1. Route by extension first (fast, usually correct)
    if ext == "pdf":
        return _extract_pdf(data)
    if ext in OFFICE_ZIP_EXT:
        return _extract_office_zip(data, "docx" if ext.startswith("doc")
                                   else "xlsx" if ext.startswith("xls")
                                   else "pptx")
    if ext == "msg":
        return _extract_msg(data)
    if ext == "eml":
        return _extract_eml(data)
    if ext in HTML_EXT:
        return _extract_html(data)
    if ext == "rtf":
        return _extract_rtf(data)
    if ext in PLAINTEXT_EXT:
        return _extract_plaintext(data)
    if ext in LEGACY_OLE_EXT:
        return ExtractResult(
            extractor="unsupported",
            error=f"legacy OLE .{ext} needs a dedicated parser (future work)",
        )

    # 2. No / unknown extension — sniff magic bytes
    sniffed = _sniff(data)
    if sniffed == "pdf":
        return _extract_pdf(data)
    if sniffed == "rtf":
        return _extract_rtf(data)
    if sniffed == "html":
        return _extract_html(data)
    if sniffed == "zip":
        kind = _office_kind_from_zip(data)
        if kind:
            return _extract_office_zip(data, kind)
        return ExtractResult(extractor="zip",
                             error="zip archive (not an office document)")
    if sniffed == "ole":
        return ExtractResult(extractor="ole",
                             error="OLE compound file (legacy office or .msg)")
    if sniffed == "text":
        return _extract_plaintext(data)

    return ExtractResult(extractor="binary",
                         error="binary or unrecognised content")


def supported_summary() -> str:
    return ("PDF, DOCX/XLSX/PPTX, MSG, EML, HTML, RTF, and plain-text / "
            "source-code files. Legacy DOC/XLS/PPT and encrypted archives "
            "are detected but not yet extracted.")
