"""Plain 'what is this?' help popups for forensic concepts in the UI."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QLabel, QPushButton, QSizePolicy,
    QTextBrowser, QVBoxLayout, QWidget,
)


HELP: dict[str, dict[str, str]] = {
    "audit_chain": {
        "title": "Verify Audit Chain",
        "body": """
<h3>What is the audit log?</h3>
<p>Every action the examiner performs in this tool is recorded as a row in
the case's <code>audit_log</code> table inside <code>case.db</code>:
opening the case, ingesting evidence, running a search, exporting a
report, signing a manifest, even free-form notes you save.</p>

<h3>What is the chain?</h3>
<p>Each row stores a SHA-256 hash that covers <b>its own payload + the
row hash of the previous entry</b>. So the log is a hash chain (the
same construction blockchains use).</p>

<h3>Why?</h3>
<p>If anyone later edits a historical row, deletes a row, or inserts a
fake one, the chain breaks at that point. <b>Verify Audit Chain</b>
walks the table forward and re-derives every hash. If a single byte
of any row has been changed, the verification fails and tells you
which row first broke.</p>

<h3>What's it for?</h3>
<p>Courtroom defensibility. An examiner being cross-examined can show:
"every action I took on this evidence is in this log; the log is
hash-chained; here is the verification proving it has not been
tampered with."</p>
""",
    },
    "sign_manifest": {
        "title": "Sign Manifest",
        "body": """
<h3>What is the manifest?</h3>
<p>A JSON file listing every file in the case folder along with its
SHA-256 hash, file sizes, the tool's dependency versions at the time
of the run, and the OS / Python environment.</p>

<h3>What is signing?</h3>
<p><b>Sign Manifest</b> writes the JSON to <code>manifest.json</code>
and an <b>Ed25519 signature</b> over its bytes to
<code>manifest.sig</code>. The signing key is generated once per case
and stored in <code>keys/case_ed25519.key</code>.</p>

<h3>Why not bit-for-bit reproducibility?</h3>
<p>Tantivy segment IDs and worker scheduling are non-deterministic, so
the underlying index bytes can vary across runs even with identical
input. What the manifest <i>does</i> guarantee is: "given the inputs
named in this manifest, with these tool versions, an examiner can
re-verify all output hashes." That's the reproducibility level
defensible in court.</p>

<h3>When to sign?</h3>
<p>At the end of an examination, before producing a report or sending
evidence packages to opposing counsel. Sign again any time the case
folder changes materially.</p>
""",
    },
    "tlsh": {
        "title": "TLSH — Trend Micro Locality Sensitive Hash",
        "body": """
<h3>What is TLSH?</h3>
<p>A <b>fuzzy similarity hash</b>. Unlike MD5/SHA-256 (which change
completely if a single byte changes), TLSH produces a 72-character
hex string where <i>close files get close hashes</i>.</p>

<h3>How is it used?</h3>
<p>Find related variants in an investigation:</p>
<ul>
<li>An attacker renamed <code>mimikatz.exe</code> to
<code>winhelper.dll</code>: identical MD5, so the
<code>file_name</code> rename hides nothing, but if the binary was
also slightly modified, TLSH still places it nearby.</li>
<li>A document gets resaved with small edits: SHA-256 differs, TLSH
keeps it in the cluster of related drafts.</li>
<li>Configurable malware payloads: same family, different campaigns,
different SHA-256 — clustered by TLSH.</li>
</ul>

<h3>Distance scale</h3>
<p>TLSH "distance" is an integer:</p>
<ul>
<li><b>0</b>: identical content</li>
<li><b>1-30</b>: very similar (likely related)</li>
<li><b>30-100</b>: somewhat similar</li>
<li><b>&gt; 200</b>: probably unrelated</li>
</ul>

<h3>Why not ssdeep?</h3>
<p>TLSH has better statistical properties and is actively maintained
by Trend Micro. ssdeep is kept around for NSRL backward compatibility
in try2 but isn't enabled by default.</p>
""",
    },
    "hash_policy": {
        "title": "Hash Policy",
        "body": """
<h3>What is it?</h3>
<p>The case's <b>chosen hash algorithms</b>. The Primary algorithm is
the one your courtroom / agency wants as the canonical fingerprint;
Extras are additional digests computed in the same pass.</p>

<h3>Which to pick?</h3>
<ul>
<li><b>SHA-256</b> &mdash; recommended default. The modern courtroom
standard.</li>
<li><b>MD5</b> &mdash; cryptographically broken but mandated by NSRL
RDS and many older evidence-handling SOPs. Keep as an Extra if your
receiving agency requires it.</li>
<li><b>SHA-1</b> &mdash; weakened; required for some legacy chain-of-
custody systems.</li>
<li><b>SHA-512</b> &mdash; stronger than SHA-256, slower; rarely
mandated.</li>
<li><b>BLAKE2b</b> &mdash; faster than SHA-256 on commodity CPUs,
modern cryptographic strength. Not yet a courtroom default.</li>
</ul>

<h3>Why a policy?</h3>
<p>Lock the choice for the whole case so every later ingest, integrity
export, and audit-log entry uses the same set of digests &mdash; no
mixed-algorithm chain-of-custody.</p>
""",
    },
}


class HelpDialog(QDialog):
    def __init__(self, parent: QWidget | None = None, *, key: str):
        super().__init__(parent)
        item = HELP.get(key)
        if not item:
            item = {"title": "Help", "body": "(no entry)"}
        self.setWindowTitle(item["title"])
        self.resize(620, 460)
        self.setStyleSheet(parent.styleSheet() if parent else "")
        v = QVBoxLayout(self)
        v.setContentsMargins(16, 16, 16, 12)

        head = QLabel(item["title"])
        head.setObjectName("h1")
        v.addWidget(head)

        body = QTextBrowser()
        body.setOpenExternalLinks(True)
        body.setHtml(item["body"])
        body.setStyleSheet(
            "QTextBrowser { background:#14171d; border:1px solid #2a2d35; "
            "border-radius:4px; padding:8px; color:#e8e8ea; }"
        )
        v.addWidget(body, 1)

        btns = QDialogButtonBox(QDialogButtonBox.Ok)
        btns.accepted.connect(self.accept)
        v.addWidget(btns)


def info_button(key: str, parent: QWidget | None = None) -> QPushButton:
    """A small inline '?' button that opens the named help entry."""
    b = QPushButton("?")
    b.setFixedSize(22, 22)
    b.setToolTip(f"What is this? ({HELP.get(key, {}).get('title', key)})")
    b.setStyleSheet(
        "QPushButton { background:#2a2d35; color:#e8e8ea; border-radius:11px; "
        "font-weight:700; font-size:11px; padding:0; }"
        "QPushButton:hover { background:#353944; }"
    )
    b.clicked.connect(lambda: HelpDialog(parent, key=key).exec())
    return b
