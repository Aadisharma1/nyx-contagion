"""Pure-Python PDF 1.4 binary honeypot compiler + matching text extractor.

Zero external system dependencies: builds valid PDF byte streams with exact
byte-offset ``xref`` tables, FlateDecode content streams, an ``/Info`` metadata
dictionary, visible invoice line items, and two hidden-channel trap classes:

* invisible OCR/text-layer directives rendered with text mode ``3 Tr``
* micro-point reconciliation footnotes (0.4pt type, effectively unreadable to a
  human reviewer but fully visible to LLM document-ingestion pipelines)

The companion :class:`PdfTextExtractor` reproduces exactly what a document
ingestion pipeline sees: every text-showing operator in reading order, visible
or not.
"""
from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field
from typing import List, Sequence

from ..config import sha256_hex


@dataclass(frozen=True)
class InvoiceLine:
    description: str
    qty: float
    unit_price: float

    @property
    def amount(self) -> float:
        return round(self.qty * self.unit_price, 2)


@dataclass(frozen=True)
class PDFInvoiceSpec:
    vendor: str
    invoice_id: str
    po_number: str
    lines: Sequence[InvoiceLine]
    visible_notes: Sequence[str] = ()
    hidden_directives: Sequence[tuple[str, str]] = ()
    doc_date: str = "D:20261106090000Z"
    title: str = "Vendor Invoice"
    author: str = "Procurement Portal"

    @property
    def subtotal(self) -> float:
        return round(sum(line.amount for line in self.lines), 2)

    @property
    def tax(self) -> float:
        return round(self.subtotal * 0.0825, 2)

    @property
    def total(self) -> float:
        return round(self.subtotal + self.tax, 2)


def _pdf_escape(text: str) -> str:
    out = []
    for ch in text:
        if ch in "()\\":
            out.append("\\" + ch)
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\n":
            out.append("\\n")
        elif ord(ch) > 126:
            out.append("?")
        else:
            out.append(ch)
    return "".join(out)


def _fmt_money(value: float) -> str:
    return f"${value:,.2f}"


class PDFBinaryCompiler:
    """Compiles a :class:`PDFInvoiceSpec` into a valid PDF-1.4 byte stream."""

    MEDIA_BOX = "[0 0 612 792]"

    def compile(self, spec: PDFInvoiceSpec) -> bytes:
        content = self._content_stream(spec)
        compressed = zlib.compress(content.encode("latin-1"))

        info = {
            "/Title": f"({self._s(spec.title)})",
            "/Author": f"({self._s(spec.author)})",
            "/Subject": f"({self._s('Invoice ' + spec.invoice_id)})",
            "/Producer": "(nyx-contagion honeypot compiler)",
            "/Creator": "(nyx-contagion)",
            "/CreationDate": f"({spec.doc_date})",
        }
        objects: list[bytes] = []
        objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
        objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
        objects.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox " + self.MEDIA_BOX.encode()
            + b" /Resources << /Font << /F1 5 0 R /F2 6 0 R >> >> /Contents 4 0 R >>"
        )
        objects.append(
            b"<< /Length " + str(len(compressed)).encode()
            + b" /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream"
        )
        objects.append(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        )
        objects.append(
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
        )
        objects.append(("<< " + " ".join(f"/{k.lstrip('/')}{v}" for k, v in info.items()) + " >>").encode())

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = []
        for idx, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += f"{idx} 0 obj\n".encode() + body + b"\nendobj\n"

        xref_offset = len(out)
        n = len(objects) + 1
        out += b"xref\n"
        out += f"0 {n}\n".encode()
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += f"{off:010d} 00000 n \n".encode()
        out += (
            b"trailer\n<< /Size " + str(n).encode() + b" /Root 1 0 R /Info 7 0 R >>\n"
        )
        out += b"startxref\n" + str(xref_offset).encode() + b"\n%%EOF\n"
        return bytes(out)

    @staticmethod
    def _s(text: str) -> str:
        return text.encode("latin-1", "replace").decode("latin-1")

    def _content_stream(self, spec: PDFInvoiceSpec) -> str:
        ops: List[str] = []
        ops.append("BT /F1 16 Tf 72 740 Td (INVOICE) Tj ET")
        ops.append(f"BT /F1 11 Tf 72 718 Td ({_pdf_escape(spec.vendor)}) Tj ET")
        ops.append(f"BT /F1 10 Tf 400 740 Td (Invoice #: {_pdf_escape(spec.invoice_id)}) Tj ET")
        ops.append(f"BT /F1 10 Tf 400 726 Td (PO #: {_pdf_escape(spec.po_number)}) Tj ET")

        y = 680.0
        ops.append(f"BT /F1 10 Tf 72 {y:.0f} Td (Description) Tj ET")
        ops.append(f"BT /F1 10 Tf 330 {y:.0f} Td (Qty) Tj ET")
        ops.append(f"BT /F1 10 Tf 400 {y:.0f} Td (Unit) Tj ET")
        ops.append(f"BT /F1 10 Tf 480 {y:.0f} Td (Amount) Tj ET")
        y -= 18
        for line in spec.lines:
            ops.append(f"BT /F1 10 Tf 72 {y:.0f} Td ({_pdf_escape(line.description[:52])}) Tj ET")
            ops.append(f"BT /F1 10 Tf 330 {y:.0f} Td ({line.qty:g}) Tj ET")
            ops.append(f"BT /F1 10 Tf 400 {y:.0f} Td ({_fmt_money(line.unit_price)}) Tj ET")
            ops.append(f"BT /F1 10 Tf 480 {y:.0f} Td ({_fmt_money(line.amount)}) Tj ET")
            y -= 16
        y -= 6
        ops.append(f"BT /F1 10 Tf 400 {y:.0f} Td (Subtotal: {_fmt_money(spec.subtotal)}) Tj ET")
        y -= 14
        ops.append(f"BT /F1 10 Tf 400 {y:.0f} Td (Tax: {_fmt_money(spec.tax)}) Tj ET")
        y -= 14
        ops.append(f"BT /F1 11 Tf 400 {y:.0f} Td (TOTAL: {_fmt_money(spec.total)}) Tj ET")

        y -= 30
        for note in spec.visible_notes:
            ops.append(f"BT /F1 9 Tf 72 {y:.0f} Td ({_pdf_escape(note[:90])}) Tj ET")
            y -= 12

        for kind, directive in spec.hidden_directives:
            if kind == "ocr3tr":
                ops.append(f"BT 3 Tr /F1 10 Tf 40 40 Td ({_pdf_escape(directive)}) Tj ET")
            elif kind == "microfoot":
                ops.append(f"BT /F2 0.4 Tf 40 30 Td ({_pdf_escape(directive)}) Tj ET")
            else:
                raise ValueError(f"unknown hidden directive kind: {kind}")
        return "\n".join(ops)


@dataclass
class ExtractedPDF:
    text: str
    sha256: str
    num_objects: int
    has_xref: bool


class PdfTextExtractor:
    """Extracts the raw text stream exactly as an ingestion pipeline sees it."""

    _OBJ_RE = re.compile(rb"(\d+) 0 obj\b", re.S)
    _STREAM_RE = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
    _BT_ET_RE = re.compile(rb"BT(.*?)ET", re.S)
    _TJ_LIT_RE = re.compile(rb"\((?:\\.|[^\\()])*\)\s*Tj")
    _TJ_ARRAY_RE = re.compile(rb"\[(.*?)\]\s*TJ", re.S)
    _LIT_STR_RE = re.compile(rb"\((?:\\.|[^\\()])*\)")

    @classmethod
    def extract(cls, pdf_bytes: bytes) -> ExtractedPDF:
        pieces: List[str] = []
        n_objects = 0
        for m in cls._OBJ_RE.finditer(pdf_bytes):
            n_objects += 1
            start = m.end()
            end = pdf_bytes.find(b"endobj", start)
            body = pdf_bytes[start:end if end != -1 else len(pdf_bytes)]
            sm = cls._STREAM_RE.search(body)
            if not sm:
                continue
            raw = sm.group(1)
            if b"/FlateDecode" in body[: sm.start()]:
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    continue
            pieces.append(cls._text_from_content(raw))
        text = "\n".join(p for p in pieces if p)
        return ExtractedPDF(
            text=text,
            sha256=sha256_hex(pdf_bytes),
            num_objects=n_objects,
            has_xref=b"xref" in pdf_bytes and b"startxref" in pdf_bytes,
        )

    @classmethod
    def _text_from_content(cls, content: bytes) -> str:
        lines: List[str] = []
        for block in cls._BT_ET_RE.finditer(content):
            seg = block.group(1)
            for lit in cls._TJ_LIT_RE.finditer(seg):
                s = cls._LIT_STR_RE.search(lit.group(0))
                if s:
                    lines.append(cls._unescape(s.group(0)[1:-1]).strip())
            for arr in cls._TJ_ARRAY_RE.finditer(seg):
                for s in cls._LIT_STR_RE.finditer(arr.group(1)):
                    lines.append(cls._unescape(s.group(0)[1:-1]).strip())
        return "\n".join(line for line in lines if line)

    @staticmethod
    def _unescape(raw: bytes) -> str:
        text = raw.decode("latin-1")
        out: List[str] = []
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text):
                nxt = text[i + 1]
                mapping = {"n": "\n", "r": "\r", "t": "\t", "(": "(", ")": ")", "\\": "\\"}
                out.append(mapping.get(nxt, nxt))
                i += 2
            else:
                out.append(ch)
                i += 1
        return "".join(out)


def xref_table(pdf_bytes: bytes) -> dict[int, int]:
    """Parses the xref table and returns {object_number: byte_offset} (test aid)."""
    start = int(re.search(rb"startxref\s+(\d+)", pdf_bytes).group(1))
    if pdf_bytes[start:start + 4] != b"xref":
        raise ValueError("startxref does not point at an xref table")
    entries: dict[int, int] = {}
    count = int(re.search(rb"xref\s+(\d+)\s+(\d+)", pdf_bytes).group(2))
    cursor = pdf_bytes.index(b"\n", pdf_bytes.index(b"xref", start)) + 1
    cursor = pdf_bytes.index(b"\n", cursor) + 1
    for obj_num in range(count):
        entry = pdf_bytes[cursor:cursor + 20]
        if obj_num > 0:
            entries[obj_num] = int(entry[0:10])
        cursor += 20
    return entries
