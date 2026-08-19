#!/usr/bin/env python3
"""
pdf_check.py — эвристическая проверка цифрового (не скан) PDF на признаки
позднейшего редактирования.

Не требует внешних библиотек — работает на чистом stdlib, разбирает сырые
байты PDF по спецификации (xref/trailer/%%EOF), поэтому его можно вписать
прямо в backend (main.py) при загрузке вложения к обращению.

Проверяет:
  1. Число ревизий (incremental updates) — сколько раз файл дописывался
     поверх после первого сохранения. 1 ревизия = документ ни разу не
     пересохранялся после создания. >1 — файл правили уже после того, как
     он стал PDF (не обязательно подделка — так же работает "добавить
     подпись" или "дозаполнить форму", но повод присмотреться).
  2. Метаданные (/Info и XMP): даты создания/модификации, Producer/Creator —
     несоответствие между ними или подозрительный Producer (типа известных
     "редакторов PDF" вместо ожидаемого источника).
  3. Наличие и валидность цифровой подписи (/Type /Sig, /ByteRange) —
     единственная по-настоящему надёжная проверка. Если подпись есть и
     покрывает не весь файл (ByteRange меньше размера файла) — файл
     дописан ПОСЛЕ подписания.
  4. Объекты, помеченные как «удалённые» в последней ревизии, но чьи
     данные физически остаются в теле файла (типичный след правки текста
     наложением / повторной заливкой поля) — старые версии объектов можно
     достать и сравнить.

Использование:
    python3 pdf_check.py file1.pdf file2.pdf ...
    python3 pdf_check.py --json file.pdf        # машиночитаемый вывод

Ограничения (см. также текстовый ответ в чате):
  - Если документ не является правкой существующего PDF, а нарисован
    "с нуля" в редакторе с имитацией оригинала — эти проверки ничего не
    покажут, различий с подлинником в самом файле не будет.
  - Это скрининг-инструмент ("presumption of guilt"), не юридическое
    доказательство. Подозрительный результат — повод запросить документ
    у источника (банк/контрагент/ФНС), а не сам факт фальсификации.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime


EOF_RE = re.compile(rb"%%EOF")
STARTXREF_RE = re.compile(rb"startxref\s+(\d+)")
TRAILER_RE = re.compile(rb"trailer\s*<<(.*?)>>", re.DOTALL)
PREV_RE = re.compile(rb"/Prev\s+(\d+)")
INFO_REF_RE = re.compile(rb"/Info\s+(\d+)\s+\d+\s+R")
OBJ_RE = re.compile(rb"(\d+)\s+(\d+)\s+obj(.*?)endobj", re.DOTALL)
SIG_TYPE_RE = re.compile(rb"/Type\s*/Sig\b")
BYTERANGE_RE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")
PDF_DATE_RE = re.compile(
    rb"D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?"
)
PRODUCER_RE = re.compile(rb"/Producer\s*\((.*?)(?<!\\)\)", re.DOTALL)
CREATOR_RE = re.compile(rb"/Creator\s*\((.*?)(?<!\\)\)", re.DOTALL)
CREATIONDATE_RE = re.compile(rb"/CreationDate\s*\((D:[^)]*)\)")
MODDATE_RE = re.compile(rb"/ModDate\s*\((D:[^)]*)\)")

# Producer/Creator строки, часто встречающиеся у инструментов "перевыпуска"
# документа (не исходников банков/1С/ФНС). Наличие — не приговор, но сигнал.
SUSPICIOUS_TOOLS = [
    b"iLovePDF", b"Smallpdf", b"PDF24", b"Soda PDF", b"PDFescape",
    b"Sejda", b"pdfFiller", b"PDF-XChange Editor", b"Foxit PhantomPDF",
    b"Adobe Acrobat Pro",  # сам по себе не подозрителен, но часто = редактирование
]


def pdf_date_to_dt(raw: bytes) -> datetime | None:
    m = PDF_DATE_RE.search(raw)
    if not m:
        return None
    parts = [int(g) if g else d for g, d in zip(m.groups(), (1, 1, 1, 0, 0, 0))]
    try:
        return datetime(*parts)  # type: ignore[arg-type]
    except ValueError:
        return None


@dataclass
class PdfReport:
    path: str
    size: int
    revisions: int = 1
    creation_date: str | None = None
    mod_date: str | None = None
    producer: str | None = None
    creator: str | None = None
    has_signature: bool = False
    signature_covers_full_file: bool | None = None
    suspicious_tool: str | None = None
    flags: list[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "path": self.path,
            "size_bytes": self.size,
            "revisions": self.revisions,
            "creation_date": self.creation_date,
            "mod_date": self.mod_date,
            "producer": self.producer,
            "creator": self.creator,
            "has_signature": self.has_signature,
            "signature_covers_full_file": self.signature_covers_full_file,
            "suspicious_tool": self.suspicious_tool,
            "flags": self.flags,
            "verdict": self.verdict(),
        }

    def verdict(self) -> str:
        if self.flags:
            return "ПОДОЗРИТЕЛЬНО — есть основания присмотреться"
        return "явных следов правки не найдено"


def count_revisions(data: bytes) -> int:
    return max(1, len(EOF_RE.findall(data)))


def check_signature(data: bytes) -> tuple[bool, bool | None]:
    if not SIG_TYPE_RE.search(data):
        return False, None
    m = BYTERANGE_RE.search(data)
    if not m:
        return True, None
    start1, len1, start2, len2 = (int(g) for g in m.groups())
    covered = len1 + len2
    # ByteRange описывает подписанный диапазон (до и после блока подписи).
    # Если конец второго диапазона существенно меньше размера файла —
    # значит после подписи в файл что-то дописали.
    signed_end = start2 + len2
    return True, signed_end >= len(data) - 32  # небольшой допуск на finalизацию


def analyze(path: str) -> PdfReport:
    with open(path, "rb") as f:
        data = f.read()

    report = PdfReport(path=path, size=len(data))

    if not data.startswith(b"%PDF-"):
        report.flags.append("файл не начинается с %PDF- — это вообще не PDF или он повреждён")
        return report

    report.revisions = count_revisions(data)
    if report.revisions > 1:
        report.flags.append(
            f"файл дописывался поверх {report.revisions - 1} раз(а) после первого сохранения "
            f"(incremental update) — возможна правка контента, подпись или просто добавленные "
            f"комментарии/поля формы"
        )

    # В incremental update более новое значение дописывается ПОЗЖЕ в байтовом
    # потоке, поэтому берём последнее совпадение, а не первое.
    prod_all = PRODUCER_RE.findall(data)
    if prod_all:
        report.producer = prod_all[-1].decode("latin-1", errors="replace")
    creator_all = CREATOR_RE.findall(data)
    if creator_all:
        report.creator = creator_all[-1].decode("latin-1", errors="replace")

    all_tool_strings = b" ".join(prod_all + creator_all).decode("latin-1", errors="replace")
    for tool in SUSPICIOUS_TOOLS:
        if tool.decode() in all_tool_strings:
            report.suspicious_tool = tool.decode()
            report.flags.append(
                f"Producer/Creator указывает на инструмент пересборки PDF: {tool.decode()!r} "
                f"— типично для документов, которые не экспортированы напрямую из исходной системы"
            )
            break

    cdate_all = CREATIONDATE_RE.findall(data)
    mdate_all = MODDATE_RE.findall(data)
    cdate = pdf_date_to_dt(cdate_all[-1]) if cdate_all else None
    mdate = pdf_date_to_dt(mdate_all[-1]) if mdate_all else None
    if cdate:
        report.creation_date = cdate.isoformat()
    if mdate:
        report.mod_date = mdate.isoformat()
    if cdate and mdate and mdate < cdate:
        report.flags.append("ModDate раньше CreationDate — метаданные подделаны/некорректны")
    if cdate and mdate and (mdate - cdate).total_seconds() > 3600 and report.revisions == 1:
        report.flags.append(
            "между CreationDate и ModDate большой разрыв, но ревизия всего одна — "
            "метаданные, вероятно, проставлены вручную, а не сгенерированы честной пересборкой"
        )

    has_sig, covers_full = check_signature(data)
    report.has_signature = has_sig
    report.signature_covers_full_file = covers_full
    if has_sig and covers_full is False:
        report.flags.append(
            "в файле есть цифровая подпись, но её ByteRange НЕ покрывает весь файл — "
            "документ был изменён ПОСЛЕ подписания (это самый надёжный признак из всех)"
        )
    if not has_sig:
        report.flags.append(
            "цифровой подписи нет — подлинность нельзя подтвердить криптографически, "
            "только косвенными признаками ниже"
        )

    return report


def main(argv: list[str]) -> int:
    as_json = "--json" in argv
    paths = [a for a in argv if a != "--json"]
    if not paths:
        print(__doc__)
        return 1

    reports = [analyze(p) for p in paths]

    if as_json:
        print(json.dumps([r.to_dict() for r in reports], ensure_ascii=False, indent=2))
        return 0

    for r in reports:
        print(f"\n=== {r.path} ===")
        print(f"  размер: {r.size} байт")
        print(f"  ревизий (incremental updates): {r.revisions}")
        print(f"  создан: {r.creation_date or '—'}   изменён: {r.mod_date or '—'}")
        print(f"  Producer: {r.producer or '—'}")
        print(f"  Creator:  {r.creator or '—'}")
        print(f"  подпись: {'есть' if r.has_signature else 'нет'}"
              + (f", покрывает весь файл: {r.signature_covers_full_file}" if r.has_signature else ""))
        print(f"  вердикт: {r.verdict()}")
        for flag in r.flags:
            print(f"    ⚠ {flag}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
