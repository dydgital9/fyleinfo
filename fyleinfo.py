#!/usr/bin/env python3
"""fyleinfo: comprehensive text-file analysis using only Python stdlib.

This file is intentionally self-contained so it can be copied directly to
~/.local/bin/fyleinfo.  The optional graphical interface uses tkinter, which
is part of the Python standard library but may be packaged separately by some
Linux distributions.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import statistics
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Sequence


PROGRAM_NAME = "fyleinfo"
VERSION = "1.0.0"
DEFAULT_LONG_THRESHOLD = 7
DEFAULT_TOP_COUNT = 15
DEFAULT_MAX_BYTES = 50 * 1024 * 1024

# A deliberately small stop-word set.  It is used only when --ignore-common is
# requested, so default results never silently omit words.
COMMON_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "been", "but", "by",
    "for", "from", "had", "has", "have", "he", "her", "hers", "him",
    "his", "i", "if", "in", "into", "is", "it", "its", "me", "my",
    "no", "not", "of", "on", "or", "our", "ours", "she", "so", "that",
    "the", "their", "theirs", "them", "then", "there", "these", "they",
    "this", "those", "to", "too", "up", "us", "was", "we", "were",
    "what", "when", "where", "which", "who", "why", "will", "with",
    "you", "your", "yours",
}

# WORD_RE keeps internal hyphens and apostrophes.  Examples:
#   state-of-the-art  do-not  O'Reilly  Python3
# Underscore identifiers are analyzed separately because source-code names are
# useful developer signals but are not ordinary prose words.
WORD_RE = re.compile(r"[^\W_]+(?:[-'’][^\W_]+)*", re.UNICODE)
IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"]+", re.IGNORECASE)
EMAIL_RE = re.compile(
    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE
)
IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TODO_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|NOTE)\b", re.IGNORECASE)
NUMBER_RE = re.compile(r"^[+-]?(?:\d+(?:\.\d*)?|\.\d+)$")


class Style:
    """ANSI styling used only when stdout is an interactive terminal."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    BLUE = "\033[38;5;39m"
    GREEN = "\033[38;5;82m"
    ORANGE = "\033[38;5;208m"
    DIM = "\033[2m"


@dataclass(frozen=True)
class ReadResult:
    """Decoded text plus byte-level details needed by the report."""

    source_label: str
    path: Path | None
    raw: bytes
    text: str
    encoding: str
    decode_warning: str | None


class FyleInfoError(Exception):
    """Expected user-facing errors such as missing files or size limits."""


def human_bytes(value: int) -> str:
    """Convert a byte count into a readable binary-unit string."""

    units = ("B", "KiB", "MiB", "GiB", "TiB")
    size = float(value)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{value} B"


def percentage(part: int | float, whole: int | float) -> float:
    """Return a safe percentage, avoiding division by zero."""

    return 0.0 if whole == 0 else (float(part) / float(whole)) * 100.0


def display_char(character: str) -> str:
    """Give whitespace and control characters readable labels."""

    names = {
        " ": "SPACE",
        "\t": "TAB",
        "\n": "NEWLINE",
        "\r": "CARRIAGE RETURN",
    }
    if character in names:
        return names[character]
    if character.isprintable():
        return character
    return f"U+{ord(character):04X}"


def detect_newline_style(raw: bytes) -> dict[str, Any]:
    """Inspect raw bytes so newline style is not altered by text decoding."""

    crlf = raw.count(b"\r\n")
    remaining = raw.replace(b"\r\n", b"")
    lf = remaining.count(b"\n")
    cr = remaining.count(b"\r")

    present = [
        name
        for name, count in (("CRLF", crlf), ("LF", lf), ("CR", cr))
        if count
    ]
    if not present:
        style = "none"
    elif len(present) == 1:
        style = present[0]
    else:
        style = "mixed"

    return {"style": style, "crlf": crlf, "lf": lf, "cr": cr}


def detect_newline_style_text(text: str) -> dict[str, Any]:
    """Inspect decoded text for multibyte encodings such as UTF-16."""

    crlf = text.count("\r\n")
    remaining = text.replace("\r\n", "")
    lf = remaining.count("\n")
    cr = remaining.count("\r")

    present = [
        name
        for name, count in (("CRLF", crlf), ("LF", lf), ("CR", cr))
        if count
    ]
    if not present:
        style = "none"
    elif len(present) == 1:
        style = present[0]
    else:
        style = "mixed"

    return {"style": style, "crlf": crlf, "lf": lf, "cr": cr}


def decode_bytes(
    raw: bytes,
    requested_encoding: str,
) -> tuple[str, str, str | None]:
    """Decode bytes using an explicit encoding or a conservative auto mode."""

    if requested_encoding != "auto":
        try:
            return raw.decode(requested_encoding), requested_encoding, None
        except (LookupError, UnicodeDecodeError) as exc:
            raise FyleInfoError(
                "Unable to decode input with encoding "
                f"{requested_encoding}: {exc}"
            ) from exc

    # The byte-order mark checks prevent a UTF-16 file from being mistaken for
    # UTF-8 merely because its first few bytes happen to decode.
    candidates: list[str] = []
    if raw.startswith(b"\xef\xbb\xbf"):
        candidates.append("utf-8-sig")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        candidates.append("utf-16")
    candidates.extend(["utf-8", "cp1252", "latin-1"])

    attempted: set[str] = set()
    for encoding in candidates:
        if encoding in attempted:
            continue
        attempted.add(encoding)
        try:
            text = raw.decode(encoding)
            warning = None
            if encoding in {"cp1252", "latin-1"}:
                warning = (
                    "Input required fallback decoding with "
                    f"{encoding}; verify the "
                    "encoding when exact character fidelity matters."
                )
            return text, encoding, warning
        except UnicodeDecodeError:
            continue

    # latin-1 maps every byte, so this branch is a defensive fallback.
    return raw.decode("latin-1"), "latin-1", "Used latin-1 fallback decoding."


def read_source(
    source: str,
    requested_encoding: str = "auto",
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> ReadResult:
    """Read a path or stdin while enforcing an optional byte-size ceiling."""

    if source == "-":
        raw = sys.stdin.buffer.read()
        if max_bytes and len(raw) > max_bytes:
            raise FyleInfoError(
                f"Standard input is {human_bytes(len(raw))}, above the "
                f"configured limit of {human_bytes(max_bytes)}. Use "
                "--max-bytes 0 to disable "
                "the limit."
            )
        text, encoding, warning = decode_bytes(raw, requested_encoding)
        return ReadResult("standard input", None, raw, text, encoding, warning)

    path = Path(source).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except FileNotFoundError as exc:
        raise FyleInfoError(f"File not found: {path}") from exc

    if not resolved.is_file():
        raise FyleInfoError(f"Not a regular file: {resolved}")

    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise FyleInfoError(f"Unable to inspect file metadata: {exc}") from exc

    if max_bytes and size > max_bytes:
        raise FyleInfoError(
            f"File is {human_bytes(size)}, above the configured limit of "
            f"{human_bytes(max_bytes)}. Use --max-bytes 0 to disable "
            "the limit."
        )

    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise FyleInfoError(f"Unable to read {resolved}: {exc}") from exc

    text, encoding, warning = decode_bytes(raw, requested_encoding)
    return ReadResult(str(resolved), resolved, raw, text, encoding, warning)


def normalized_word(word: str, case_sensitive: bool) -> str:
    """Normalize a word for counting without changing the displayed source."""

    return word if case_sensitive else word.casefold()


def count_sentences(text: str) -> int:
    """Estimate sentence count from punctuation boundaries.

    This is intentionally a heuristic.  It is useful for rough text metrics but
    is not a natural-language parser and can over-count abbreviations.
    """

    stripped = text.strip()
    if not stripped:
        return 0
    endings = re.findall(r"[.!?]+(?:[\"')\]]+)?(?=\s|$)", stripped)
    return max(1, len(endings))


def valid_ipv4_addresses(text: str) -> list[str]:
    """Return valid IPv4 strings and reject invalid candidates."""

    found: list[str] = []
    for candidate in IPV4_CANDIDATE_RE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.version == 4:
            found.append(candidate)
    return found


def top_counter_items(
    counter: collections.Counter[str],
    count: int,
) -> list[dict[str, Any]]:
    """Convert Counter output into JSON-friendly dictionaries."""

    return [
        {"item": item, "count": amount}
        for item, amount in counter.most_common(count)
    ]


def analyze_text(
    read_result: ReadResult,
    *,
    case_sensitive: bool = False,
    ignore_common: bool = False,
    top_count: int = DEFAULT_TOP_COUNT,
    long_threshold: int = DEFAULT_LONG_THRESHOLD,
    excluded_words: Iterable[str] = (),
    query_words: Iterable[str] = (),
    full_frequency: bool = False,
) -> dict[str, Any]:
    """Compute prose, layout, encoding, and developer-oriented metrics."""

    text = read_result.text
    raw = read_result.raw
    lines = text.splitlines()
    # splitlines drops the final empty element.  A non-empty file ending in a
    # newline still has the expected logical line count through this
    # adjustment.
    logical_line_count = len(lines)
    if text and not lines:
        logical_line_count = 1

    words_original = WORD_RE.findall(text)
    normalized_words = [
        normalized_word(word, case_sensitive) for word in words_original
    ]

    excluded = {
        normalized_word(word, case_sensitive) for word in excluded_words
    }
    frequency_words = [
        word for word in normalized_words if word not in excluded
    ]
    if ignore_common:
        frequency_words = [
            word
            for word in frequency_words
            if word.casefold() not in COMMON_WORDS
        ]

    frequency = collections.Counter(frequency_words)
    all_frequency = collections.Counter(normalized_words)
    word_lengths = [len(word) for word in words_original]

    alphabetic_words = [word for word in words_original if word.isalpha()]
    numeric_words = [
        word for word in words_original if NUMBER_RE.fullmatch(word)
    ]
    alphanumeric_words = [word for word in words_original if word.isalnum()]
    mixed_alphanumeric = [
        word
        for word in alphanumeric_words
        if any(char.isalpha() for char in word)
        and any(char.isdigit() for char in word)
    ]
    hyphenated_words = [word for word in words_original if "-" in word]
    apostrophe_words = [
        word for word in words_original if "'" in word or "’" in word
    ]
    uppercase_words = [
        word for word in words_original
        if any(char.isalpha() for char in word) and word.isupper()
    ]
    titlecase_words = [word for word in words_original if word.istitle()]
    long_words = [
        word for word in words_original if len(word) > long_threshold
    ]

    unique_original_by_normalized: dict[str, str] = {}
    for original, normalized in zip(words_original, normalized_words):
        unique_original_by_normalized.setdefault(normalized, original)

    longest_unique = sorted(
        unique_original_by_normalized.values(),
        key=lambda item: (-len(item), item.casefold(), item),
    )[:10]
    shortest_unique = sorted(
        unique_original_by_normalized.values(),
        key=lambda item: (len(item), item.casefold(), item),
    )[:10]

    non_empty_lines = [line for line in lines if line.strip()]
    blank_lines = [line for line in lines if not line.strip()]
    line_lengths = [len(line) for line in lines]
    trailing_whitespace_lines = [
        index for index, line in enumerate(lines, start=1)
        if line.rstrip(" \t") != line
    ]
    tab_indented_lines = [
        index for index, line in enumerate(lines, start=1)
        if line.startswith("\t")
    ]
    space_indented_lines = [
        index for index, line in enumerate(lines, start=1)
        if re.match(r"^ +\S", line)
    ]
    mixed_indent_lines = [
        index for index, line in enumerate(lines, start=1)
        if re.match(r"^(?: +\t|\t+ )", line)
    ]
    over_79_lines = [
        index for index, line in enumerate(lines, start=1) if len(line) > 79
    ]
    over_120_lines = [
        index for index, line in enumerate(lines, start=1) if len(line) > 120
    ]

    nonempty_line_counter = collections.Counter(
        line.strip() for line in non_empty_lines
    )
    duplicated_line_values = {
        line: count
        for line, count in nonempty_line_counter.items()
        if count > 1
    }
    duplicated_line_occurrences = sum(
        count - 1 for count in duplicated_line_values.values()
    )

    paragraphs = [
        part
        for part in re.split(r"(?:\r?\n){2,}", text.strip())
        if part.strip()
    ] if text.strip() else []

    urls = URL_RE.findall(text)
    emails = EMAIL_RE.findall(text)
    ipv4_addresses = valid_ipv4_addresses(text)
    identifiers = IDENTIFIER_RE.findall(text)
    underscore_identifiers = [item for item in identifiers if "_" in item]
    camel_case_identifiers = [
        item for item in identifiers
        if re.search(r"[a-z][A-Z]", item) and "_" not in item
    ]

    marker_hits: list[dict[str, Any]] = []
    marker_counter: collections.Counter[str] = collections.Counter()
    for line_number, line in enumerate(lines, start=1):
        for match in TODO_RE.finditer(line):
            marker = match.group(1).upper()
            marker_counter[marker] += 1
            marker_hits.append(
                {
                    "marker": marker,
                    "line": line_number,
                    "preview": line.strip()[:160],
                }
            )

    comment_like_lines = [
        index for index, line in enumerate(lines, start=1)
        if re.match(r"^\s*(?:#|//|/\*|\*|;|<!--)", line)
    ]

    bracket_counts = {
        "parentheses": {"open": text.count("("), "close": text.count(")")},
        "square_brackets": {"open": text.count("["), "close": text.count("]")},
        "curly_braces": {"open": text.count("{"), "close": text.count("}")},
    }
    bracket_balance = {
        name: values["open"] - values["close"]
        for name, values in bracket_counts.items()
    }

    character_counter = collections.Counter(text)
    printable_non_ascii = [
        char for char in text if ord(char) > 127 and char.isprintable()
    ]
    control_characters = [
        char for char in text
        if ord(char) < 32 and char not in {"\n", "\r", "\t"}
    ]
    whitespace_characters = sum(1 for char in text if char.isspace())
    digit_characters = sum(1 for char in text if char.isdigit())
    alpha_characters = sum(1 for char in text if char.isalpha())
    punctuation_characters = sum(
        1 for char in text if not char.isalnum() and not char.isspace()
    )

    top_characters = [
        {"character": display_char(char), "count": count}
        for char, count in character_counter.most_common(15)
    ]
    top_non_ascii = top_counter_items(
        collections.Counter(printable_non_ascii), 15
    )

    query_result: dict[str, int] = {}
    for query in query_words:
        normalized_query = normalized_word(query, case_sensitive)
        query_result[query] = all_frequency.get(normalized_query, 0)

    is_multibyte_unicode = read_result.encoding.lower().startswith(
        ("utf-16", "utf-32")
    )
    newline = (
        detect_newline_style_text(text)
        if is_multibyte_unicode
        else detect_newline_style(raw)
    )
    null_bytes = raw.count(b"\x00")
    likely_binary = null_bytes > 0 and not is_multibyte_unicode

    stat_data: dict[str, Any] = {}
    if read_result.path is not None:
        stat = read_result.path.stat()
        stat_data = {
            "absolute_path": str(read_result.path),
            "file_name": read_result.path.name,
            "extension": read_result.path.suffix or "none",
            "modified_local": (
                dt.datetime.fromtimestamp(stat.st_mtime)
                .astimezone()
                .isoformat()
            ),
            "permissions_octal": oct(stat.st_mode & 0o777),
        }
    else:
        stat_data = {
            "absolute_path": None,
            "file_name": "stdin",
            "extension": "none",
            "modified_local": None,
            "permissions_octal": None,
        }

    average_word_length = (
        statistics.fmean(word_lengths) if word_lengths else 0.0
    )
    median_word_length = (
        statistics.median(word_lengths) if word_lengths else 0.0
    )
    average_line_length = (
        statistics.fmean(line_lengths) if line_lengths else 0.0
    )
    median_line_length = (
        statistics.median(line_lengths) if line_lengths else 0.0
    )
    unique_word_count = len(set(normalized_words))

    top_words = top_counter_items(frequency, max(0, top_count))
    full_words = (
        top_counter_items(frequency, len(frequency))
        if full_frequency
        else []
    )

    warnings: list[str] = []
    if read_result.decode_warning:
        warnings.append(read_result.decode_warning)
    if likely_binary:
        warnings.append(
            "NUL bytes were detected.  This file may be binary or may use a "
            "multibyte encoding that was decoded incorrectly."
        )
    if newline["style"] == "mixed":
        warnings.append("Mixed newline styles were detected.")
    if trailing_whitespace_lines:
        warnings.append(
            "Trailing spaces or tabs occur on "
            f"{len(trailing_whitespace_lines)} line(s)."
        )
    if mixed_indent_lines:
        warnings.append(
            "Mixed leading tabs and spaces occur on "
            f"{len(mixed_indent_lines)} line(s)."
        )
    unbalanced = [
        name
        for name, amount in bracket_balance.items()
        if amount != 0
    ]
    if unbalanced:
        warnings.append(
            "Raw bracket counts are unbalanced for: "
            + ", ".join(unbalanced)
            + "."
        )

    report: dict[str, Any] = {
        "program": {"name": PROGRAM_NAME, "version": VERSION},
        "generated_at": dt.datetime.now().astimezone().isoformat(),
        "source": {
            **stat_data,
            "source_label": read_result.source_label,
            "bytes": len(raw),
            "human_size": human_bytes(len(raw)),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "encoding": read_result.encoding,
            "newline": newline,
            "null_bytes": null_bytes,
            "likely_binary": likely_binary,
        },
        "overview": {
            "characters": len(text),
            "characters_without_whitespace": len(text) - whitespace_characters,
            "lines": logical_line_count,
            "non_empty_lines": len(non_empty_lines),
            "blank_lines": len(blank_lines),
            "paragraphs": len(paragraphs),
            "estimated_sentences": count_sentences(text),
            "words": len(words_original),
            "unique_words": unique_word_count,
            "lexical_diversity_percent": percentage(
                unique_word_count,
                len(words_original),
            ),
        },
        "word_statistics": {
            "most_used_word": top_words[0] if top_words else None,
            "longest_word": longest_unique[0] if longest_unique else None,
            "shortest_word": shortest_unique[0] if shortest_unique else None,
            "average_length": average_word_length,
            "median_length": median_word_length,
            "longer_than_threshold": {
                "threshold": long_threshold,
                "count": len(long_words),
                "percent": percentage(len(long_words), len(words_original)),
            },
            "hyphenated": {
                "count": len(hyphenated_words),
                "unique": len({item.casefold() for item in hyphenated_words}),
            },
            "apostrophe_words": {
                "count": len(apostrophe_words),
                "unique": len({item.casefold() for item in apostrophe_words}),
            },
            "all_caps": {
                "count": len(uppercase_words),
                "unique": len({item.casefold() for item in uppercase_words}),
            },
            "title_case": {
                "count": len(titlecase_words),
                "unique": len({item.casefold() for item in titlecase_words}),
            },
            "alphabetic": len(alphabetic_words),
            "numeric": len(numeric_words),
            "alphanumeric": len(alphanumeric_words),
            "mixed_alphanumeric": len(mixed_alphanumeric),
            "longest_unique": longest_unique,
            "shortest_unique": shortest_unique,
            "top_words": top_words,
            "full_frequency": full_words,
        },
        "line_and_layout": {
            "average_line_length": average_line_length,
            "median_line_length": median_line_length,
            "maximum_line_length": max(line_lengths, default=0),
            "maximum_line_number": (
                line_lengths.index(max(line_lengths)) + 1
                if line_lengths
                else None
            ),
            "lines_over_79": len(over_79_lines),
            "line_numbers_over_79": over_79_lines[:50],
            "lines_over_120": len(over_120_lines),
            "line_numbers_over_120": over_120_lines[:50],
            "trailing_whitespace_lines": len(trailing_whitespace_lines),
            "trailing_whitespace_line_numbers": trailing_whitespace_lines[:50],
            "tab_indented_lines": len(tab_indented_lines),
            "space_indented_lines": len(space_indented_lines),
            "mixed_indent_lines": len(mixed_indent_lines),
            "mixed_indent_line_numbers": mixed_indent_lines[:50],
            "duplicate_nonempty_line_values": len(duplicated_line_values),
            "duplicate_extra_occurrences": duplicated_line_occurrences,
            "top_duplicate_lines": [
                {"line": line, "count": count}
                for line, count in sorted(
                    duplicated_line_values.items(),
                    key=lambda pair: (-pair[1], pair[0]),
                )[:10]
            ],
        },
        "developer_signals": {
            "urls": {"count": len(urls), "unique": sorted(set(urls))[:50]},
            "emails": {
                "count": len(emails),
                "unique": sorted(set(emails))[:50],
            },
            "ipv4_addresses": {
                "count": len(ipv4_addresses),
                "unique": sorted(set(ipv4_addresses))[:50],
            },
            "identifiers": {
                "count": len(identifiers),
                "unique": len(set(identifiers)),
                "underscore_style": len(underscore_identifiers),
                "camel_case": len(camel_case_identifiers),
                "top": top_counter_items(collections.Counter(identifiers), 15),
            },
            "comment_like_lines": len(comment_like_lines),
            "markers": {
                "counts": dict(sorted(marker_counter.items())),
                "hits": marker_hits[:100],
            },
            "brackets": {
                "counts": bracket_counts,
                "raw_balance": bracket_balance,
                "note": (
                    "Raw counts do not parse strings or comments, so a "
                    "nonzero balance is a review signal rather than proof of "
                    "a syntax error."
                ),
            },
        },
        "character_statistics": {
            "alphabetic": alpha_characters,
            "digits": digit_characters,
            "whitespace": whitespace_characters,
            "punctuation_or_symbols": punctuation_characters,
            "tabs": text.count("\t"),
            "spaces": text.count(" "),
            "non_ascii_printable": len(printable_non_ascii),
            "unique_non_ascii_printable": len(set(printable_non_ascii)),
            "control_characters_excluding_newline_tab": len(
                control_characters
            ),
            "top_characters": top_characters,
            "top_non_ascii": top_non_ascii,
        },
        "query_words": query_result,
        "settings": {
            "case_sensitive": case_sensitive,
            "ignore_common": ignore_common,
            "top_count": top_count,
            "long_threshold": long_threshold,
            "excluded_words": sorted(excluded),
        },
        "warnings": warnings,
    }
    return report


def fmt_number(value: int | float) -> str:
    """Format integers with grouping and floats with two decimal places."""

    if isinstance(value, bool):
        return str(value)
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, float):
        return f"{value:,.2f}"
    return str(value)


def list_preview(values: Sequence[Any], limit: int = 10) -> str:
    """Render a compact comma-separated preview."""

    if not values:
        return "none"
    text = ", ".join(str(value) for value in values[:limit])
    if len(values) > limit:
        text += f", ... and {len(values) - limit} more"
    return text


def make_painter(color_enabled: bool):
    """Return a small function that conditionally wraps ANSI sequences."""

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{Style.RESET}" if color_enabled else text

    return paint


def render_text(report: dict[str, Any], color_enabled: bool = False) -> str:
    """Create the human-readable terminal report."""

    paint = make_painter(color_enabled)
    source = report["source"]
    overview = report["overview"]
    words = report["word_statistics"]
    layout = report["line_and_layout"]
    dev = report["developer_signals"]
    chars = report["character_statistics"]
    settings = report["settings"]

    output: list[str] = []
    width = 78

    def section(title: str) -> None:
        output.append("")
        output.append(paint(title, Style.BOLD + Style.BLUE))
        output.append(paint("─" * min(width, len(title) + 12), Style.DIM))

    def row(label: str, value: Any, note: str | None = None) -> None:
        rendered = (
            fmt_number(value)
            if isinstance(value, (int, float))
            else str(value)
        )
        line = f"  {label:<34} {paint(rendered, Style.GREEN)}"
        if note:
            line += f"  {paint(note, Style.DIM)}"
        output.append(line)

    title = (
        f"{PROGRAM_NAME} {report['program']['version']}"
        "  |  Text File Analysis"
    )
    output.append(paint("═" * width, Style.BLUE))
    output.append(paint(title.center(width), Style.BOLD + Style.BLUE))
    output.append(paint("═" * width, Style.BLUE))

    section("SOURCE")
    row("Source", source["source_label"])
    row("Size", f"{source['human_size']} ({source['bytes']:,} bytes)")
    row("Encoding", source["encoding"])
    row("Newline style", source["newline"]["style"])
    if source.get("modified_local"):
        row("Modified", source["modified_local"])
    if source.get("permissions_octal"):
        row("Permissions", source["permissions_octal"])
    row("SHA-256", source["sha256"])

    section("OVERVIEW")
    row("Total words", overview["words"])
    row("Unique words", overview["unique_words"])
    row("Lexical diversity", f"{overview['lexical_diversity_percent']:.2f}%")
    row("Characters", overview["characters"])
    row(
        "Characters without whitespace",
        overview["characters_without_whitespace"],
    )
    row("Lines", overview["lines"])
    row("Non-empty lines", overview["non_empty_lines"])
    row("Blank lines", overview["blank_lines"])
    row("Paragraphs", overview["paragraphs"])
    row("Estimated sentences", overview["estimated_sentences"], "heuristic")

    section("WORD STATISTICS")
    most_used = words["most_used_word"]
    row(
        "Most used word",
        (
            f"{most_used['item']} ({most_used['count']:,})"
            if most_used
            else "none"
        ),
    )
    row("Longest word", words["longest_word"] or "none")
    row("Shortest word", words["shortest_word"] or "none")
    row("Average word length", words["average_length"])
    row("Median word length", words["median_length"])
    threshold = words["longer_than_threshold"]
    row(
        f"Words longer than {threshold['threshold']}",
        threshold["count"],
        f"{threshold['percent']:.2f}%",
    )
    row("Words containing a hyphen", words["hyphenated"]["count"])
    row("Words containing an apostrophe", words["apostrophe_words"]["count"])
    row("All-caps words", words["all_caps"]["count"])
    row("Title-case words", words["title_case"]["count"])
    row("Alphabetic words", words["alphabetic"])
    row("Numeric tokens", words["numeric"])
    row("Alphanumeric words", words["alphanumeric"])
    row("Mixed letter-number words", words["mixed_alphanumeric"])
    row("Longest unique words", list_preview(words["longest_unique"], 10))

    section(f"TOP {settings['top_count']} WORDS")
    if words["top_words"]:
        for index, item in enumerate(words["top_words"], start=1):
            count_text = f"{item['count']:,}"
            output.append(
                f"  {index:>3}. {item['item']:<32} "
                f"{paint(count_text, Style.GREEN)}"
            )
    else:
        output.append("  none")

    section("LINE AND LAYOUT REVIEW")
    row("Average line length", layout["average_line_length"])
    row("Median line length", layout["median_line_length"])
    row(
        "Maximum line length",
        layout["maximum_line_length"],
        (
            f"line {layout['maximum_line_number']}"
            if layout["maximum_line_number"]
            else None
        ),
    )
    row("Lines longer than 79 chars", layout["lines_over_79"])
    row("Lines longer than 120 chars", layout["lines_over_120"])
    row("Lines with trailing whitespace", layout["trailing_whitespace_lines"])
    row("Tab-indented lines", layout["tab_indented_lines"])
    row("Space-indented lines", layout["space_indented_lines"])
    row("Mixed-indent lines", layout["mixed_indent_lines"])
    row(
        "Duplicate non-empty line values",
        layout["duplicate_nonempty_line_values"],
    )
    row("Extra duplicate occurrences", layout["duplicate_extra_occurrences"])

    section("DEVELOPER SIGNALS")
    row("URLs", dev["urls"]["count"])
    row("Email addresses", dev["emails"]["count"])
    row("IPv4 addresses", dev["ipv4_addresses"]["count"])
    row("Identifier-like tokens", dev["identifiers"]["count"])
    row("Unique identifiers", dev["identifiers"]["unique"])
    row("Underscore identifiers", dev["identifiers"]["underscore_style"])
    row("Camel-case identifiers", dev["identifiers"]["camel_case"])
    row("Comment-like lines", dev["comment_like_lines"])
    marker_counts = dev["markers"]["counts"]
    row(
        "Review markers",
        sum(marker_counts.values()),
        (
            ", ".join(
                f"{key}={value}"
                for key, value in marker_counts.items()
            )
            or "none"
        ),
    )
    for bracket_name, balance in dev["brackets"]["raw_balance"].items():
        row(f"Raw {bracket_name} balance", balance)

    section("CHARACTERS AND ENCODING")
    row("Alphabetic characters", chars["alphabetic"])
    row("Digit characters", chars["digits"])
    row("Whitespace characters", chars["whitespace"])
    row("Punctuation or symbols", chars["punctuation_or_symbols"])
    row("Space characters", chars["spaces"])
    row("Tab characters", chars["tabs"])
    row("Printable non-ASCII chars", chars["non_ascii_printable"])
    row("Unique printable non-ASCII", chars["unique_non_ascii_printable"])
    row(
        "Other control characters",
        chars["control_characters_excluding_newline_tab"],
    )
    row("NUL bytes", source["null_bytes"])

    if report["query_words"]:
        section("REQUESTED WORD COUNTS")
        for query, count in report["query_words"].items():
            row(query, count)

    section("WARNINGS AND REVIEW ITEMS")
    if report["warnings"]:
        for warning in report["warnings"]:
            output.append(f"  {paint('WARNING', Style.ORANGE)}  {warning}")
    else:
        output.append(
            f"  {paint('No automatic warnings detected.', Style.GREEN)}"
        )

    output.append("")
    output.append(paint("═" * width, Style.BLUE))
    output.append(
        paint(
            f"Generated {report['generated_at']}  |  {PROGRAM_NAME}",
            Style.DIM,
        )
    )
    return "\n".join(output)


def render_json(report: dict[str, Any]) -> str:
    """Serialize the report with indentation and Unicode preservation."""

    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)


def default_save_path(source: str, output_format: str) -> Path:
    """Build the requested file-name-plus-.word-review default path."""

    suffix = (
        ".word-review.json"
        if output_format == "json"
        else ".word-review.txt"
    )
    if source == "-":
        return Path.cwd() / f"stdin{suffix}"
    path = Path(source).expanduser()
    return Path(f"{path}{suffix}")


def write_report(path: Path, content: str, overwrite: bool = False) -> None:
    """Write UTF-8 output and protect existing files by default."""

    target = path.expanduser()
    if target.exists() and not overwrite:
        raise FyleInfoError(
            f"Output already exists: {target}. Use --overwrite to replace it."
        )
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        final_content = content + (
            "" if content.endswith("\n") else "\n"
        )
        target.write_text(final_content, encoding="utf-8")
    except OSError as exc:
        raise FyleInfoError(f"Unable to write report {target}: {exc}") from exc


def positive_int(value: str) -> int:
    """argparse converter for values that must be zero or greater."""

    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 0:
        raise argparse.ArgumentTypeError("must be zero or greater")
    return number


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line interface and its help text."""

    parser = argparse.ArgumentParser(
        prog=PROGRAM_NAME,
        description=(
            "Analyze a text file and report word, line, character, encoding, "
            "layout, and developer-oriented statistics."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  fyleinfo notes.txt\n"
            "  fyleinfo --save notes.txt\n"
            "  fyleinfo --format json --output report.json notes.txt\n"
            "  fyleinfo --find Python --find TODO source.py\n"
            "  printf 'alpha beta beta' | fyleinfo -\n"
            "  fyleinfo --gui notes.txt"
        ),
    )
    parser.add_argument(
        "file",
        nargs="?",
        help="file to analyze, or - to read standard input",
    )
    parser.add_argument(
        "-s",
        "--save",
        action="store_true",
        help=(
            "save to FILE.word-review.txt or FILE.word-review.json while also "
            "printing the report"
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        metavar="PATH",
        help="save to PATH; this implies --save",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=(
            "suppress terminal report output; normally used with --save "
            "or --output"
        ),
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="allow --save to replace an existing output file",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format, default: text",
    )
    parser.add_argument(
        "-t",
        "--top",
        type=positive_int,
        default=DEFAULT_TOP_COUNT,
        metavar="N",
        help=f"number of frequent words to show, default: {DEFAULT_TOP_COUNT}",
    )
    parser.add_argument(
        "--long-threshold",
        type=positive_int,
        default=DEFAULT_LONG_THRESHOLD,
        metavar="N",
        help=(
            "count words longer than N characters, "
            f"default: {DEFAULT_LONG_THRESHOLD}"
        ),
    )
    parser.add_argument(
        "--case-sensitive",
        action="store_true",
        help="treat Word and word as different frequency entries",
    )
    parser.add_argument(
        "--ignore-common",
        action="store_true",
        help="omit a small English stop-word set from frequency rankings",
    )
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="WORD",
        help="exclude WORD from frequency rankings; may be repeated",
    )
    parser.add_argument(
        "--find",
        action="append",
        default=[],
        metavar="WORD",
        help="report the exact token count for WORD; may be repeated",
    )
    parser.add_argument(
        "--full-frequency",
        action="store_true",
        help="include the complete frequency table in JSON output",
    )
    parser.add_argument(
        "--encoding",
        default="auto",
        metavar="NAME",
        help="input encoding or auto, default: auto",
    )
    parser.add_argument(
        "--max-bytes",
        type=positive_int,
        default=DEFAULT_MAX_BYTES,
        metavar="N",
        help=(
            "maximum input size in bytes; 0 disables the limit, default: "
            f"{DEFAULT_MAX_BYTES}"
        ),
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in terminal text output",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="open the tkinter interface; FILE is optional",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )
    return parser


def launch_gui(initial_file: str | None = None) -> int:
    """Start the optional tkinter front end."""

    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError as exc:
        raise FyleInfoError(
            "tkinter is not available. On Linux Mint or Ubuntu, install "
            "it with: "
            "sudo apt install python3-tk"
        ) from exc

    class FyleInfoApp:
        """GUI wrapper around shared read, analyze, and render functions."""

        def __init__(self, root: "tk.Tk") -> None:
            self.root = root
            self.root.title("fyleinfo - Text File Analysis")
            self.root.geometry("1120x760")
            self.root.minsize(820, 560)
            self.current_report: dict[str, Any] | None = None
            self.current_rendered = ""

            self.file_var = tk.StringVar(value=initial_file or "")
            self.format_var = tk.StringVar(value="text")
            self.top_var = tk.IntVar(value=DEFAULT_TOP_COUNT)
            self.threshold_var = tk.IntVar(value=DEFAULT_LONG_THRESHOLD)
            self.case_var = tk.BooleanVar(value=False)
            self.stop_var = tk.BooleanVar(value=False)
            self.status_var = tk.StringVar(
                value="Select a text file, then choose Analyze."
            )

            self._configure_style(ttk)
            self._build_widgets(tk, ttk, filedialog, messagebox)

            if initial_file:
                self.root.after(100, self.analyze)

        def _configure_style(self, ttk_module: Any) -> None:
            style = ttk_module.Style()
            if "clam" in style.theme_names():
                style.theme_use("clam")
            self.root.configure(bg="#070b10")
            style.configure("TFrame", background="#070b10")
            style.configure(
                "TLabel",
                background="#070b10",
                foreground="#dbe9f4",
                font=("Sans", 10),
            )
            style.configure(
                "Title.TLabel",
                background="#070b10",
                foreground="#39a8ff",
                font=("Sans", 18, "bold"),
            )
            style.configure(
                "TButton",
                background="#14283a",
                foreground="#e8f4ff",
                padding=(12, 8),
                borderwidth=1,
            )
            style.map("TButton", background=[("active", "#1f4664")])
            style.configure(
                "TCheckbutton", background="#070b10", foreground="#dbe9f4"
            )
            style.configure(
                "TEntry", fieldbackground="#0d1620", foreground="#f1f7fb"
            )
            style.configure(
                "TCombobox", fieldbackground="#0d1620", foreground="#f1f7fb"
            )
            style.configure("TSpinbox", fieldbackground="#0d1620")

        def _build_widgets(
            self,
            tk_module: Any,
            ttk_module: Any,
            filedialog_module: Any,
            messagebox_module: Any,
        ) -> None:
            self.filedialog = filedialog_module
            self.messagebox = messagebox_module

            outer = ttk_module.Frame(self.root, padding=14)
            outer.pack(fill="both", expand=True)

            ttk_module.Label(
                outer, text="fyleinfo", style="Title.TLabel"
            ).pack(anchor="w")
            ttk_module.Label(
                outer,
                text=(
                    "Comprehensive text, layout, encoding, and "
                    "developer-signal review"
                ),
            ).pack(anchor="w", pady=(0, 12))

            file_row = ttk_module.Frame(outer)
            file_row.pack(fill="x", pady=(0, 8))
            ttk_module.Label(file_row, text="File").pack(side="left")
            self.file_entry = ttk_module.Entry(
                file_row,
                textvariable=self.file_var,
            )
            self.file_entry.pack(side="left", fill="x", expand=True, padx=8)
            ttk_module.Button(
                file_row,
                text="Browse",
                command=self.browse,
            ).pack(side="left")

            options = ttk_module.Frame(outer)
            options.pack(fill="x", pady=(0, 8))
            ttk_module.Label(options, text="Format").pack(side="left")
            ttk_module.Combobox(
                options,
                textvariable=self.format_var,
                values=("text", "json"),
                state="readonly",
                width=8,
            ).pack(side="left", padx=(6, 16))
            ttk_module.Label(options, text="Top words").pack(side="left")
            ttk_module.Spinbox(
                options, from_=0, to=500, textvariable=self.top_var, width=7
            ).pack(side="left", padx=(6, 16))
            ttk_module.Label(options, text="Longer than").pack(side="left")
            ttk_module.Spinbox(
                options,
                from_=0,
                to=200,
                textvariable=self.threshold_var,
                width=7,
            ).pack(side="left", padx=(6, 16))
            ttk_module.Checkbutton(
                options, text="Case-sensitive", variable=self.case_var
            ).pack(side="left", padx=(0, 12))
            ttk_module.Checkbutton(
                options, text="Ignore common words", variable=self.stop_var
            ).pack(side="left")

            actions = ttk_module.Frame(outer)
            actions.pack(fill="x", pady=(0, 8))
            ttk_module.Button(
                actions,
                text="Analyze",
                command=self.analyze,
            ).pack(
                side="left", padx=(0, 6)
            )
            ttk_module.Button(
                actions,
                text="Save report",
                command=self.save,
            ).pack(
                side="left", padx=6
            )
            ttk_module.Button(
                actions,
                text="Copy report",
                command=self.copy,
            ).pack(
                side="left", padx=6
            )
            ttk_module.Button(actions, text="Clear", command=self.clear).pack(
                side="left", padx=6
            )
            ttk_module.Button(
                actions,
                text="Exit",
                command=self.root.destroy,
            ).pack(
                side="right"
            )

            text_frame = ttk_module.Frame(outer)
            text_frame.pack(fill="both", expand=True)
            self.output = tk_module.Text(
                text_frame,
                wrap="none",
                bg="#05080c",
                fg="#dcecff",
                insertbackground="#ffffff",
                selectbackground="#164f72",
                relief="flat",
                padx=12,
                pady=12,
                font=("Monospace", 10),
            )
            vertical = ttk_module.Scrollbar(
                text_frame, orient="vertical", command=self.output.yview
            )
            horizontal = ttk_module.Scrollbar(
                text_frame, orient="horizontal", command=self.output.xview
            )
            self.output.configure(
                yscrollcommand=vertical.set, xscrollcommand=horizontal.set
            )
            self.output.grid(row=0, column=0, sticky="nsew")
            vertical.grid(row=0, column=1, sticky="ns")
            horizontal.grid(row=1, column=0, sticky="ew")
            text_frame.rowconfigure(0, weight=1)
            text_frame.columnconfigure(0, weight=1)

            ttk_module.Label(outer, textvariable=self.status_var).pack(
                fill="x", pady=(8, 0)
            )

            self.root.bind("<Control-o>", lambda _event: self.browse())
            self.root.bind("<Control-s>", lambda _event: self.save())
            self.root.bind("<Control-Return>", lambda _event: self.analyze())
            self.root.bind("<Escape>", lambda _event: self.root.destroy())

        def browse(self) -> None:
            selected = self.filedialog.askopenfilename(
                title="Select a text file"
            )
            if selected:
                self.file_var.set(selected)
                self.analyze()

        def analyze(self) -> None:
            source = self.file_var.get().strip()
            if not source:
                self.messagebox.showerror("fyleinfo", "Select a file first.")
                return
            try:
                read_result = read_source(source)
                report = analyze_text(
                    read_result,
                    case_sensitive=self.case_var.get(),
                    ignore_common=self.stop_var.get(),
                    top_count=max(0, self.top_var.get()),
                    long_threshold=max(0, self.threshold_var.get()),
                )
                rendered = (
                    render_json(report)
                    if self.format_var.get() == "json"
                    else render_text(report, color_enabled=False)
                )
            except (FyleInfoError, OSError, ValueError) as exc:
                self.messagebox.showerror("fyleinfo", str(exc))
                self.status_var.set("Analysis failed.")
                return

            self.current_report = report
            self.current_rendered = rendered
            self.output.delete("1.0", "end")
            self.output.insert("1.0", rendered)
            self.status_var.set(
                f"Analyzed {source}: {report['overview']['words']:,} words, "
                f"{report['overview']['lines']:,} lines."
            )

        def save(self) -> None:
            if not self.current_rendered:
                self.analyze()
            if not self.current_rendered:
                return
            source = self.file_var.get().strip()
            default = default_save_path(source, self.format_var.get())
            selected = self.filedialog.asksaveasfilename(
                title="Save fyleinfo report",
                initialdir=str(default.parent),
                initialfile=default.name,
                defaultextension=(
                    ".json" if self.format_var.get() == "json" else ".txt"
                ),
            )
            if not selected:
                return
            try:
                write_report(
                    Path(selected),
                    self.current_rendered,
                    overwrite=True,
                )
            except FyleInfoError as exc:
                self.messagebox.showerror("fyleinfo", str(exc))
                return
            self.status_var.set(f"Saved report to {selected}")

        def copy(self) -> None:
            if not self.current_rendered:
                self.analyze()
            if not self.current_rendered:
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(self.current_rendered)
            self.root.update()
            self.status_var.set("Report copied to the clipboard.")

        def clear(self) -> None:
            self.output.delete("1.0", "end")
            self.current_report = None
            self.current_rendered = ""
            self.status_var.set("Output cleared.")

    root = tk.Tk()
    FyleInfoApp(root)
    root.mainloop()
    return 0


def run_cli(args: argparse.Namespace) -> int:
    """Execute one non-GUI analysis request."""

    if not args.file:
        raise FyleInfoError(
            "A FILE argument is required unless --gui is used."
        )

    read_result = read_source(
        args.file,
        requested_encoding=args.encoding,
        max_bytes=args.max_bytes,
    )
    report = analyze_text(
        read_result,
        case_sensitive=args.case_sensitive,
        ignore_common=args.ignore_common,
        top_count=args.top,
        long_threshold=args.long_threshold,
        excluded_words=args.exclude,
        query_words=args.find,
        full_frequency=args.full_frequency,
    )

    color_enabled = (
        args.format == "text"
        and not args.no_color
        and sys.stdout.isatty()
        and os.environ.get("NO_COLOR") is None
    )
    rendered = (
        render_json(report)
        if args.format == "json"
        else render_text(report, color_enabled=color_enabled)
    )

    # Default behavior prints.  --save adds a file output; --quiet is available
    # for scripts that need only the generated file.
    if not args.quiet:
        print(rendered)

    if args.save or args.output:
        save_path = (
            Path(args.output)
            if args.output
            else default_save_path(args.file, args.format)
        )
        write_report(save_path, rendered, overwrite=args.overwrite)
        print(f"Saved report: {save_path}", file=sys.stderr)

    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Program entry point with clean, user-facing error handling."""

    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.gui:
            return launch_gui(args.file)
        return run_cli(args)
    except KeyboardInterrupt:
        print(f"{PROGRAM_NAME}: interrupted", file=sys.stderr)
        return 130
    except FyleInfoError as exc:
        print(f"{PROGRAM_NAME}: error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
