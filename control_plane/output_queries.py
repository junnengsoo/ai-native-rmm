from __future__ import annotations

from typing import Iterable, Mapping


MAX_RESPONSE_CONTENT_BYTES = 65_536
MAX_QUERY_SCAN_EVENTS = 4_096
MAX_QUERY_SCAN_BYTES = 1_048_576


def _event_sequence(event: Mapping[str, object]) -> int:
    return int(event["sequence"])


def _event_text(event: Mapping[str, object]) -> str:
    return str(event["text"])


def _event_byte_count(event: Mapping[str, object]) -> int:
    return int(event["byte_count"])


def _take_utf8_prefix(value: str, limit: int) -> tuple[str, bool]:
    parts, size = [], 0
    for character in value:
        character_size = len(character.encode())
        if size + character_size > limit:
            return "".join(parts), True
        parts.append(character)
        size += character_size
    return value, False


def _take_utf8_suffix(value: str, limit: int) -> tuple[str, int, bool]:
    parts, size, removed = [], 0, len(value.encode())
    for character in reversed(value):
        character_size = len(character.encode())
        if size + character_size > limit:
            return "".join(reversed(parts)), removed - size, True
        parts.append(character)
        size += character_size
    return value, 0, False


def _byte_offset_for_char(value: str, char_index: int) -> int:
    return len(value[:char_index].encode())


def _char_index_for_byte(value: str, byte_offset: int) -> int:
    size = 0
    for index, character in enumerate(value):
        character_size = len(character.encode())
        if size + character_size > byte_offset:
            return index
        size += character_size
    return len(value)


def _line_spans(value: str) -> list[tuple[int, int]]:
    spans, start = [], 0
    for line in value.splitlines(keepends=True):
        end = start + len(line)
        spans.append((start, end))
        start = end
    if value and (not spans or spans[-1][1] < len(value)):
        spans.append((start, len(value)))
    return spans


def _line_index_at_char(spans: list[tuple[int, int]], char_index: int) -> int:
    if not spans:
        return 0
    for index, (start, end) in enumerate(spans):
        if start <= char_index < end:
            return index
    return len(spans) - 1


def _line_range_for_chars(value: str, start_char: int, end_char: int) -> dict[str, int]:
    spans = _line_spans(value)
    if not spans:
        return {"start_line": 1, "end_line": 1}
    start_index = _line_index_at_char(spans, start_char)
    end_index = _line_index_at_char(spans, max(start_char, end_char - 1))
    return {"start_line": start_index + 1, "end_line": end_index + 1}


def _snapshot(events: Iterable[Mapping[str, object]], high_water_cursor: int | None) -> tuple[list[Mapping[str, object]], str, bool, str | None]:
    scanned, scanned_bytes = [], 0
    partial, reason = False, None
    all_events = list(events)
    for event in all_events:
        if len(scanned) >= MAX_QUERY_SCAN_EVENTS:
            partial, reason = True, "event_scan_limit"
            break
        byte_count = _event_byte_count(event)
        if scanned and scanned_bytes + byte_count > MAX_QUERY_SCAN_BYTES:
            partial, reason = True, "byte_scan_limit"
            break
        scanned.append(event)
        scanned_bytes += byte_count
    if len(scanned) < len(all_events):
        partial = True
        reason = reason or "event_scan_limit"
    last_scanned = _event_sequence(scanned[-1]) if scanned else 0
    if high_water_cursor is not None and high_water_cursor > last_scanned:
        partial = True
        reason = reason or "event_scan_limit"
    return scanned, str(high_water_cursor if high_water_cursor is not None else last_scanned), partial, reason


def _snapshot_response(scanned: list[Mapping[str, object]], high_water_cursor: str) -> dict[str, object]:
    return {
        "high_water_cursor": high_water_cursor,
        "scanned_events": len(scanned),
        "scanned_bytes": sum(_event_byte_count(event) for event in scanned),
    }


def _stream_text(scanned: list[Mapping[str, object]]) -> str:
    return "".join(_event_text(event) for event in scanned)


def _range_text_by_byte(value: str, start_byte: int, end_byte: int) -> tuple[str, int, int]:
    if end_byte <= start_byte:
        return "", start_byte, start_byte
    size, parts, actual_start, actual_end = 0, [], None, start_byte
    for character in value:
        character_size = len(character.encode())
        character_start, character_end = size, size + character_size
        size = character_end
        if character_end <= start_byte:
            continue
        if character_start >= end_byte:
            break
        if character_start >= start_byte and character_end <= end_byte:
            if actual_start is None:
                actual_start = character_start
            actual_end = character_end
            parts.append(character)
    if actual_start is None:
        return "", min(start_byte, size), min(start_byte, size)
    return "".join(parts), actual_start, actual_end


def query_retained_output(events: Iterable[Mapping[str, object]], *, query: str,
                          case_sensitive: bool = False, context_lines: int = 0,
                          limit_matches: int = 20,
                          after_byte: int = 0,
                          high_water_cursor: int | None = None) -> dict[str, object]:
    scanned, high_water, partial, partial_reason = _snapshot(events, high_water_cursor)
    text = _stream_text(scanned)
    haystack = text if case_sensitive else text.lower()
    needle = query if case_sensitive else query.lower()
    spans = _line_spans(text)
    matches, search_from, content_bytes = [], _char_index_for_byte(text, after_byte), 0
    response_truncated = False
    while len(matches) < limit_matches:
        found = haystack.find(needle, search_from)
        if found < 0:
            break
        match_end = found + len(needle)
        start_line_index = _line_index_at_char(spans, found)
        end_line_index = _line_index_at_char(spans, max(found, match_end - 1))
        before_start = max(0, start_line_index - context_lines)
        after_end = min(len(spans), end_line_index + context_lines + 1)
        before = "".join(text[start:end] for start, end in spans[before_start:start_line_index])
        match_text = text[found:match_end]
        after = "".join(text[start:end] for start, end in spans[end_line_index + 1:after_end])
        fields = {}
        for key, value in (("before", before), ("text", match_text), ("after", after)):
            remaining = max(0, MAX_RESPONSE_CONTENT_BYTES - content_bytes)
            kept, truncated = _take_utf8_prefix(value, remaining)
            content_bytes += len(kept.encode())
            fields[key] = kept
            response_truncated = response_truncated or truncated
        matches.append({
            "range": {
                "start_byte": _byte_offset_for_char(text, found),
                "end_byte": _byte_offset_for_char(text, match_end),
            },
            "line_range": _line_range_for_chars(text, found, match_end),
            "text": fields["text"],
            "context": {"before": fields["before"], "after": fields["after"]},
            "shortened": response_truncated,
        })
        search_from = match_end if match_end > found else found + 1
    more_match = haystack.find(needle, search_from)
    return {
        "snapshot": _snapshot_response(scanned, high_water),
        "query": query,
        "case_sensitive": case_sensitive,
        "context_lines": context_lines,
        "searched_from_byte": after_byte,
        "matches": matches,
        "match_count": len(matches),
        "limit_reached": more_match >= 0,
        "next_after_byte": _byte_offset_for_char(text, more_match) if more_match >= 0 else None,
        "partial": partial,
        "partial_reason": partial_reason,
        "content_truncated": response_truncated,
        "content_limit_bytes": MAX_RESPONSE_CONTENT_BYTES,
    }


def tail_retained_output(events: Iterable[Mapping[str, object]], *, lines: int,
                         high_water_cursor: int | None = None) -> dict[str, object]:
    scanned, high_water, partial, partial_reason = _snapshot(events, high_water_cursor)
    text = _stream_text(scanned)
    spans = _line_spans(text)
    selected = spans[-lines:] if spans else []
    start_char = selected[0][0] if selected else len(text)
    end_char = selected[-1][1] if selected else len(text)
    start_byte = _byte_offset_for_char(text, start_char)
    end_byte = _byte_offset_for_char(text, end_char)
    selected_text = text[start_char:end_char]
    kept, removed_bytes, shortened = _take_utf8_suffix(selected_text, MAX_RESPONSE_CONTENT_BYTES)
    return {
        "snapshot": _snapshot_response(scanned, high_water),
        "lines": lines,
        "text": kept,
        "range": {"start_byte": start_byte + removed_bytes, "end_byte": end_byte},
        "line_range": {
            "start_line": (len(spans) - len(selected) + 1) if selected else 1,
            "end_line": len(spans) if selected else 1,
        },
        "partial": partial,
        "partial_reason": partial_reason,
        "content_truncated": shortened,
        "content_limit_bytes": MAX_RESPONSE_CONTENT_BYTES,
    }


def range_retained_output(events: Iterable[Mapping[str, object]], *, start_byte: int,
                          end_byte: int, high_water_cursor: int | None = None) -> dict[str, object]:
    scanned, high_water, partial, partial_reason = _snapshot(events, high_water_cursor)
    text = _stream_text(scanned)
    selected_text, actual_start, actual_end = _range_text_by_byte(text, start_byte, end_byte)
    kept, shortened = _take_utf8_prefix(selected_text, MAX_RESPONSE_CONTENT_BYTES)
    kept_end = actual_start + len(kept.encode())
    return {
        "snapshot": _snapshot_response(scanned, high_water),
        "text": kept,
        "range": {"start_byte": actual_start, "end_byte": kept_end if shortened else actual_end},
        "requested_range": {"start_byte": start_byte, "end_byte": end_byte},
        "line_range": _line_range_for_chars(
            text, _char_index_for_byte(text, actual_start), _char_index_for_byte(text, actual_end),
        ),
        "partial": partial,
        "partial_reason": partial_reason,
        "content_truncated": shortened,
        "content_limit_bytes": MAX_RESPONSE_CONTENT_BYTES,
    }
