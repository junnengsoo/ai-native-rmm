import asyncio
import uuid

import pytest
from fastapi import HTTPException

from control_plane import app as app_module
from control_plane import database as database_module
from control_plane.output_queries import query_retained_output, range_retained_output, tail_retained_output


def install_output_fakes(monkeypatch, row, workspace_id, calls):
    def fake_auth(authorization, required_role=None):
        assert authorization == "Bearer operator-secret"
        assert required_role == "operator"
        return {"workspace_id": workspace_id, "id": uuid.uuid4(), "role": "operator"}

    def fake_get_execution(requested_workspace_id, execution_id):
        if requested_workspace_id != row["workspace_id"] or execution_id != row["id"]:
            return None
        return row

    monkeypatch.setattr(app_module, "authenticated_caller", fake_auth)
    monkeypatch.setattr(app_module, "get_workspace_execution", fake_get_execution)
    monkeypatch.setattr(app_module, "send_execution_command", lambda *_: calls.append("dispatch"))


def fake_output_events():
    return [
        {"sequence": 1, "text": "alpha\nERR", "byte_count": len("alpha\nERR".encode())},
        {"sequence": 2, "text": "OR caf", "byte_count": len("OR caf".encode())},
        {"sequence": 3, "text": "é\nomega\n", "byte_count": len("é\nomega\n".encode())},
    ]


def fake_stderr_events():
    return [
        {"sequence": 1, "text": "warn one\n", "byte_count": len("warn one\n".encode())},
        {"sequence": 2, "text": "fatal two\n", "byte_count": len("fatal two\n".encode())},
        {"sequence": 3, "text": "done three\n", "byte_count": len("done three\n".encode())},
    ]


def install_query_fakes(monkeypatch):
    def choose(execution_id, stream):
        assert execution_id
        return fake_stderr_events() if stream == "stderr" else fake_output_events()

    def search(execution_id, stream, query, *, case_sensitive, context_lines, limit_matches, after_byte):
        return query_retained_output(
            choose(execution_id, stream), query=query, case_sensitive=case_sensitive,
            context_lines=context_lines, limit_matches=limit_matches,
            after_byte=after_byte,
        )

    def tail(execution_id, stream, lines):
        return tail_retained_output(choose(execution_id, stream), lines=lines)

    def expand(execution_id, stream, start_byte, end_byte):
        return range_retained_output(
            choose(execution_id, stream), start_byte=start_byte, end_byte=end_byte,
        )

    monkeypatch.setattr(app_module, "search_execution_output", search)
    monkeypatch.setattr(app_module, "tail_execution_output", tail)
    monkeypatch.setattr(app_module, "range_execution_output", expand)


def execution_row(execution_id, workspace_id):
    return {
        "id": execution_id,
        "workspace_id": workspace_id,
        "session_id": uuid.uuid4(),
        "caller_id": uuid.uuid4(),
        "status": "completed",
        "capture_truncated": False,
    }


async def _search_tail_and_range_are_read_only_and_workspace_scoped(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    dispatch_calls = []
    row = execution_row(execution_id, workspace_id)
    install_output_fakes(monkeypatch, row, workspace_id, dispatch_calls)
    install_query_fakes(monkeypatch)

    search = await app_module.search_execution_output_endpoint(
        execution_id, "stdout", authorization="Bearer operator-secret",
        query="error café", context_lines=1, case_sensitive=False,
        limit_matches=10, after_byte=0,
    )

    assert search["query"] == "error café"
    assert search["case_sensitive"] is False
    assert search["snapshot"]["high_water_cursor"] == "3"
    assert search["partial"] is False
    assert search["searched_from_byte"] == 0
    assert search["next_after_byte"] is None
    assert len(search["matches"]) == 1
    match = search["matches"][0]
    assert match["text"] == "ERROR café"
    assert match["context"]["before"] == "alpha\n"
    assert match["context"]["after"] == "omega\n"
    assert match["range"]["start_byte"] == len("alpha\n".encode())
    assert match["range"]["end_byte"] == len("alpha\nERROR café".encode())

    expanded = await app_module.range_execution_output_endpoint(
        execution_id, "stdout", authorization="Bearer operator-secret",
        start_byte=match["range"]["start_byte"], end_byte=match["range"]["end_byte"],
    )
    assert expanded["text"] == "ERROR café"
    assert expanded["range"] == match["range"]
    assert expanded["unicode"]["unit"] == "utf-8 byte offsets"

    tail = await app_module.tail_execution_output_endpoint(
        execution_id, "stderr", authorization="Bearer operator-secret", lines=2,
    )
    assert tail["text"] == "fatal two\ndone three\n"
    assert tail["line_range"] == {"start_line": 2, "end_line": 3}

    other_row = {**row, "workspace_id": uuid.uuid4()}
    install_output_fakes(monkeypatch, other_row, workspace_id, dispatch_calls)
    with pytest.raises(HTTPException) as denied:
        await app_module.search_execution_output_endpoint(
            execution_id, "stdout", authorization="Bearer operator-secret", query="error", after_byte=0,
        )
    assert denied.value.status_code == 404
    assert dispatch_calls == []


def test_search_tail_and_range_are_read_only_and_workspace_scoped(monkeypatch):
    asyncio.run(_search_tail_and_range_are_read_only_and_workspace_scoped(monkeypatch))


async def _output_investigation_rejects_invalid_stream_and_empty_query(monkeypatch):
    workspace_id = uuid.uuid4()
    execution_id = uuid.uuid4()
    row = execution_row(execution_id, workspace_id)
    install_output_fakes(monkeypatch, row, workspace_id, [])
    install_query_fakes(monkeypatch)

    with pytest.raises(HTTPException) as bad_stream:
        await app_module.search_execution_output_endpoint(
            execution_id, "combined", authorization="Bearer operator-secret", query="x", after_byte=0,
        )
    assert bad_stream.value.status_code == 404

    with pytest.raises(HTTPException) as bad_query:
        await app_module.search_execution_output_endpoint(
            execution_id, "stdout", authorization="Bearer operator-secret", query="", after_byte=0,
        )
    assert bad_query.value.status_code == 422

    with pytest.raises(HTTPException) as bad_range:
        await app_module.range_execution_output_endpoint(
            execution_id, "stdout", authorization="Bearer operator-secret",
            start_byte=10, end_byte=5,
        )
    assert bad_range.value.status_code == 422


def test_output_investigation_rejects_invalid_stream_and_empty_query(monkeypatch):
    asyncio.run(_output_investigation_rejects_invalid_stream_and_empty_query(monkeypatch))


def test_literal_search_continuation_and_partial_scan_are_disclosed():
    events = [
        {"sequence": 1, "text": "hit one\n", "byte_count": len("hit one\n".encode())},
        {"sequence": 2, "text": "hit two\n", "byte_count": len("hit two\n".encode())},
    ]

    first = query_retained_output(events, query="hit", limit_matches=1)
    second = query_retained_output(events, query="hit", limit_matches=1, after_byte=first["next_after_byte"])

    assert first["matches"][0]["text"] == "hit"
    assert first["limit_reached"] is True
    assert first["next_after_byte"] == len("hit one\n".encode())
    assert second["matches"][0]["range"]["start_byte"] == len("hit one\n".encode())
    assert second["limit_reached"] is False

    many_events = [
        {"sequence": index, "text": "line\n", "byte_count": len("line\n".encode())}
        for index in range(1, 4098)
    ]
    partial = query_retained_output(many_events, query="needle", high_water_cursor=4097)

    assert partial["matches"] == []
    assert partial["partial"] is True
    assert partial["partial_reason"] == "event_scan_limit"
    assert partial["snapshot"]["high_water_cursor"] == "4097"
    assert partial["snapshot"]["scanned_events"] == 4096


def test_database_search_uses_high_water_snapshot_for_growing_output(monkeypatch):
    execution_id = uuid.uuid4()
    calls = []

    def fake_high_water(requested_execution, stream):
        assert requested_execution == execution_id
        assert stream == "stdout"
        return 1

    def fake_scan_events(requested_execution, stream, high_water):
        calls.append(high_water)
        assert requested_execution == execution_id
        assert stream == "stdout"
        return [
            {"sequence": 1, "text": "before snapshot\n", "byte_count": len("before snapshot\n".encode())},
            # This simulates a racey storage collaborator trying to hand back a
            # later append. The query helper still discloses the high-water
            # snapshot so callers know the read boundary.
            {"sequence": 2, "text": "after snapshot needle\n", "byte_count": len("after snapshot needle\n".encode())},
        ][:high_water]

    monkeypatch.setattr(database_module, "get_execution_output_high_water", fake_high_water)
    monkeypatch.setattr(database_module, "get_execution_output_scan_events", fake_scan_events)

    result = database_module.search_execution_output(
        execution_id, "stdout", "needle", case_sensitive=False,
        context_lines=0, limit_matches=10, after_byte=0,
    )

    assert calls == [1]
    assert result["matches"] == []
    assert result["snapshot"]["high_water_cursor"] == "1"


def test_empty_stream_search_tail_and_range_are_bounded_empty_results():
    search = query_retained_output([], query="anything")
    tail = tail_retained_output([], lines=10)
    expanded = range_retained_output([], start_byte=0, end_byte=10)

    assert search["matches"] == []
    assert search["partial"] is False
    assert tail["text"] == ""
    assert tail["range"] == {"start_byte": 0, "end_byte": 0}
    assert expanded["text"] == ""
    assert expanded["range"] == {"start_byte": 0, "end_byte": 0}
