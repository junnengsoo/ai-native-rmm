import json
import time

import httpx
import pytest

from control_plane.openai_driver import (
    ControlPlaneClient,
    DiagnosticTools,
    DriverError,
    ModelReply,
    OpenAIResponsesClient,
    build_script,
    DIAGNOSTIC_OPERATIONS,
    drive_diagnostic,
    parse_arguments,
    render_result,
    sanitize_progress_text,
    summarize_usage,
    validate_port,
    validate_timeout_ms,
)


def tool_call(call_id, name, arguments):
    return {
        "type": "function_call",
        "call_id": call_id,
        "name": name,
        "arguments": json.dumps(arguments) if not isinstance(arguments, str) else arguments,
    }


class FakeModel:
    def __init__(self, outputs=None):
        self.calls = 0
        self.inputs = []
        self.timeouts = []
        self.outputs = outputs or [
            [tool_call("call-1", "run_diagnostic", {
                "operation": "tcp_port",
                "target_host": "rmm-test-fileserver",
                "port": 445,
                "timeout_ms": 5000,
                "reason": "Check SMB TCP reachability to the requested file server.",
            })],
            [tool_call("call-2", "get_output_page", {
                "execution_id": "exec-1",
                "stream": "stdout",
                "after": "0",
            })],
            [{
                "type": "message",
                "content": [{"type": "output_text", "text": "Likely host override sends SMB to an unreachable test address."}],
            }],
        ]

    def create_response(self, input_items, *, timeout_seconds):
        self.calls += 1
        self.inputs.append(json.loads(json.dumps(input_items)))
        self.timeouts.append(timeout_seconds)
        output = self.outputs[min(self.calls - 1, len(self.outputs) - 1)]
        return ModelReply(
            output=output,
            text="Likely host override sends SMB to an unreachable test address." if output and output[0]["type"] == "message" else "",
            response_id="resp-" + str(self.calls),
            usage={"input_tokens": 10 * self.calls, "output_tokens": 4},
            latency_ms=100 + self.calls,
        )


class FakeControlPlane:
    def __init__(self, *, close_failures=0, page_text="TcpTestSucceeded: False\nResolvedAddresses: 203.0.113.10\n"):
        self.closed = False
        self.close_failures = close_failures
        self.close_attempts = 0
        self.open_timeouts = []
        self.close_timeouts = []
        self.submit_timeouts = []
        self.get_timeouts = []
        self.event_timeouts = []
        self.page_timeouts = []
        self.submitted = []
        self.pages = []
        self.page_text = page_text

    def open_session(self, device_id, *, timeout_seconds):
        assert device_id == "device-1"
        self.open_timeouts.append(timeout_seconds)
        return {"session_id": "session-1", "status": "active"}

    def close_session(self, session_id, *, timeout_seconds):
        assert session_id == "session-1"
        self.close_attempts += 1
        self.close_timeouts.append(timeout_seconds)
        if self.close_attempts <= self.close_failures:
            return False, {"status": "cleanup_unknown"}
        self.closed = True
        return True, {"status": "closed"}

    def submit_execution(self, session_id, script, timeout_ms, idempotency_key, *, timeout_seconds):
        assert session_id == "session-1"
        assert idempotency_key.startswith("openai-driver-")
        assert "Remove-Item" not in script
        assert "Test-NetConnection" in script
        self.submit_timeouts.append(timeout_seconds)
        self.submitted.append((script, timeout_ms))
        return {"execution_id": "exec-1", "status": "queued", "script_sha256": "abc"}

    def output_events(self, execution_id, stream, *, after, wait_ms, timeout_seconds, limit=8):
        assert execution_id == "exec-1"
        assert stream in {"stdout", "stderr"}
        assert 1 <= wait_ms <= 2000
        assert timeout_seconds > wait_ms / 1000
        self.event_timeouts.append(timeout_seconds)
        if after != "0":
            return {
                "events": [],
                "next_cursor": after,
                "terminal": True,
                "more_available": False,
                "timed_out": False,
            }
        return {
            "events": [{"cursor": "1", "text": "event", "byte_count": 5, "created_at": "now"}],
            "next_cursor": "1",
            "terminal": True,
            "more_available": False,
        }

    def get_execution(self, execution_id, *, timeout_seconds):
        assert execution_id == "exec-1"
        self.get_timeouts.append(timeout_seconds)
        return {
            "status": "completed",
            "invocation_outcome": "completed_normally",
            "exit_code": 0,
            "had_errors": False,
            "duration_ms": 42.0,
            "capture": {"loss_detected": False, "reason": None},
            "output_preview": {
                "stdout": {"text": "TcpTestSucceeded: False\n", "shortened": True},
                "stderr": {"text": "", "shortened": False},
            },
        }

    def output_page(self, execution_id, stream, after, limit_bytes, *, timeout_seconds):
        self.pages.append((execution_id, stream, after, limit_bytes))
        self.page_timeouts.append(timeout_seconds)
        return {
            "text": self.page_text,
            "next_cursor": "2",
            "more_available": False,
            "capture_lost": False,
            "gap": {"detected": False, "reason": None},
        }


class TimeoutOnceControlPlane(FakeControlPlane):
    def __init__(self):
        super().__init__()
        self.timed_out_once = False

    def output_events(self, execution_id, stream, *, after, wait_ms, timeout_seconds, limit=8):
        if not self.timed_out_once:
            self.timed_out_once = True
            raise httpx.ReadTimeout("no change")
        return super().output_events(
            execution_id,
            stream,
            after=after,
            wait_ms=wait_ms,
            timeout_seconds=timeout_seconds,
            limit=limit,
        )


class ManyEventsControlPlane(FakeControlPlane):
    def output_events(self, execution_id, stream, *, after, wait_ms, timeout_seconds, limit=8):
        if stream == "stderr":
            return {"events": [], "next_cursor": after, "terminal": True, "more_available": False}
        if after == "0":
            return {
                "events": [{"cursor": str(index), "text": f"event-{index}", "byte_count": 7, "created_at": "now"} for index in range(1, 9)],
                "next_cursor": "8",
                "terminal": True,
                "more_available": True,
            }
        if after == "8":
            return {
                "events": [{"cursor": str(index), "text": f"event-{index}", "byte_count": 8, "created_at": "now"} for index in range(9, 11)],
                "next_cursor": "10",
                "terminal": True,
                "more_available": False,
            }
        return {"events": [], "next_cursor": after, "terminal": True, "more_available": False}


def test_driver_runs_constrained_diagnostics_closes_session_and_keeps_timings_out_of_tool_context():
    model = FakeModel()
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Why can Windows not reach \\\\rmm-test-fileserver\\diagnostics?",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=3,
        max_seconds=60,
    )

    assert result.final_report.startswith("Likely host override")
    assert result.completed is True
    assert result.closed is True
    assert control_plane.closed is True
    assert len(control_plane.submitted) == 1
    script, timeout_ms = control_plane.submitted[0]
    assert "Test-NetConnection" in script
    assert "rmm-test-fileserver" in script
    assert timeout_ms == 5000
    assert control_plane.pages == [("exec-1", "stdout", "0", 8192)]
    assert [step.tool for step in result.steps] == ["run_diagnostic:tcp_port", "get_output_page"]
    assert result.steps[0].execution_ms == 42.0
    tool_output_message = model.inputs[1][-1]
    assert tool_output_message["type"] == "function_call_output"
    assert "api_round_trip_ms" not in tool_output_message["output"]
    assert "model_ms_before_step" not in tool_output_message["output"]


def test_transient_long_poll_timeout_reports_progress_and_continues_within_budget():
    progress = []
    control_plane = TimeoutOnceControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=FakeModel(),
        control_plane=control_plane,
        max_steps=1,
        max_seconds=60,
        progress_callback=progress.append,
    )

    assert result.closed is True
    assert control_plane.timed_out_once is True
    assert progress[0]["type"] == "long_poll_timeout"


def test_long_poll_drains_more_than_eight_events_after_terminal():
    progress = []
    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=FakeModel(),
        control_plane=ManyEventsControlPlane(),
        max_steps=1,
        max_seconds=60,
        progress_callback=progress.append,
    )

    assert result.closed is True
    output_events = [event for event in progress if event["type"] == "output" and event["stream"] == "stdout"]
    assert [event["cursor"] for event in output_events] == [str(index) for index in range(1, 11)]


def test_build_script_only_uses_fixed_templates_and_quotes_target():
    script = build_script("dns_resolution", "file-server'01", 445)

    assert "Resolve-DnsName" in script
    assert "$TargetHost = 'file-server''01'" in script
    assert "Remove-Item" not in script


def test_fixed_templates_include_expected_read_only_diagnostics_and_valid_gateway_pipeline_shape():
    assert {"network_config", "default_gateway_ping", "dns_resolution", "target_ping", "tcp_port"} == set(DIAGNOSTIC_OPERATIONS)
    gateway_script = build_script("default_gateway_ping", "unused", 445)
    assert "@(foreach ($gateway in $gateways)" in gateway_script
    assert "}) | ConvertTo-Json" in gateway_script
    for operation in DIAGNOSTIC_OPERATIONS:
        script = build_script(operation, "rmm-test-fileserver", 445)
        assert "Remove-Item" not in script
        assert "Set-" not in script
        assert "New-" not in script


def test_arbitrary_raw_powershell_tool_call_is_rejected_without_execution():
    model = FakeModel(outputs=[
        [tool_call("call-1", "run_powershell", {
            "script": "Remove-Item C:\\important -Recurse",
            "timeout_ms": 1000,
            "reason": "mutate",
        })],
        [{"type": "message", "content": [{"type": "output_text", "text": "Rejected unsafe tool."}]}],
    ])
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
    )

    assert control_plane.submitted == []
    assert result.steps[0].status == "rejected"
    assert result.steps[0].step == 1
    assert json.loads(model.inputs[1][-1]["output"])["error"]["code"] == "invalid_tool_request"
    assert result.closed is True


def test_mutating_target_argument_is_rejected_without_execution():
    model = FakeModel(outputs=[
        [tool_call("call-1", "run_diagnostic", {
            "operation": "tcp_port",
            "target_host": "server; Remove-Item C:\\important",
            "port": 445,
            "timeout_ms": 1000,
            "reason": "try injection",
        })],
        [{"type": "message", "content": [{"type": "output_text", "text": "Rejected invalid host."}]}],
    ])
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
    )

    assert control_plane.submitted == []
    assert result.steps[0].status == "rejected"


def test_invalid_json_tool_arguments_return_controlled_error():
    model = FakeModel(outputs=[
        [tool_call("call-1", "run_diagnostic", "{not-json")],
        [{"type": "message", "content": [{"type": "output_text", "text": "Recovered."}]}],
    ])
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
    )

    assert result.steps[0].status == "rejected"
    assert json.loads(model.inputs[1][-1]["output"])["error"]["code"] == "invalid_tool_request"


def test_output_page_is_restricted_to_known_execution_and_next_cursor():
    control_plane = FakeControlPlane()
    tools = DiagnosticTools(control_plane, "session-1", deadline_monotonic=time.perf_counter() + 60)

    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="other-exec", stream="stdout", after="0")

    tools.executions["exec-1"] = {
        "page_cursors": {"stdout": "0", "stderr": "0"},
        "page_allowed": {"stdout": True, "stderr": False},
    }
    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="exec-1", stream="stdout", after="999")

    page, _ = tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")
    assert page["next_cursor"] == "2"
    assert tools.executions["exec-1"]["page_cursors"]["stdout"] == "2"
    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")


def test_output_page_requires_preview_or_prior_page_more_available():
    control_plane = FakeControlPlane()
    tools = DiagnosticTools(control_plane, "session-1", deadline_monotonic=time.perf_counter() + 60)
    tools.executions["exec-1"] = {
        "page_cursors": {"stdout": "0", "stderr": "0"},
        "page_allowed": {"stdout": False, "stderr": False},
    }

    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")


def test_valid_api_minimum_sized_ascii_page_is_fully_exposed_and_advances_cursor():
    control_plane = FakeControlPlane(page_text="x" * 7000)
    tools = DiagnosticTools(control_plane, "session-1", deadline_monotonic=time.perf_counter() + 60)
    tools.executions["exec-1"] = {
        "page_cursors": {"stdout": "0", "stderr": "0"},
        "page_allowed": {"stdout": True, "stderr": False},
    }

    page, _ = tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")

    assert page["page"]["shortened"] is False
    assert len(page["page"]["text"]) == 7000
    assert tools.executions["exec-1"]["page_cursors"]["stdout"] == "2"


def test_driver_closes_session_when_step_budget_is_exhausted():
    model = FakeModel()
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=1,
        max_seconds=60,
    )

    assert result.final_report == "Stopped because the configured diagnostic step budget was exhausted."
    assert result.closed is True
    assert result.completed is False
    assert len(result.steps) == 1


def test_driver_caps_execution_timeout_and_api_waits_to_remaining_time_budget():
    model = FakeModel()
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=1,
        max_seconds=1,
    )

    assert result.closed is True
    assert len(control_plane.submitted) == 1
    assert result.completed is False
    assert 100 <= control_plane.submitted[0][1] <= 1000
    assert all(timeout <= 1.1 for timeout in model.timeouts)
    api_timeouts = control_plane.open_timeouts + control_plane.submit_timeouts + control_plane.get_timeouts
    assert all(timeout <= 1.1 for timeout in api_timeouts)


def test_session_close_uses_one_bounded_attempt_for_non_idempotent_api():
    model = FakeModel(outputs=[
        [{"type": "message", "content": [{"type": "output_text", "text": "No commands needed."}]}],
    ])
    control_plane = FakeControlPlane(close_failures=1)

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=1,
        max_seconds=60,
        cleanup_seconds=2,
    )

    assert result.closed is False
    assert control_plane.close_attempts == 1
    assert control_plane.close_timeouts[0] <= 2
    assert "session closure was not confirmed" in result.final_report


def test_unconfirmed_session_close_is_surfaced_as_command_failure():
    model = FakeModel(outputs=[
        [{"type": "message", "content": [{"type": "output_text", "text": "No commands needed."}]}],
    ])
    control_plane = FakeControlPlane(close_failures=99)

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=1,
        max_seconds=60,
        cleanup_seconds=1,
    )

    assert result.closed is False
    assert "Command failure: session closure was not confirmed" in result.final_report
    assert result.close_error


def test_cleanup_seconds_must_be_positive_and_bounded():
    model = FakeModel(outputs=[
        [{"type": "message", "content": [{"type": "output_text", "text": "No commands needed."}]}],
    ])
    control_plane = FakeControlPlane()

    with pytest.raises(ValueError):
        drive_diagnostic(
            problem="Diagnose file server access",
            device_id="device-1",
            model_client=model,
            control_plane=control_plane,
            cleanup_seconds=0,
        )
    with pytest.raises(ValueError):
        drive_diagnostic(
            problem="Diagnose file server access",
            device_id="device-1",
            model_client=model,
            control_plane=control_plane,
            cleanup_seconds=61,
        )


def test_bool_port_and_timeout_are_rejected():
    with pytest.raises(DriverError):
        validate_port(True)
    with pytest.raises(DriverError):
        validate_timeout_ms(True)


def test_late_model_final_reply_becomes_budget_exhaustion():
    class SlowModel(FakeModel):
        def create_response(self, input_items, *, timeout_seconds):
            time.sleep(1.1)
            return ModelReply(
                output=[{"type": "message", "content": [{"type": "output_text", "text": "too late"}]}],
                text="too late",
                response_id="late",
                usage=None,
                latency_ms=1100,
            )

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=SlowModel(),
        control_plane=FakeControlPlane(),
        max_steps=1,
        max_seconds=1,
    )

    assert result.final_report == "Stopped because the configured diagnostic time budget was exhausted."


def test_progress_callback_receives_bounded_output_outside_model_context():
    progress = []
    model = FakeModel()
    control_plane = FakeControlPlane()

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=1,
        max_seconds=60,
        progress_callback=progress.append,
    )

    assert result.closed is True
    assert progress[0]["type"] == "output"
    assert progress[0]["text"]["text"] == "event"
    assert "event" not in model.inputs[1][-1]["output"]


def test_no_change_progress_is_emitted_for_quiet_polls():
    progress = []
    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=FakeModel(),
        control_plane=FakeControlPlane(),
        max_steps=1,
        max_seconds=60,
        progress_callback=progress.append,
    )

    assert result.closed is True
    assert any(event["type"] == "no_change" for event in progress)


def test_progress_sanitizes_terminal_control_characters():
    assert sanitize_progress_text("ok\n\tesc:\x1b[31m\rbad\x85") == "ok\n\tesc:\\x1b[31m\\x0dbad\\x85"


def test_model_failure_raises_structured_error_with_close_failure():
    class FailingModel:
        def create_response(self, input_items, *, timeout_seconds):
            raise RuntimeError("model exploded")

    with pytest.raises(DriverError) as caught:
        drive_diagnostic(
            problem="Diagnose file server access",
            device_id="device-1",
            model_client=FailingModel(),
            control_plane=FakeControlPlane(close_failures=1),
            max_steps=1,
            max_seconds=60,
            cleanup_seconds=1,
        )

    assert caught.value.code == "driver_failed"
    assert caught.value.original_error == "RuntimeError"
    assert caught.value.close_error


def test_parse_arguments_raises_controlled_error_for_non_object():
    with pytest.raises(DriverError):
        parse_arguments({"arguments": "[]"})


def test_control_plane_client_authenticates_public_api_without_openai_key():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer operator-secret"
        assert "openai-secret" not in str(request.headers)
        if request.url.path.endswith("/executions"):
            assert request.headers["Idempotency-Key"] == "idem-1"
            return httpx.Response(202, json={"execution_id": "exec-1", "status": "queued", "script_sha256": "abc"})
        if request.url.path == "/executions/exec-1/output/stdout/events":
            return httpx.Response(200, json={"events": [], "next_cursor": "0", "terminal": True})
        if request.url.path == "/executions/exec-1/output/stdout":
            return httpx.Response(200, json={
                "text": "page",
                "next_cursor": "1",
                "more_available": False,
                "capture_lost": False,
                "gap": {"detected": False, "reason": None},
            })
        raise AssertionError(request.url.path)

    client = ControlPlaneClient("http://control-plane.test", "operator-secret")
    client.client = httpx.Client(
        base_url="http://control-plane.test",
        headers={"Authorization": "Bearer operator-secret"},
        transport=httpx.MockTransport(handler),
    )

    assert client.submit_execution("session-1", "Get-Date", 1000, "idem-1", timeout_seconds=1)["execution_id"] == "exec-1"
    assert client.output_events("exec-1", "stdout", after="0", wait_ms=50, timeout_seconds=1)["terminal"] is True
    assert client.output_page("exec-1", "stdout", "0", 8192, timeout_seconds=1)["text"] == "page"
    assert len(requests) == 3


def test_first_online_device_paginates_until_online_device():
    requests = []

    def handler(request):
        requests.append(request)
        if len(requests) == 1:
            assert "after" not in request.url.params
            return httpx.Response(200, json={
                "devices": [{"id": "stale-1", "reachability": "stale"}],
                "next_cursor": "cursor-1",
            })
        assert request.url.params["after"] == "cursor-1"
        return httpx.Response(200, json={
            "devices": [{"id": "online-1", "reachability": "online"}],
            "next_cursor": None,
        })

    original_get = httpx.get
    try:
        httpx.get = httpx.Client(
            base_url="http://control-plane.test",
            transport=httpx.MockTransport(handler),
        ).get
        device = ControlPlaneClient.first_online_device(
            "http://control-plane.test",
            "admin-secret",
            deadline_monotonic=time.perf_counter() + 60,
        )
    finally:
        httpx.get = original_get

    assert device == "online-1"
    assert len(requests) == 2


def test_openai_responses_client_uses_bounded_model_request_and_reports_usage():
    seen_timeout = []

    def handler(request):
        body = json.loads(request.content)
        seen_timeout.append(request.extensions["timeout"]["connect"])
        assert request.headers["Authorization"] == "Bearer openai-secret"
        assert body["model"] == "gpt-5-nano"
        assert body["store"] is False
        assert body["max_output_tokens"] == 123
        assert body["tools"][0]["name"] == "run_diagnostic"
        return httpx.Response(200, json={
            "id": "resp-1",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "done"}]}],
            "usage": {"input_tokens": 5, "output_tokens": 7},
        })

    client = OpenAIResponsesClient("openai-secret", max_output_tokens=123)
    client.client = httpx.Client(
        base_url="https://api.openai.com/v1",
        headers={"Authorization": "Bearer openai-secret"},
        transport=httpx.MockTransport(handler),
    )
    reply = client.create_response([{"role": "user", "content": "hello"}], timeout_seconds=2)

    assert reply.text == "done"
    assert seen_timeout == [2]
    assert summarize_usage([reply]) == {"input_tokens": 5, "output_tokens": 7}
    rendered = render_result(type("Result", (), {
        "final_report": "done",
        "steps": [],
        "model_calls": [reply],
        "model_latency_ms": reply.latency_ms,
        "closed": True,
        "close_error": None,
    })())
    assert "approximate_cost=$" in rendered


def test_openai_client_raises_for_failed_response_without_exposing_body():
    def handler(request):
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    client = OpenAIResponsesClient("openai-secret")
    client.client = httpx.Client(
        base_url="https://api.openai.com/v1",
        headers={"Authorization": "Bearer openai-secret"},
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(httpx.HTTPStatusError):
        client.create_response([{"role": "user", "content": "hello"}], timeout_seconds=1)
