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
    drive_diagnostic,
    parse_arguments,
    render_result,
    summarize_usage,
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
        assert timeout_seconds <= wait_ms / 1000
        self.event_timeouts.append(timeout_seconds)
        return {
            "events": [{"cursor": "1", "text": "event", "byte_count": 5, "created_at": "now"}],
            "next_cursor": "1",
            "terminal": True,
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
    assert result.closed is True
    assert control_plane.closed is True
    assert len(control_plane.submitted) == 1
    script, timeout_ms = control_plane.submitted[0]
    assert "Test-NetConnection" in script
    assert "rmm-test-fileserver" in script
    assert timeout_ms == 5000
    assert control_plane.pages == [("exec-1", "stdout", "0", 4096)]
    assert [step.tool for step in result.steps] == ["run_diagnostic:tcp_port", "get_output_page"]
    assert result.steps[0].execution_ms == 42.0
    tool_output_message = model.inputs[1][-1]
    assert tool_output_message["type"] == "function_call_output"
    assert "api_round_trip_ms" not in tool_output_message["output"]
    assert "model_ms_before_step" not in tool_output_message["output"]


def test_build_script_only_uses_fixed_templates_and_quotes_target():
    script = build_script("dns_resolution", "file-server'01", 445)

    assert "Resolve-DnsName" in script
    assert "$TargetHost = 'file-server''01'" in script
    assert "Remove-Item" not in script


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

    tools.executions["exec-1"] = {"page_cursors": {"stdout": "0", "stderr": "0"}}
    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="exec-1", stream="stdout", after="999")

    page, _ = tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")
    assert page["next_cursor"] == "2"
    assert tools.executions["exec-1"]["page_cursors"]["stdout"] == "2"
    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")


def test_page_larger_than_model_exposure_limit_is_rejected_to_avoid_skipped_middle_output():
    control_plane = FakeControlPlane(page_text="x" * 7000)
    tools = DiagnosticTools(control_plane, "session-1", deadline_monotonic=time.perf_counter() + 60)
    tools.executions["exec-1"] = {"page_cursors": {"stdout": "0", "stderr": "0"}}

    with pytest.raises(DriverError):
        tools.get_output_page(execution_id="exec-1", stream="stdout", after="0")

    assert tools.executions["exec-1"]["page_cursors"]["stdout"] == "0"


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
    assert 100 <= control_plane.submitted[0][1] <= 1000
    assert all(timeout <= 1.1 for timeout in model.timeouts)
    api_timeouts = control_plane.open_timeouts + control_plane.submit_timeouts + control_plane.get_timeouts
    assert all(timeout <= 1.1 for timeout in api_timeouts)


def test_session_close_retries_within_cleanup_allowance_and_reports_failure():
    model = FakeModel(outputs=[
        [{"type": "message", "content": [{"type": "output_text", "text": "No commands needed."}]}],
    ])
    control_plane = FakeControlPlane(close_failures=2)

    result = drive_diagnostic(
        problem="Diagnose file server access",
        device_id="device-1",
        model_client=model,
        control_plane=control_plane,
        max_steps=1,
        max_seconds=60,
        cleanup_seconds=2,
    )

    assert result.closed is True
    assert control_plane.close_attempts == 3
    assert control_plane.close_timeouts[0] <= 2


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
    assert client.output_page("exec-1", "stdout", "0", 4096, timeout_seconds=1)["text"] == "page"
    assert len(requests) == 3


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
