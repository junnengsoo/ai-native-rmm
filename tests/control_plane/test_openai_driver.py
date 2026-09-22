import json

import httpx
import pytest

from control_plane.openai_driver import (
    ControlPlaneClient,
    ModelReply,
    OpenAIResponsesClient,
    drive_diagnostic,
    render_result,
    summarize_usage,
)


class FakeModel:
    def __init__(self):
        self.calls = 0
        self.inputs = []

    def create_response(self, input_items):
        self.calls += 1
        self.inputs.append(json.loads(json.dumps(input_items)))
        if self.calls == 1:
            return ModelReply(
                output=[{
                    "type": "function_call",
                    "call_id": "call-1",
                    "name": "run_powershell",
                    "arguments": json.dumps({
                        "script": "Test-NetConnection rmm-test-fileserver -Port 445",
                        "timeout_ms": 5000,
                        "reason": "Check SMB TCP reachability to the requested file server.",
                    }),
                }],
                text="",
                response_id="resp-1",
                usage={"input_tokens": 10, "output_tokens": 4},
                latency_ms=123,
            )
        if self.calls == 2:
            return ModelReply(
                output=[{
                    "type": "function_call",
                    "call_id": "call-2",
                    "name": "get_output_page",
                    "arguments": json.dumps({
                        "execution_id": "exec-1",
                        "stream": "stdout",
                        "after": "0",
                    }),
                }],
                text="",
                response_id="resp-2",
                usage={"input_tokens": 20, "output_tokens": 6},
                latency_ms=234,
            )
        return ModelReply(
            output=[{
                "type": "message",
                "content": [{"type": "output_text", "text": "Likely host override sends SMB to an unreachable test address."}],
            }],
            text="Likely host override sends SMB to an unreachable test address.",
            response_id="resp-3",
            usage={"input_tokens": 30, "output_tokens": 8},
            latency_ms=345,
        )


class FakeControlPlane:
    def __init__(self):
        self.closed = False
        self.submitted = []
        self.pages = []

    def open_session(self, device_id):
        assert device_id == "device-1"
        return {"session_id": "session-1", "status": "active"}

    def close_session(self, session_id):
        assert session_id == "session-1"
        self.closed = True
        return True, {"status": "closed"}

    def submit_execution(self, session_id, script, timeout_ms, idempotency_key):
        assert session_id == "session-1"
        assert idempotency_key.startswith("openai-driver-")
        self.submitted.append((script, timeout_ms))
        return {"execution_id": "exec-1", "status": "queued", "script_sha256": "abc"}

    def output_events(self, execution_id, stream, *, after, wait_ms, limit=8):
        assert execution_id == "exec-1"
        assert stream in {"stdout", "stderr"}
        assert 1 <= wait_ms <= 2000
        return {
            "events": [{"cursor": "1", "text": "event", "byte_count": 5, "created_at": "now"}],
            "next_cursor": "1",
            "terminal": True,
        }

    def get_execution(self, execution_id):
        assert execution_id == "exec-1"
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

    def output_page(self, execution_id, stream, after, limit_bytes):
        self.pages.append((execution_id, stream, after, limit_bytes))
        return {
            "text": "TcpTestSucceeded: False\nResolvedAddresses: 203.0.113.10\n",
            "next_cursor": "2",
            "more_available": False,
            "capture_lost": False,
            "gap": {"detected": False, "reason": None},
        }


def test_driver_runs_adaptive_tools_closes_session_and_keeps_timings_out_of_tool_context():
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
    assert control_plane.submitted == [("Test-NetConnection rmm-test-fileserver -Port 445", 5000)]
    assert control_plane.pages == [("exec-1", "stdout", "0", 65536)]
    assert [step.tool for step in result.steps] == ["run_powershell", "get_output_page"]
    assert result.steps[0].execution_ms == 42.0
    tool_output_message = model.inputs[1][-1]
    assert tool_output_message["type"] == "function_call_output"
    assert "api_round_trip_ms" not in tool_output_message["output"]
    assert "model_ms_before_step" not in tool_output_message["output"]


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


def test_driver_caps_execution_timeout_to_remaining_time_budget():
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
    client.client = httpx.Client(base_url="http://control-plane.test", headers={"Authorization": "Bearer operator-secret"}, transport=httpx.MockTransport(handler))

    assert client.submit_execution("session-1", "Get-Date", 1000, "idem-1")["execution_id"] == "exec-1"
    assert client.output_events("exec-1", "stdout", after="0", wait_ms=50)["terminal"] is True
    assert client.output_page("exec-1", "stdout", "0", 65536)["text"] == "page"
    assert len(requests) == 3


def test_openai_responses_client_uses_bounded_model_request_and_reports_usage():
    def handler(request):
        body = json.loads(request.content)
        assert request.headers["Authorization"] == "Bearer openai-secret"
        assert body["model"] == "gpt-5-nano"
        assert body["store"] is False
        assert body["max_output_tokens"] == 123
        assert body["tools"][0]["name"] == "run_powershell"
        return httpx.Response(200, json={
            "id": "resp-1",
            "output": [{"type": "message", "content": [{"type": "output_text", "text": "done"}]}],
            "usage": {"input_tokens": 5, "output_tokens": 7},
        })

    client = OpenAIResponsesClient("openai-secret", max_output_tokens=123)
    client.client = httpx.Client(base_url="https://api.openai.com/v1", headers={"Authorization": "Bearer openai-secret"}, transport=httpx.MockTransport(handler))
    reply = client.create_response([{"role": "user", "content": "hello"}])

    assert reply.text == "done"
    assert summarize_usage([reply]) == {"input_tokens": 5, "output_tokens": 7}
    rendered = render_result(type("Result", (), {
        "final_report": "done",
        "steps": [],
        "model_calls": [reply],
        "model_latency_ms": reply.latency_ms,
        "closed": True,
    })())
    assert "approximate_cost=$" in rendered


def test_openai_client_raises_for_failed_response_without_exposing_body():
    def handler(request):
        return httpx.Response(401, json={"error": {"message": "bad key"}})

    client = OpenAIResponsesClient("openai-secret")
    client.client = httpx.Client(base_url="https://api.openai.com/v1", headers={"Authorization": "Bearer openai-secret"}, transport=httpx.MockTransport(handler))

    with pytest.raises(httpx.HTTPStatusError):
        client.create_response([{"role": "user", "content": "hello"}])
