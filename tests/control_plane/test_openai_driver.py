import asyncio
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from agents import Model, ModelResponse, RunContextWrapper
from agents.usage import InputTokensDetails, OutputTokensDetails, Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from control_plane.openai_driver import (
    DEFAULT_PAGE_LIMIT_BYTES,
    ControlPlaneClient,
    DiagnosticContext,
    DriverError,
    _read_output,
    _submit_script,
    _wait_for_execution,
    build_agent,
    drive_diagnostic,
    inert_text,
    render_result,
)


class FakeControlPlane:
    def __init__(self, *, close_ok=True):
        self.closed = False
        self.close_ok = close_ok
        self.close_raises = False
        self.submitted = []
        self.waits = []
        self.pages = []
        self.next_execution = 1
        self.wait_counts = {}

    async def open_session(self, device_id, *, timeout_seconds):
        assert device_id == "device-1"
        assert timeout_seconds > 0
        return {"session_id": "session-1", "status": "active"}

    async def close_session(self, session_id, *, timeout_seconds):
        assert session_id == "session-1"
        assert timeout_seconds >= 31
        if self.close_raises:
            raise httpx.ReadTimeout("close stuck")
        self.closed = self.close_ok
        return (self.close_ok, None if self.close_ok else "session_close_unconfirmed")

    async def submit_execution(self, session_id, script, timeout_ms, *, timeout_seconds):
        assert session_id == "session-1"
        assert 100 <= timeout_ms <= 60_000
        execution_id = f"exec-{self.next_execution}"
        self.next_execution += 1
        self.submitted.append((execution_id, script, timeout_ms))
        return {
            "execution_id": execution_id,
            "status": "queued",
            "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
        }

    async def wait_execution(self, execution_id, timeout_seconds):
        self.waits.append((execution_id, timeout_seconds))
        self.wait_counts[execution_id] = self.wait_counts.get(execution_id, 0) + 1
        if execution_id == "exec-1" and self.wait_counts[execution_id] == 1:
            return {
                "execution_id": execution_id,
                "status": "running",
                "terminal": False,
                "wait_timed_out": True,
            }
        if execution_id == "exec-1":
            return {
                "execution_id": execution_id,
                "status": "completed",
                "terminal": True,
                "wait_timed_out": False,
                "invocation_outcome": "completed_normally",
                "exit_code": 0,
                "duration_ms": 12.0,
                "capture": {"loss_detected": False},
                "output_preview": {
                    "stdout": {"text": "DNS resolves to 10.0.0.5\n", "shortened": False},
                    "stderr": {"text": "", "shortened": False},
                },
            }
        return {
            "execution_id": execution_id,
            "status": "completed",
            "terminal": True,
            "wait_timed_out": False,
            "invocation_outcome": "completed_normally",
            "exit_code": 0,
            "duration_ms": 42.0,
            "capture": {"loss_detected": False},
            "output_preview": {
                "stdout": {"text": "TcpTestSucceeded: False\n", "shortened": True},
                "stderr": {"text": "", "shortened": False},
            },
        }

    async def output_page(self, execution_id, stream, after, *, timeout_seconds):
        self.pages.append((execution_id, stream, after))
        return {
            "text": "full tcp page",
            "next_cursor": "9",
            "more_available": False,
            "capture_lost": False,
            "gap": {"detected": False, "reason": None},
        }


def test_agent_exposes_exactly_three_script_execution_tools():
    agent = build_agent("gpt-5-nano")

    assert agent.model == "gpt-5-nano"
    assert [tool.name for tool in agent.tools] == ["submit_script", "wait_for_execution", "read_output"]
    assert "run_diagnostic" not in {tool.name for tool in agent.tools}
    assert agent.model_settings.parallel_tool_calls is False
    assert agent.model_settings.max_tokens == 600

    schemas = {tool.name: tool.params_json_schema["properties"] for tool in agent.tools}
    assert set(schemas["submit_script"]) == {"script", "timeout_ms"}
    assert schemas["submit_script"]["script"]["maxLength"] == 32768
    assert schemas["submit_script"]["timeout_ms"]["minimum"] == 100
    assert schemas["submit_script"]["timeout_ms"]["maximum"] == 60000
    assert set(schemas["wait_for_execution"]) == {"execution_id", "timeout_seconds"}
    assert schemas["wait_for_execution"]["timeout_seconds"]["maximum"] == 60
    assert set(schemas["read_output"]) == {"execution_id", "stream", "cursor"}


def context(max_steps=2):
    return DiagnosticContext(FakeControlPlane(), "session-1", 9999999999.0, max_steps)


def tool_context(ctx):
    return RunContextWrapper(ctx, usage=SimpleNamespace())


def test_real_agents_sdk_submit_tool_invokes_bound_session_and_schema():
    submit_tool = build_agent("gpt-5-nano").tools[0]
    ctx = context()

    payload = asyncio.run(submit_tool.on_invoke_tool(
        tool_context(ctx),
        json.dumps({"script": "Resolve-DnsName rmm-test-fileserver", "timeout_ms": 5000}),
    ))

    assert payload["execution_id"] == "exec-1"
    assert payload["status"] == "queued"
    assert payload["script_sha256"]
    assert ctx.owned_execution_ids == {"exec-1"}
    assert ctx.control_plane.submitted == [("exec-1", "Resolve-DnsName rmm-test-fileserver", 5000)]


def test_wait_and_read_reject_unknown_execution_ids():
    ctx = context()

    with pytest.raises(DriverError, match="unknown_execution_id"):
        asyncio.run(_wait_for_execution(ctx, "not-created-here", 1))
    with pytest.raises(DriverError, match="unknown_execution_id"):
        asyncio.run(_read_output(ctx, "not-created-here", "stdout", "0"))


def test_submit_enforces_driver_owned_script_budget():
    ctx = context(max_steps=1)

    first = asyncio.run(_submit_script(ctx, "Get-NetIPConfiguration", 5000))
    assert first["execution_id"] == "exec-1"
    with pytest.raises(DriverError, match="script_step_budget_exhausted"):
        asyncio.run(_submit_script(ctx, "Test-NetConnection rmm-test-fileserver -Port 445", 5000))


def test_three_tools_handle_repeated_wait_and_paged_output():
    ctx = context(max_steps=2)
    first = asyncio.run(_submit_script(ctx, "Resolve-DnsName rmm-test-fileserver", 5000))
    running = asyncio.run(_wait_for_execution(ctx, first["execution_id"], 0.1))
    complete = asyncio.run(_wait_for_execution(ctx, first["execution_id"], 5))
    second = asyncio.run(_submit_script(ctx, "Test-NetConnection rmm-test-fileserver -Port 445", 5000))
    tcp = asyncio.run(_wait_for_execution(ctx, second["execution_id"], 5))
    page = asyncio.run(_read_output(ctx, second["execution_id"], "stdout", "0"))

    assert running == {
        "execution_id": "exec-1",
        "status": "running",
        "terminal": False,
        "wait_timed_out": True,
        "invocation_outcome": None,
        "exit_code": None,
        "duration_ms": None,
        "capture": None,
        "output_preview": None,
    }
    assert complete["output_preview"]["stdout"]["text"] == "DNS resolves to 10.0.0.5\n"
    assert tcp["output_preview"]["stdout"]["more_available"] is True
    assert page["text"]["text"] == "full tcp page"
    assert page["next_cursor"] == "9"
    assert [step.tool for step in ctx.steps] == [
        "submit_script",
        "wait_for_execution",
        "wait_for_execution",
        "submit_script",
        "wait_for_execution",
        "read_output:stdout",
    ]


def sdk_usage():
    return Usage(
        requests=1,
        input_tokens=1,
        output_tokens=1,
        total_tokens=2,
        input_tokens_details=InputTokensDetails(cached_tokens=0),
        output_tokens_details=OutputTokensDetails(reasoning_tokens=0),
    )


class ScriptedModel(Model):
    def __init__(self):
        self.calls = 0

    async def get_response(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-1",
                name="submit_script",
                arguments=json.dumps({"script": "Resolve-DnsName rmm-test-fileserver", "timeout_ms": 5000}),
            )]
        elif self.calls == 2:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-2",
                name="wait_for_execution",
                arguments=json.dumps({"execution_id": "exec-1", "timeout_seconds": 0.1}),
            )]
        elif self.calls == 3:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-3",
                name="wait_for_execution",
                arguments=json.dumps({"execution_id": "exec-1", "timeout_seconds": 5}),
            )]
        elif self.calls == 4:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-4",
                name="submit_script",
                arguments=json.dumps({"script": "Test-NetConnection rmm-test-fileserver -Port 445", "timeout_ms": 5000}),
            )]
        elif self.calls == 5:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-5",
                name="wait_for_execution",
                arguments=json.dumps({"execution_id": "exec-2", "timeout_seconds": 5}),
            )]
        elif self.calls == 6:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-6",
                name="read_output",
                arguments=json.dumps({"execution_id": "exec-2", "stream": "stdout", "cursor": "0"}),
            )]
        else:
            output = [ResponseOutputMessage(
                id="msg-1",
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text="DNS resolves, but SMB TCP 445 is unreachable.", annotations=[])],
            )]
        return ModelResponse(output=output, usage=sdk_usage(), response_id="resp-" + str(self.calls))

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError


def test_real_agents_sdk_runner_loop_submit_wait_read_dependent_script_and_reports():
    model = ScriptedModel()
    control_plane = FakeControlPlane()
    result = asyncio.run(drive_diagnostic(
        problem="Why can Windows not reach the test share?",
        device_id="device-1",
        control_plane=control_plane,
        model=model,
        max_steps=2,
        max_seconds=60,
    ))

    assert model.calls == 7
    assert result.completed is True
    assert result.final_report == "DNS resolves, but SMB TCP 445 is unreachable."
    assert [script for _, script, _ in control_plane.submitted] == [
        "Resolve-DnsName rmm-test-fileserver",
        "Test-NetConnection rmm-test-fileserver -Port 445",
    ]
    assert control_plane.waits == [("exec-1", 0.1), ("exec-1", 5.0), ("exec-2", 5.0)]
    assert control_plane.pages == [("exec-2", "stdout", "0")]
    assert [step.tool for step in result.steps] == [
        "submit_script",
        "wait_for_execution",
        "wait_for_execution",
        "submit_script",
        "wait_for_execution",
        "read_output:stdout",
    ]


def test_drive_diagnostic_delegates_loop_to_runner_and_closes_session():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        assert [tool.name for tool in agent.tools] == ["submit_script", "wait_for_execution", "read_output"]
        assert "Budget: at most 2 submitted PowerShell scripts" in prompt
        assert "policy, not sandbox enforcement" in prompt
        assert max_turns == 11
        assert run_config.tracing_disabled is True
        await hooks.on_llm_start(None, agent, None, [])
        await hooks.on_llm_end(None, agent, None)
        first = await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver", 5000)
        await _wait_for_execution(context.context, first["execution_id"], 0.1)
        await _wait_for_execution(context.context, first["execution_id"], 5)
        second = await _submit_script(context.context, "Test-NetConnection rmm-test-fileserver -Port 445", 5000)
        await _wait_for_execution(context.context, second["execution_id"], 5)
        return SimpleNamespace(
            final_output="Likely file-server TCP 445 is unreachable.",
            raw_responses=[SimpleNamespace(usage=SimpleNamespace(requests=1, input_tokens=10, output_tokens=20, total_tokens=30))],
        )

    control_plane = FakeControlPlane()
    result = asyncio.run(drive_diagnostic(
        problem="Why can Windows not reach the test share?",
        device_id="device-1",
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is True
    assert result.closed is True
    assert control_plane.closed is True
    assert len([step for step in result.steps if step.tool == "submit_script"]) == 2
    assert result.usage == {"requests": 1, "input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
    assert result.model_latency_ms >= 0
    rendered = render_result(result)
    assert "Likely file-server TCP 445 is unreachable." in rendered
    assert "Model latency ms:" in rendered


def test_drive_diagnostic_does_not_complete_without_diagnostics():
    async def fake_runner(*args, **kwargs):
        return SimpleNamespace(final_output="No commands needed.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        max_steps=2,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is False
    assert "required multi-step diagnostic depth" in result.final_report


def test_drive_diagnostic_surfaces_time_budget_and_still_closes():
    async def slow_runner(*args, **kwargs):
        await asyncio.sleep(0.2)

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        max_steps=1,
        max_seconds=0.1,
        runner=slow_runner,
    ))

    assert result.final_report == "Stopped because the configured diagnostic time budget was exhausted."
    assert result.closed is True


def test_unconfirmed_session_close_is_reported():
    async def fake_runner(*args, **kwargs):
        return SimpleNamespace(final_output="No issue found.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(close_ok=False),
        max_steps=1,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.closed is False
    assert "closure_unconfirmed" in result.final_report


def test_close_transport_failure_preserves_primary_outcome():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        first = await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver", 5000)
        await _wait_for_execution(context.context, first["execution_id"], 5)
        second = await _submit_script(context.context, "Test-NetConnection rmm-test-fileserver -Port 445", 5000)
        await _wait_for_execution(context.context, second["execution_id"], 5)
        return SimpleNamespace(final_output="Primary finding.", raw_responses=[])

    control_plane = FakeControlPlane()
    control_plane.close_raises = True
    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is True
    assert result.closed is False
    assert result.close_error == "transport:ReadTimeout"
    assert result.final_report.startswith("Primary finding.")


def test_control_plane_client_authenticates_public_api_without_openai_key():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer operator-secret"
        assert "openai-secret" not in str(request.headers)
        if request.url.path.endswith("/executions"):
            assert request.headers["Idempotency-Key"].startswith("openai-driver-")
            return httpx.Response(202, json={"execution_id": "exec-1", "status": "queued"})
        if request.url.path == "/executions/exec-1/wait":
            return httpx.Response(200, json={"execution_id": "exec-1", "status": "completed", "terminal": True, "wait_timed_out": False})
        if request.url.path == "/executions/exec-1/output/stdout":
            assert request.url.params["limit_bytes"] == str(DEFAULT_PAGE_LIMIT_BYTES)
            return httpx.Response(200, json={
                "text": "page",
                "next_cursor": "1",
                "more_available": False,
                "capture_lost": False,
                "gap": {"detected": False, "reason": None},
            })
        raise AssertionError(request.url.path)

    client = ControlPlaneClient("http://control-plane.test", "operator-secret")
    client.client = httpx.AsyncClient(
        base_url="http://control-plane.test",
        headers={"Authorization": "Bearer operator-secret"},
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(client.submit_execution("session-1", "Get-Date", 1000, timeout_seconds=1))["execution_id"] == "exec-1"
    assert asyncio.run(client.wait_execution("exec-1", 1))["terminal"] is True
    assert asyncio.run(client.output_page("exec-1", "stdout", "0", timeout_seconds=1))["text"] == "page"
    assert len(requests) == 3


def test_terminal_rendering_escapes_untrusted_control_sequences():
    result = SimpleNamespace(
        final_report="ok\x1b]0;pwned\x07\rbad",
        steps=[],
        model_latency_ms=0,
        total_ms=1,
        usage={},
        completed=True,
        closed=False,
        close_error="close\x1b[31m",
    )

    rendered = render_result(result)

    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert "\\x1b]0;pwned\\x07\\x0dbad" in rendered
    assert inert_text("a\x1b\rb") == "a\\x1b\\x0db"
