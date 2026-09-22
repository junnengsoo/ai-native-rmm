"""In-process routing for currently connected endpoint agents.

Durable claims live in PostgreSQL. This registry only addresses the WebSocket
owned by this trial control-plane process.
"""
import asyncio
from dataclasses import dataclass, field
from typing import Any

from fastapi import WebSocket


@dataclass
class EndpointAgentChannel:
    device_id: str
    socket: WebSocket
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    waiters: dict[tuple[str, str], asyncio.Future] = field(default_factory=dict)

    async def send(self, message: dict[str, Any]) -> None:
        async with self.send_lock:
            await self.socket.send_json(message)

    def expect(self, kind: str, resource_id: str) -> asyncio.Future:
        key = (kind, resource_id)
        if key in self.waiters:
            raise RuntimeError("duplicate_protocol_waiter")
        future = asyncio.get_running_loop().create_future()
        self.waiters[key] = future
        return future

    def deliver(self, message: dict[str, Any]) -> bool:
        kind = message.get("type")
        resource_id = message.get("executionId") or message.get("sessionId")
        future = self.waiters.pop((kind, resource_id), None)
        if future is None or future.done():
            return False
        future.set_result(message)
        return True

    def fail_waiters(self) -> None:
        for future in self.waiters.values():
            if not future.done():
                future.set_exception(ConnectionError("endpoint_disconnected"))
        self.waiters.clear()


class EndpointAgentRegistry:
    def __init__(self) -> None:
        self._channels: dict[str, EndpointAgentChannel] = {}
        self._lock = asyncio.Lock()

    async def register(self, device_id: str, socket: WebSocket) -> EndpointAgentChannel:
        channel = EndpointAgentChannel(device_id, socket)
        async with self._lock:
            previous = self._channels.get(device_id)
            self._channels[device_id] = channel
        if previous is not None:
            previous.fail_waiters()
        return channel

    async def unregister(self, channel: EndpointAgentChannel) -> bool:
        removed = False
        async with self._lock:
            if self._channels.get(channel.device_id) is channel:
                self._channels.pop(channel.device_id, None)
                removed = True
        channel.fail_waiters()
        return removed

    async def get_connected_channel(self, device_id: str) -> EndpointAgentChannel | None:
        async with self._lock:
            return self._channels.get(device_id)

    async def disconnect(self, device_id: str, code: int = 1008) -> bool:
        """Stop routing before closing so a revoked peer cannot receive new work."""
        async with self._lock:
            channel = self._channels.pop(device_id, None)
        if channel is None:
            return False
        channel.fail_waiters()
        try:
            await channel.socket.close(code=code)
        except RuntimeError:
            pass
        return True


endpoint_agents = EndpointAgentRegistry()
