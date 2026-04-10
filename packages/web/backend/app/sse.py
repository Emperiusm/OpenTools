"""Server-Sent Events manager with per-user channels."""

import asyncio
import json
from typing import AsyncGenerator


class SSEManager:
    def __init__(self):
        self._channels: dict[str, list[asyncio.Queue]] = {}

    async def subscribe(self, user_id: str) -> AsyncGenerator[str, None]:
        queue: asyncio.Queue = asyncio.Queue()
        self._channels.setdefault(user_id, []).append(queue)
        try:
            while True:
                event = await queue.get()
                yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
        finally:
            self._channels[user_id].remove(queue)
            if not self._channels[user_id]:
                del self._channels[user_id]

    async def publish(self, user_id: str, event_type: str, data: dict):
        for queue in self._channels.get(user_id, []):
            await queue.put({"type": event_type, "data": data})


sse_manager = SSEManager()
