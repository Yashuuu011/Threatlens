import asyncio
from collections import deque
import json
import logging
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Deque, Dict, List, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger("threatlens.websocket")


class ConnectionManager:
    """Manages active WebSocket connections and recent message buffer for real-time SOC notifications and polling fallback."""

    def __init__(self) -> None:
        self.active_connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()
        self._buffer_lock = Lock()
        self._recent_messages: Deque[Dict[str, Any]] = deque(maxlen=100)
        self._seq: int = 0
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    @property
    def latest_seq(self) -> int:
        with self._buffer_lock:
            return self._seq

    def reset(self) -> None:
        with self._buffer_lock:
            self._recent_messages.clear()
            self._seq = 0

    def record_message(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._buffer_lock:
            self._seq += 1
            message = {
                "seq": self._seq,
                "type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "data": payload,
            }
            self._recent_messages.append(message)
            return message

    def get_poll_snapshot(self, since_seq: int = 0, limit: int = 30) -> Dict[str, Any]:
        with self._buffer_lock:
            if since_seq > 0:
                messages = [m for m in self._recent_messages if m["seq"] > since_seq][-limit:]
            else:
                messages = list(self._recent_messages)[-limit:]
            latest = self._seq
        return {
            "latest_seq": latest,
            "active_connections": len(self.active_connections),
            "messages": messages,
        }

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        async with self._lock:
            self.active_connections.add(websocket)
        logger.info("WebSocket client connected. Total active: %d", len(self.active_connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self.active_connections.discard(websocket)
        logger.info("WebSocket client disconnected. Total active: %d", len(self.active_connections))

    async def send_prepared_message(self, message: Dict[str, Any]) -> None:
        if not self.active_connections:
            return
        serialized = json.dumps(message, default=str)
        stale: List[WebSocket] = []
        async with self._lock:
            targets = list(self.active_connections)

        for connection in targets:
            try:
                await connection.send_text(serialized)
            except Exception:
                stale.append(connection)

        if stale:
            async with self._lock:
                for s in stale:
                    self.active_connections.discard(s)

    async def broadcast(self, event_type: str, payload: Dict[str, Any]) -> None:
        message = self.record_message(event_type, payload)
        await self.send_prepared_message(message)


ws_manager = ConnectionManager()


def broadcast_sync_or_async(event_type: str, payload: Dict[str, Any]) -> None:
    """Records a real-time message and schedules a WebSocket broadcast safely from sync or async contexts."""
    message = ws_manager.record_message(event_type, payload)
    if not ws_manager.active_connections:
        return
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(ws_manager.send_prepared_message(message))
    except RuntimeError:
        if ws_manager._loop and ws_manager._loop.is_running():
            try:
                asyncio.run_coroutine_threadsafe(
                    ws_manager.send_prepared_message(message),
                    ws_manager._loop,
                )
            except Exception:
                pass


