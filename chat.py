from typing import Dict, List
import json


class ConnectionManager:
    def __init__(self):
        self.active: Dict[str, object] = {}

    async def connect(self, websocket, email: str):
        await websocket.accept()
        self.active[email] = websocket

    def disconnect(self, email: str):
        self.active.pop(email, None)

    def is_online(self, email: str) -> bool:
        return email in self.active

    def get_online(self) -> List[str]:
        return list(self.active.keys())

    async def send_to(self, email: str, payload: dict):
        ws = self.active.get(email)
        if ws:
            try:
                await ws.send_text(json.dumps(payload))
            except Exception:
                self.disconnect(email)

    async def broadcast_online(self):
        online = self.get_online()
        msg = json.dumps({"type": "online_users", "users": online})
        dead = []
        for email, ws in self.active.items():
            try:
                await ws.send_text(msg)
            except Exception:
                dead.append(email)
        for e in dead:
            self.disconnect(e)


manager = ConnectionManager()