"""Tornado handler: the JSON request body's `path` field flows into a shell
pipeline in another module (modeled on CVE-2025-47782 motioneye)."""
import json

from handlers.base import BaseHandler
from controls import v4l2ctl


class CameraHandler(BaseHandler):
    async def post(self):
        await self.add_camera()

    async def add_camera(self):
        device_details = json.loads(self.request.body)
        return v4l2ctl.list_resolutions(device_details['path'])
