"""FastAPI path traversal via a file-serving response (Gradio CVE-2023-51449
shape). The route path parameter is served with FileResponse, which — like
Flask's send_file — reads an attacker-controlled path off disk."""
from fastapi import FastAPI
from fastapi.responses import FileResponse
import os

app = FastAPI()


@app.get("/file/{name}")
def serve(name: str):
    abs_path = os.path.join("/srv/data", name)  # Join does not contain "../"
    return FileResponse(abs_path)               # path traversal (sink)
