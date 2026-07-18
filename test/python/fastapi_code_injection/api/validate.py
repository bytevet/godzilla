"""FastAPI endpoint whose Pydantic request-body model reaches a code-exec sink.

`post_validate_code` takes a request body (`code: Code`) and passes `code.code`
to `validate_code` in another module, which parses it and exec()s the compiled
AST -- unauthenticated remote code execution (modeled on CVE-2025-3248 langflow).
"""
from fastapi import APIRouter

from utils.validate import validate_code

router = APIRouter(prefix="/validate")


@router.post("/code", status_code=200)
async def post_validate_code(code):
    return validate_code(code.code)
