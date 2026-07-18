"""Dangerous validator: parses untrusted source and executes it."""
import ast


def validate_code(code):
    tree = ast.parse(code)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            code_obj = compile(ast.Module(body=[node], type_ignores=[]), "<string>", "exec")
            exec(code_obj)
