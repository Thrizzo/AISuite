"""Curl preview builder. Lifted verbatim from ai_sploit.py."""
from __future__ import annotations

import json


def build_curl(
    host: str,
    port: int,
    endpoint: str,
    payload: dict,
    *,
    method: str = "POST",
    file_upload: bool = False,
) -> str:
    """Return a copy-paste-ready curl command. file_upload swaps to -F multipart."""
    url = f"http://{host}:{port}{endpoint}"
    if file_upload:
        parts = " ".join(f'-F "{k}=@{v}"' for k, v in payload.items())
        return f"curl -s -X POST {url} \\\n  {parts}"
    return (
        f"curl -s -X {method} {url} \\\n"
        f"  -H \"Content-Type: application/json\" \\\n"
        f"  -d '{json.dumps(payload)}'"
    )
