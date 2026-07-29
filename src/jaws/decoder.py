import base64
import json
from typing import Optional, Tuple, Dict, Any
from .models import DecodedToken


def pad_base64(data: str) -> str:
    return data + "=" * (4 - len(data) % 4) if len(data) % 4 else data


def safe_b64decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(pad_base64(data))


def decode_part(part: str) -> Dict[str, Any]:
    try:
        decoded = safe_b64decode(part)
        return json.loads(decoded.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {"error": "Invalid JSON or encoding"}


def decode_token(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    parts = token.split(".")
    if len(parts) != 3:
        return None, None, None

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    signature = parts[2] if len(parts) > 2 else None

    return header, payload, signature


def is_token_valid_structure(token: str) -> bool:
    """Check if token has valid JWT structure (at least 2 parts, third optional)."""
    parts = token.split(".")
    if len(parts) < 2 or len(parts) > 3:
        return False
    return all((parts[0], parts[1])) 
