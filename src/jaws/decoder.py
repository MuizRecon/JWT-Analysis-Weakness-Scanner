"""JWT decoding and validation."""

import base64
import json
from typing import Optional, Tuple, Dict, Any
from .models import DecodedToken


def pad_base64(data: str) -> str:
    """Add padding to base64 string if missing."""
    return data + '=' * (4 - len(data) % 4) if len(data) % 4 else data


def safe_b64decode(data: str) -> bytes:
    """Safely base64 decode a string with padding handling."""
    return base64.urlsafe_b64decode(pad_base64(data))


def decode_part(part: str) -> Dict[str, Any]:
    """Decode a single JWT part (header or payload)."""
    try:
        decoded = safe_b64decode(part)
        return json.loads(decoded.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return {"error": "Invalid JSON or encoding"}


def decode_token(token: str) -> Tuple[Optional[Dict], Optional[Dict], Optional[str]]:
    """
    Decode a JWT into header, payload, and signature.

    Returns:
        (header, payload, signature) where any part may be None on error.
    """
    parts = token.split('.')
    if len(parts) != 3:
        return None, None, None

    header = decode_part(parts[0])
    payload = decode_part(parts[1])
    signature = parts[2] if len(parts) > 2 else None

    return header, payload, signature


def is_token_valid_structure(token: str) -> bool:
    """Check if token has valid JWT structure (3 parts)."""
    parts = token.split('.')
    return len(parts) == 3 and all(p for p in parts)
