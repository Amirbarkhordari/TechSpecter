"""Finding validators to reduce false positives."""

from __future__ import annotations

import base64
import json
import re

_AWS_ACCESS_KEY = re.compile(r"^AKIA[0-9A-Z]{16}$")
_GITHUB_TOKEN = re.compile(
    r"^(?:ghp_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,}|gho_[A-Za-z0-9]{20,}|"
    r"ghu_[A-Za-z0-9]{20,}|ghs_[A-Za-z0-9]{20,}|ghr_[A-Za-z0-9]{20,})$"
)
_JWT_PARTS = re.compile(r"^[A-Za-z0-9_-]+$")
_PEM_HEADER = re.compile(r"^-----BEGIN (?:RSA |EC |OPENSSH )?(?:PRIVATE KEY|CERTIFICATE)-----")


def validate_jwt(value: str, _match: re.Match[str]) -> bool:
    """Validate JWT structure (header.payload.signature)."""
    parts = value.split(".")
    if len(parts) != 3:
        return False
    return all(_JWT_PARTS.match(part) for part in parts)


def validate_pem(value: str, _match: re.Match[str]) -> bool:
    """Validate PEM private key or certificate header."""
    first_line = value.strip().splitlines()[0] if value.strip() else value
    return bool(_PEM_HEADER.match(first_line))


def validate_aws_access_key(value: str, _match: re.Match[str]) -> bool:
    """Validate AWS access key ID format."""
    return bool(_AWS_ACCESS_KEY.match(value))


def validate_github_token(value: str, _match: re.Match[str]) -> bool:
    """Validate GitHub personal access token format."""
    return bool(_GITHUB_TOKEN.match(value))


def validate_jwt_payload(value: str, match: re.Match[str]) -> bool:
    """Validate JWT and decode header JSON when possible."""
    token = match.group(0)
    if not validate_jwt(token, match):
        return False
    try:
        header_segment = token.split(".", 1)[0]
        padding = "=" * (-len(header_segment) % 4)
        decoded = base64.urlsafe_b64decode(header_segment + padding)
        header = json.loads(decoded)
        return isinstance(header, dict) and "alg" in header
    except (ValueError, json.JSONDecodeError):
        return True
