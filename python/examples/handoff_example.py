"""Python equivalent of examples/test-handoff-hmac.js and examples/test-handoff-ed25519.js.

Reads the same repo-root .env as the Node examples (walks up from the working directory).

    python examples/handoff_example.py hmac
    python examples/handoff_example.py ed25519
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from partner_signed_client import HandoffResult, handoff


def load_env() -> None:
    """Minimal .env loader: first .env walking up from cwd; real env vars win."""
    for directory in (Path.cwd(), *Path.cwd().parents):
        path = directory / ".env"
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            key, sep, value = line.partition("=")
            if line.startswith("#") or not sep or not key.strip():
                continue
            os.environ.setdefault(key.strip(), value.strip())
        return


def env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing env var {name} - copy .env.example to .env and fill it in")
    return value


def main(argv: list[str]) -> int:
    load_env()

    scheme = (argv[1] if len(argv) > 1 else "hmac").lower()
    if scheme not in ("hmac", "ed25519"):
        raise SystemExit(f'Unknown scheme "{scheme}" - expected "hmac" or "ed25519"')
    prefix = scheme.upper()

    secret = (
        env("HMAC_SECRET")
        if scheme == "hmac"
        # .env can only carry the PEM with real newlines escaped as literal "\n".
        else env("ED25519_PRIVATE_KEY_PEM").replace("\\n", "\n")
    )

    try:
        response = handoff(
            base_url=env("API_BASE_URL"),
            scheme=scheme,  # type: ignore[arg-type]
            secret=secret,
            partner_id=env(f"{prefix}_PARTNER_SLUG"),
            partner_user_id=env(f"{prefix}_TEST_PARTNER_USER_ID"),
            phone_number=env(f"{prefix}_TEST_PHONE_NUMBER"),
        )
    except Exception as error:  # noqa: BLE001 - example script
        print(f"Request failed: {error!r}", file=sys.stderr)
        return 1

    print(f"status: {response.status}")
    if response.ok and isinstance(response.data, dict):
        result = HandoffResult.from_dict(response.data)
        print(f"entryUrl: {result.entry_url} (expires in {result.expires_in}s)")
    body = (
        json.dumps(response.json, indent=2, ensure_ascii=False)
        if response.json is not None
        else response.raw_body
    )
    print(f"body: {body}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
