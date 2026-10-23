# opencode relay: makes the host's opencode CLI look like an OpenAI-compatible
# chat-completions endpoint. Zero keys — uses whatever credentials opencode
# already has (free models included) and is exactly as reachable as your
# terminal. h4k's container points H4K_AI_URL at http://127.0.0.1:3777/...
#
#   OPENCODE_MODEL=opencode/beam-free python3 h4k/scripts/opencode_relay.py
#
# Then run h4k with:
#   -e H4K_AI_PROVIDER=openai_compatible \
#   -e H4K_AI_URL=http://127.0.0.1:3777/v1/chat/completions \
#   -e H4K_AI_MODEL=opencode/beam-free
#
# POST /v1/chat/completions bodies are the OpenAI shape; the system+user
# messages are flattened into one prompt for `opencode run --model <model>`.
import json
import os
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

OPENCODE_BIN = os.environ.get("OPENCODE_BIN", "opencode")
DEFAULT_MODEL = os.environ.get("OPENCODE_MODEL", "")
PORT = int(os.environ.get("OPENCODE_RELAY_PORT", "3777"))
TIMEOUT = int(os.environ.get("OPENCODE_TIMEOUT", "300"))


def _flatten(messages: list) -> str:
    """Fold OpenAI-style messages into a single prompt.

    opencode carries its own assistant persona, so an injected system prompt
    is passed through as labelled instructions inside the message body.
    """
    parts: list[str] = []
    for m in messages:
        role = str(m.get("role") or "user")
        content = str(m.get("content") or "")
        if role == "system":
            parts.append(f"[Instructions]\n{content}")
        else:
            parts.append(content)
    return "\n\n".join(p for p in parts if p)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - stdlib naming
        body = json.dumps({"status": "ok", "relay": "opencode"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib naming
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            payload = json.loads(raw or b"{}")
            messages = payload.get("messages") or []
            if not messages:
                messages = [{"role": "user", "content": str(payload.get("prompt") or "")}]
            model = str(payload.get("model") or DEFAULT_MODEL)
            prompt = _flatten(messages)

            argv = [OPENCODE_BIN, "run"]
            if model:
                argv += ["--model", model]
            argv.append(prompt)
            try:
                proc = subprocess.run(  # nosec B603 - fixed argv, no shell
                    argv, capture_output=True, text=True, timeout=TIMEOUT, check=False
                )
                content = (proc.stdout or "").strip()
                if not content and proc.stderr:
                    content = f"(opencode rc={proc.returncode}) {proc.stderr.strip()}"
            except FileNotFoundError:
                content = "(opencode not found on this host — start opencode or set OPENCODE_BIN)"
            except Exception as exc:
                content = f"(opencode relay error: {exc})"

            body = json.dumps(
                {
                    "choices": [{"message": {"role": "assistant", "content": content}}],
                    "model": model or "opencode-default",
                }
            ).encode()
            self.send_response(200)
        except Exception as exc:
            body = json.dumps({"error": str(exc)}).encode()
            self.send_response(500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(
        f"opencode relay: http://127.0.0.1:{PORT}/v1/chat/completions "
        f"(bin={OPENCODE_BIN}, model={DEFAULT_MODEL or 'opencode default'})"
    )
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()