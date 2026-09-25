#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${CODESPACES:-}" != "true" ]]; then
  echo "This automatic demo launcher runs only inside GitHub Codespaces." >&2
  exit 1
fi

if [[ ! "${CODESPACE_NAME:-}" =~ ^[a-zA-Z0-9-]+$ ]] ||
  [[ ! "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-}" =~ ^[a-zA-Z0-9.-]+$ ]]; then
  echo "Codespaces forwarding variables are unavailable; demo was not started." >&2
  exit 1
fi

if curl --fail --silent --max-time 2 http://127.0.0.1:8000/readyz >/dev/null; then
  echo "Shadow AI MCP demo is already running on port 8000."
  exit 0
fi

# Isolate the fixture demo from any mounted production .env or database settings.
export SHAI_DATABASE_URL=sqlite:///shadow-codespaces.db
export SHAI_DEVELOPMENT_MODE=true
export SHAI_AUTH_MODE=dev
export SHAI_TRANSPORT=streamable-http
export SHAI_HOST=127.0.0.1
export SHAI_PORT=8000
export SHAI_UI_ENABLED=true
export SHAI_DEV_TRUSTED_CIDRS='["127.0.0.1/32","::1/128"]'
export SHAI_ALLOWED_HOSTS="[\"127.0.0.1:8000\",\"localhost:8000\",\"${CODESPACE_NAME}-8000.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}\"]"
export SHAI_CONNECTORS_FILE=examples/connectors.yaml
export SHAI_CATALOG_FILE=examples/provider-catalog.yaml

demo_log="${TMPDIR:-/tmp}/shadow-ai-codespaces-demo.log"
nohup python -m shadow_ai_mcp.cli demo >"$demo_log" 2>&1 </dev/null &
demo_pid=$!

for _ in {1..30}; do
  if curl --fail --silent --max-time 2 http://127.0.0.1:8000/readyz >/dev/null; then
    echo "Shadow AI MCP is ready. Open the private forwarded port 8000 at /ui/."
    exit 0
  fi
  if ! kill -0 "$demo_pid" 2>/dev/null; then
    echo "Demo startup failed; inspect $demo_log in the Codespaces terminal." >&2
    exit 1
  fi
  sleep 1
done

echo "Demo is still starting; inspect $demo_log in the Codespaces terminal." >&2
exit 1
