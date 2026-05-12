#!/usr/bin/env bash
# Reject any staged change that adds or modifies a file under
# docs/design/, docs/internal/, or docs/private/. Those locations are
# reserved for the private ops repo; nothing under them belongs in this
# public repository.

set -euo pipefail

staged="$(git diff --cached --name-only --diff-filter=AM \
  | grep -E '^docs/(design|internal|private)/' || true)"

if [[ -n "${staged}" ]]; then
  cat >&2 <<EOF
OPSEC: design/internal/private docs belong in the private ops repo,
not this public repository. Move the file out of the staged set:

${staged}

If the path is intentional (e.g. a rename of a public doc that
happens to land here), revert the staging and discuss with a reviewer.
EOF
  exit 1
fi

exit 0
