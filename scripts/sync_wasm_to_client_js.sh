#!/usr/bin/env bash

# Copyright 2025 TikTok Inc. and/or its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use it except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Build pvc-wasm and sync the WASM package to pvc-client-js so the JS app
# uses the latest WASM. Run this after any change to pvc-wasm.
#
# Usage: from repo root: ./scripts/sync_wasm_to_client_js.sh
#        or from anywhere: /path/to/private-verifiable-cloud/scripts/sync_wasm_to_client_js.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PVC_WASM_DIR="$REPO_ROOT/pvc-wasm"
CLIENT_JS_DIR="$REPO_ROOT/pvc-client-js"
PKG_DIR="$PVC_WASM_DIR/pkg"
TARGET_DIR="$CLIENT_JS_DIR/wasm-pkg"

if ! command -v wasm-pack &>/dev/null; then
  echo "error: wasm-pack not found. Install with: cargo install wasm-pack" >&2
  exit 1
fi

echo "==> Building pvc-wasm (wasm-pack build)..."
(cd "$PVC_WASM_DIR" && wasm-pack build --target bundler)

if [ ! -d "$PKG_DIR" ]; then
  echo "error: expected pkg at $PKG_DIR" >&2
  exit 1
fi

echo "==> Syncing pvc-wasm/pkg -> pvc-client-js/wasm-pkg"
rm -rf "$TARGET_DIR"
cp -R "$PKG_DIR" "$TARGET_DIR"

echo "==> Done. pvc-client-js now uses the latest WASM. Run 'npm run dev' or 'npm run build' in pvc-client-js as needed."
