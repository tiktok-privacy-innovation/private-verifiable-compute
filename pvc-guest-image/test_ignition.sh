#!/bin/bash
# Copyright 2025 TikTok Inc. and/or its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

echo "[INFO] Testing Ignition file validity..."

for ign in "$@"; do
  echo "→ Checking $ign"

  # validate json format
  if ! jq empty "$ign" >/dev/null 2>&1; then
    echo "[ERROR] $ign is not valid JSON"
    exit 1
  fi

  # validate ignition.version contained in ign file
  if ! jq -e '.ignition.version' "$ign" >/dev/null; then
    echo "[ERROR] $ign missing .ignition.version"
    exit 1
  fi

  echo "[OK] $ign is valid and contains ignition.version"
done

echo "[SUCCESS] All ignition configs passed validation."
