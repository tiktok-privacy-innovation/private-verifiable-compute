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
#
# Build the React/Vite frontend via Bazel and stage the bundle under
# `pvc-client/static/` for local `cargo run` workflows. The container image
# packages the same Bazel output directly through `//pvc-client:tar`, so this
# script is only needed when running `pvc-client` outside of the image.

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

cd "${repo_root}"
bazel build //pvc-client/frontend:build

dist="$(bazel cquery --output=files //pvc-client/frontend:build 2>/dev/null)"
if [[ -z "${dist}" || ! -d "${dist}" ]]; then
    echo "failed to locate //pvc-client/frontend:build output" >&2
    exit 1
fi

static_dir="${script_dir}/static"
rm -rf "${static_dir}"
mkdir -p "${static_dir}"
cp -RL "${dist}/." "${static_dir}/"
chmod -R u+w "${static_dir}"
