#!/usr/bin/env bash

# Copyright 2025 TikTok Inc. and/or its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

cd "$(dirname "$0")/.."

OUTPUT_PATH_FILE="./.pvc-bazel-cache/reproducible_output_base.txt"

if [[ ! -f "${OUTPUT_PATH_FILE}" ]]; then
  echo "Output path file not found: ${OUTPUT_PATH_FILE}" >&2
  exit 1
fi

OUTPUT_PATH="$(<"${OUTPUT_PATH_FILE}")"

# Replace the bazel cache base inside the container `/root/.cache/bazel`
# with the cache base outside the container `.pvc-bazel-cache`
OUTPUT_PATH="${OUTPUT_PATH/#\/root\/\.cache\/bazel/.pvc-bazel-cache}"

IMAGES=(
  "pvc-client"
  "pvc-identity-server"
  "pvc-ohttp-gateway"
  "pvc-ohttp-relay"
  "pvc-tee-llm"
)

for image_name in "${IMAGES[@]}"; do
  tarball="${OUTPUT_PATH}/k8-opt/bin/${image_name}/load_image/tarball.tar"

  if [[ ! -f "${tarball}" ]]; then
    echo "Tarball not found: ${tarball}" >&2
    continue
  fi

  echo "Loading image: ${image_name}"
  docker load -i "${tarball}"
done
