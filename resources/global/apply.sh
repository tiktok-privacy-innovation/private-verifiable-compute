#!/bin/bash

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

set -e

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/../.." && pwd)"
var_file="$repo_root/.env"

if [ ! -f "$var_file" ]; then
    echo "Error: Variables file does not exist."
    exit 1
fi

source "$var_file"

if [ -z "${project_id:-}" ] || [ -z "${region:-}" ] || [ -z "${zone:-}" ]; then
    echo "Error: project_id, region, and zone must be set in $var_file."
    exit 1
fi

cd "$script_dir"

export TF_VAR_project_id="$project_id"
export TF_VAR_region="$region"
export TF_VAR_zone="$zone"

terraform init -reconfigure
terraform apply
