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

set -e

VAR_FILE="../.env"
if [ ! -f "$VAR_FILE" ]; then
    echo "Error: Variables file does not exist."
    exit 1
fi

VAR_FILE=$(realpath $VAR_FILE)
source $VAR_FILE

for arg in "$@"
do
    case $arg in
        --namespace=*)
        # If we find an argument --namespace=something, split the string into a name/value array.
        IFS='=' read -ra NAMESPACE <<< "$arg"
        # Assign the second element of the array (the value of the --namespace argument) to our variable.
        namespace="${NAMESPACE[1]}"
        ;;
    esac
done

if [ -z "$namespace" ]; then
    echo "Error: the namespace parameter is required, run the script again like ./apply.sh --namespace="
    exit 1
fi
helm_name="private-verifiable-compute"
docker_repo="pvc-${namespace}-images"
tag="latest"
privacy_gateway_reference="us-docker.pkg.dev/${project_id}/${docker_repo}/pvc-ohttp-gateway"
identity_server_reference="us-docker.pkg.dev/${project_id}/${docker_repo}/pvc-identity-server"
relay_reference="us-docker.pkg.dev/${project_id}/${docker_repo}/pvc-ohttp-relay"
tee_llm_reference="us-docker.pkg.dev/${project_id}/${docker_repo}/pvc-tee-llm"
pvc_client="us-docker.pkg.dev/${project_id}/${docker_repo}/pvc-client"
helm upgrade --cleanup-on-fail \
    --set privacyGateway.image.repository=${privacy_gateway_reference} \
    --set privacyGateway.image.tag=${tag} \
    --set namespace=${namespace} \
    --set relay.image.repository=${relay_reference} \
    --set relay.image.tag=${tag} \
    --set identityServer.image.repository=${identity_server_reference} \
    --set identityServer.image.tag=${tag} \
    --set teeLlm.image.repository=${tee_llm_reference} \
    --set teeLlm.image.tag=${tag} \
    --set client.image.repository=${pvc_client} \
    --set client.image.tag=${tag} \
    --namespace $namespace \
    --install $helm_name ./private-verifiable-compute --debug
