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

helm_name="private-verifiable-compute"
eval $(minikube docker-env)
tag="latest"
docker_repo="localhost:5000"
privacy_gateway_reference="$docker_repo/pvc-ohttp-gateway"
identity_server_reference="$docker_repo/pvc-identity-server"
relay_reference="$docker_repo/pvc-ohttp-relay"
tee_llm_reference="$docker_repo/pvc-tee-llm"
pvc_client="$docker_repo/pvc-client"

namespace=default
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
    --set teeLlm.llmModel="qwen3:0.6b" \
    --set teeLlm.embeddingModel="qwen3-embedding:0.6b" \
    --set teeLlm.llmImage.repository="ollama/ollama" \
    --set teeLlm.embeddingImage.repository="ollama/ollama" \
    --set teeLlm.llmArgs[0]="export OLLAMA_HOST=0.0.0.0:8000; ollama serve & PID=\$!; sleep 3; ollama pull qwen3:0.6b; wait \$PID" \
    --set teeLlm.embeddingArgs[0]="export OLLAMA_HOST=0.0.0.0:8001; ollama serve & PID=\$!; sleep 3; ollama pull qwen3-embedding:0.6b; wait \$PID" \
    --set teeLlm.embeddingNdims=1024 \
    --set teeLlm.llmMaxToken=8192 \
    --set teeLlm.resources=null \
    --set teeLlm.nodeSelector=null \
    --set teeLlm.tolerations=null \
    --set teeLlm.livenessProbe=null \
    --set teeLlm.readinessProbe=null \
    --namespace $namespace \
    --install $helm_name ../private-verifiable-compute --debug
