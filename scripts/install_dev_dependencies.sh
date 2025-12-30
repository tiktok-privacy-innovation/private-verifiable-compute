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

SUDO=""
if [ "$EUID" -ne 0 ]; then SUDO="sudo"; fi

install_brew_dependencies() {
  echo "====== Install dependent tools for compilation and deployment ======"
  BREW_FORMULAS=(bazelisk minikube helm kubernetes-cli)
  CMD_NAMES=(bazelisk minikube helm kubectl)
  # Step 1: Collect missing formulas based on absent commands
  to_install=()
  for i in "${!CMD_NAMES[@]}"; do
    cmd="${CMD_NAMES[$i]}"
    formula="${BREW_FORMULAS[$i]}"
    if ! command -v "$cmd" >/dev/null 2>&1; then
      to_install+=("$formula")
    fi
  done
  # Step 2: If there are missing formulas, ensure Homebrew exists and install.
  # Use homebrew so MacOS and Linux distributions are all supported.
  if [ ${#to_install[@]} -gt 0 ]; then
    if command -v brew >/dev/null 2>&1; then
      echo "The following formulas will be installed: ${to_install[*]}"
      brew install "${to_install[@]}"
    else
      echo "Homebrew not detected, and the following dependencies are missing: ${to_install[*]}"
      echo "Please install Homebrew first:"
      echo "Run the following installation command or follow instructions on https://brew.sh/"
      echo '/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'
      exit 1
    fi
  fi
  echo "Done."
}

install_dep_libs() {
  echo "====== Install dependent libs ======"
  if ! command -v apt-get >/dev/null 2>&1; then
    echo "Stop because apt-get is not detected. The following attestation-related dependencies require Debian/Ubuntu distribution."
    echo "Consider compiling without the attatation feature on non-Debian/Ubuntu OS distributions."
    exit 1
  fi
  $SUDO apt-get update && \
  $SUDO apt-get install -y libcurl4-openssl-dev libtss2-dev libsqlite3-dev libclang-dev pkg-config
  echo "Done."
}

install_dcap_libs() {
  echo "====== Install DCAP related libs ======"
  $SUDO apt-get install -y wget gnupg ca-certificates
  wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | $SUDO gpg --dearmor -o /usr/share/keyrings/intel-sgx.gpg
  echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | $SUDO tee /etc/apt/sources.list.d/intel-sgx.list
  $SUDO apt-get update && \
  $SUDO apt-get install -y libsgx-dcap-quote-verify-dev
  echo "Done."
}


PIPELINE=false
case " $* " in
  *" --pipeline "*|*" -p "*)
    PIPELINE=true
    ;;
esac

if [ "$PIPELINE" = true ]; then
  echo "Skip installing dependent tools for CI/CD pipelines as these are not required or pre-installed."
else
  install_brew_dependencies
fi
install_dep_libs
install_dcap_libs
