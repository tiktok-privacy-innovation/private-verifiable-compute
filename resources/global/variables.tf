/**
 * Copyright 2025 TikTok Inc. and/or its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

variable "region" {
  type        = string
  description = "Region to create the gcp resources"
  default     = "us-central1"
}

variable "zone" {
  type        = string
  description = "Zone to create the gcp resources"
  default     = "us-central1-a"
}

variable "project_id" {
  type        = string
  description = "The GCP project ID"
}

variable "gpu_machine_type" {
  description = "The gpu machine type to use for GKE nodes."
  type        = string
  default     = "a3-highgpu-1g"
}

variable "gpu_type" {
  description = "The type of GPU to attach to the nodes."
  type        = string
  default     = "nvidia-h100-80gb"
}

variable "gpu_count" {
  description = "The number of GPUs to attach to each node."
  type        = number
  default     = 1
}

variable "num_nodes" {
  type        = number
  description = "Number of nodes to create in the GKE cluster"
  default     = 1
}

variable "cpu_machine_type" {
  description = "The cpu machine type to use for GKE nodes."
  type        = string
  default     = "c3-highcpu-4"
}
