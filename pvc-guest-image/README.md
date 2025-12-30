
# PVC Confidential VM Image

This module provides a customized confidential VM image for security hardening, built with **Bazel**. And deployed on **Google Cloud Build** for integration and delivery.

---

## Prerequisites

Before you start, make sure you have the following installed:

- [Bazel](https://bazel.build/)
- [Gcloud](https://cloud.google.com/sdk/docs/install)

Check versions:
```bash
  bazel version
  gcloud version
```

# How to Run

## Local Build & Unit Test

### Linux(default)

```bash
  bazel build image/...
```

### macOS(x86_64)

```bash
  bazel build image/... --define platform=macos
```

## GCP Cloud Build

```bash
  gcloud builds submit .
```
