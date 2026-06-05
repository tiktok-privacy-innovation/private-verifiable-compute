# Reproducible Container Image Builds

## Summary

Reproducible container image builds ensure that the same source inputs always produce identical container image artifacts. This property is critical for supply chain security, auditability, verifiability, provenance validation, deterministic CI/CD pipelines, and long term operational consistency.

Without reproducibility, identical source code may produce different image digests across build environments or build times. Such nondeterminism complicates debugging, weakens software supply chain guarantees, and makes independent verification difficult.

This document summarizes the lessons learned while enabling the PVC project to produce reproducible container images. It focuses on controlling all major sources of nondeterminism in container build pipelines, including timestamps, metadata generation, filesystem ordering, permissions, base image drift, and builder behavior.

## Goals

A reproducible container build system should guarantee:

1. Identical inputs produce identical image digests
2. Builds are stable across machines and CI systems
3. Independent parties can verify image integrity
4. Supply chain attestations remain auditable
5. Build outputs are deterministic over time

The target property is:

```text
Same source + same dependencies + same builder configuration
=
same OCI image digest
```

## Bazel OCI images (PVC services)

Production images for the five PVC runtimes are built with Bazel `rules_oci` targets, not per-service shell Dockerfiles.

| Service | Bazel target |
| ------- | ------------ |
| pvc-client | `//pvc-client:image_tarball` |
| pvc-identity-server | `//pvc-identity-server:image_tarball` |
| pvc-ohttp-relay | `//pvc-ohttp-relay:image_tarball` |
| pvc-ohttp-gateway | `//pvc-ohttp-gateway:image_tarball` |
| pvc-tee-llm | `//pvc-tee-llm:image_tarball` |

### Reproducible build profile

Set a fixed source timestamp and use the `reproducible` Bazel config:

```bash
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
export TZ=UTC LANG=C LC_ALL=C

bazel build --config=reproducible //all_image_tarballs
```

Workspace settings live in `.bazelrc` under `build:reproducible` (`--nostamp`, `SOURCE_DATE_EPOCH`, locale). Service `pkg_tar` layers use `portable_mtime` via `//tools:reproducible_oci.bzl`.


## Common Sources of Nondeterminism

Container builds are affected by many hidden entropy sources. Common nondeterministic inputs include:

| Category                | Examples                       |
| ----------------------- | ------------------------------ |
| Base image updates      | mutable tags                   |
| Build timestamps        | embedded current time          |
| File timestamps         | mtime changes                  |
| Filesystem metadata     | uid/gid, permissions           |
| Builder metadata        | provenance, SBOM               |
| Dependency drift        | floating package versions      |
| Toolchain versions      | compiler or builder changes    |
| Environment differences | locale, timezone               |

A reproducible pipeline must explicitly control each source.

## Core Reproducibility Requirements

### 1. Base Image Must Be Fixed

Using mutable tags introduces nondeterminism because the underlying image may change over time.

#### Problem

This is nondeterministic:

```dockerfile
FROM debian:12.13
```

The digest behind the tag may change.

#### Recommended Approach

Pin images by immutable digest:

```dockerfile
FROM debian@sha256:<digest>
```

Benefits:

* Immutable dependency graph
* Stable layer contents
* Verifiable provenance
* Consistent base package state

#### Additional Recommendations

* Mirror external images internally
* Maintain explicit image lock files
* Periodically rotate digests intentionally through controlled updates

### 2. SOURCE_DATE_EPOCH Must Be Fixed

`SOURCE_DATE_EPOCH` is the standard mechanism for deterministic build timestamps across ecosystems.

Many tools honor this variable automatically:

* tar
* gzip
* Go
* Rust
* OCI build tooling

#### Recommended Approach

Set a globally fixed timestamp or derive from Git:

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
```

#### Why This Matters

Without a fixed build timestamp:

* compiled binaries may differ
* archives differ
* layer metadata differs
* OCI image config timestamps differ


### 3. Dockerfile Contents Must Be Fixed

The Dockerfile itself is an input artifact.

Changing:

* command ordering
* whitespace in copied archives
* modification timestamps
* generated build scripts

may affect image output.

#### Recommended Approach

Ensure:

* Dockerfile contents are stable
* Generated Dockerfiles are deterministic

### 4. File Permissions and Timestamps Must Be Fixed

Filesystem metadata frequently causes nondeterministic image digests.

#### Common Problems

* inconsistent executable bits
* varying uid/gid ownership
* differing mtimes
* filesystem extraction differences

#### Recommended Approach

Normalize all metadata before build. Also keep permissions and ownership consistent.

#### Normalize Timestamps

```bash
find . -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
```

### 5. PVC Executable Files Must Be Fixed

The PVC executables are built from source. Compared with externally obtained artifacts, the PVC executables themselves are also an important source of nondeterminism.

#### Risks

* stale binaries
* implicit upgrades
* inconsistent toolchain state
* cache pollution
* timestamp propagation

#### Recommended Approach

To minimize potential sources of nondeterminism, we adopted a hermetic build system such as Bazel and recommend performing builds from scratch inside relatively fixed container images. In addition, we apply the following strategies:

* Lock versions for all tools
* Vendor dependency libraries
* Build with a clean cache
* Adopt hermetic build principles
* Store toolchains in immutable images

### 6. Disable Nondeterministic Metadata

Some builders automatically attach SBOMs and provenance data, which are non-deterministic by default.

#### Recommended Approach

Disable automatic provenance and SBOM generation during reproducible builds.

Example:

```bash
docker buildx build \
  --provenance=false
  --sbom=false
```

If SBOMs are required:

* generate them separately
* canonicalize ordering
* normalize timestamps
* version pin SBOM tooling

### 7. Builder and Output Mode Must Be Fixed

Different builders may produce different layer structures or metadata. Even different versions of the same builder may differ.

#### Recommended Approach

Fix:

* builder implementation
* builder version
* output format
* compression configuration

Example:

Ensure the builder version is pinned in CI.

```bash
docker buildx version
```

OCI and Docker formats may differ. Explicitly choose one:

```bash
--output=type=oci
```

### 8. Deterministic Dependency Resolution

Package managers frequently introduce nondeterminism.

#### Risks

* floating versions
* mirror drift
* transient registry state

#### Recommended Approach

Use lock files:

* Cargo.lock
* package-lock.json
* go.sum
* poetry.lock
* requirements.txt with hashes

Pin package repositories where possible.

### 9. Environment Normalization

Build environments should be standardized.

#### Recommended Variables

```bash
export TZ=UTC
export LANG=C
export LC_ALL=C
```

Avoid locale dependent sorting or formatting behavior.

## Validation Strategies

Reproducibility should be validated continuously across different machines and over time.

### Recommended Validation

Perform independent rebuilds:

```text
Build A -> image digest X
Build B -> image digest X
```

If digests differ:

* inspect layer digests
* compare tar contents
* compare metadata
* compare timestamps

## Recommended Best Practices Summary

| Area                  | Recommendation               |
| --------------------- | ---------------------------- |
| Base images           | Pin by digest                |
| SOURCE_DATE_EPOCH     | Fixed globally               |
| File timestamps       | Normalize                    |
| File permissions      | Normalize                    |
| Dockerfile timestamps | Normalize                    |
| PVC executables       | Immutable and version pinned |
| Provenance            | Disable or canonicalize      |
| SBOM                  | Disable or canonicalize      |
| Builder               | Version pinned               |
| Output format         | Explicit                     |
| Locale                | Fixed                        |
| Dependency versions   | Locked                       |
| Environment Variables | Normalize                    |

## Conclusion

Reproducible container image builds require strict control over every input that influences image generation. Achieving deterministic OCI artifacts is not the result of a single configuration flag. It requires coordinated normalization across:

* base images
* filesystem metadata
* timestamps
* builders
* dependency resolution
* archives
* metadata generation
* toolchains

Organizations that adopt reproducible build practices gain stronger software supply chain guarantees, improved auditability, better operational consistency, and significantly enhanced trust in released artifacts.
