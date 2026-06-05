# Build PVC

Install depdencies.
```
./scripts/install_dev_dependencies.sh
```

Build the project with Bazel.
```
bazel build //...
```

Load images to local image repoisitory.
```
bazel run //:load_all_images
```

## Reproducible Build

See [reproducibility.md](reproducibility.md) for background information.

To build the service container images reproducibly:

```bash
# Step 1:
# Build the builder image. This provides a stable compilation
# environment for the remaining build steps.
scripts/build_pvc_builder_image.sh

# Step 2:
# Build the PVC container images inside the builder container.
# Bazel cache files are stored under:
#   ${REPO_ROOT}/.pvc-bazel-cache
scripts/reproducible_build.sh

# Step 3:
# Load the generated image tarballs into the local Docker daemon.
# This step runs completely outside the container.
scripts/load_reproducible_images.sh
```
