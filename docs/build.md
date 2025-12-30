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