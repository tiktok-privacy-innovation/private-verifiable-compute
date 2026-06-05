# Test Deployment on Minikube

We also made it possible to deploy and test PVC without having any cloud account.
Our test deployment uses a local Minikube cluster with a few components that replaces cloud resources.
With this, users can quickly test and try PVC without having an actual TEE backend.

## Prerequisite

First, Install [Minikube CLI](https://minikube.sigs.k8s.io/docs/start/).

Then, create a minikube cluster with enough memory.

```
minikube start --memory=12192mb --cpus=16 --disk-size=50g
```

## Build Images

Now, build the images and load them directly into minikube's Docker engine.
Minikube has its own Docker engine running inside the cluster, so we point the
local Docker client at it before building. The deploy script references each
image by its short local name (for example, `pvc-tee-llm:latest`) and sets
`image.pullPolicy=IfNotPresent` for every component, so the images only need to
be present in minikube's Docker daemon — no registry is required.

```
eval $(minikube docker-env)
bazel run //:load_all_images
```

## Deploy

Deploy PVC to minikube.

```
./deployment/deploy.sh --platform=minikube
```

To preview the rendered release without applying changes:

```
./deployment/deploy.sh --platform=minikube --dry-run
```

`--dry-run` does not apply changes, but it still talks to Helm and the current cluster context.

## Check The Result
You can check the logs of client to make sure all the services working properly. The client pod is a job and it should be completed after several restarts. 
```
minikube kubectl get pods
kubectl port-forward --address 0.0.0.0 svc/pvc-client 8083:8083
```

Open `localhost:8083` in your browser to access the client application.

## Sample Attestation

Minikube has neither Intel TDX nor a CC-enabled NVIDIA Hopper GPU, so
`pvc-tee-llm` cannot produce real attestation evidence. The minikube
overlay (`deployment/envs/minikube.yaml`) sets `teeLlm.sampleAttestation:
true`, which causes the chart to inject `ENABLE_SAMPLE_DEVICE=1` on the
`pvc-tee-server` container. This opts the upstream attester crate into its
`Tee::SampleDevice` fallback. The CPU side already falls back to
`Tee::Sample` automatically when no TDX is detected. Both sample
verifiers ship with `common/pvc-client-core` and validate the evidence
end-to-end without contacting Intel PCS or NVIDIA NRAS, so
`/v1/attestation` and `/api/attestation` return real CPU + device claims
on minikube. **Never enable `sampleAttestation` on the GKE or kata
overlays.**

## Clean Up Deployment
```
helm delete private-verifiable-compute
```

## Clean Up MiniKube Cluster
```
minikube delete --purge
```
