# Test Deployment on Minikube

We also made it possible to deploy and test PVC without having any cloud account.
Our test deployment uses a local Minikube cluster with a few components that replaces cloud resources.
With this, users can quickly test and try PVC without having an actual TEE backend.

## Prerequisite

First, Install [Minikube CLI](https://minikube.sigs.k8s.io/docs/start/).

Then, create a minikube cluster with enough memory. We need larger memory because of the Kaniko jobs.

```
minikube start --memory=12192mb --cpus=16 --disk-size=50g --insecure-registry "10.0.0.0/24"
```

## Build Images

Now, build the images and load it into the Docker.
Minikube has its own Docker engine running inside the cluster.
Thus, we first need to point the local Docker client to the Docker engine inside minikube 

```
eval $(minikube docker-env)
bazel run //:load_all_images
```

## Setup Registry

The API requires artifact registry to store the TEE base image.
Thus, we use minikube's registry addon to host the image.

Enable the registry
```
minikube addons enable registry
```

RUN a proxy to connect to minikube registry and push executor image to minikube registry.
```
docker run --rm -it --network=host alpine ash -c "apk add socat && socat TCP-LISTEN:5000,reuseaddr,fork TCP:$(minikube ip):5000"
```

Open another terminal, and run

```
eval $(minikube docker-env)
image_name=(
    "pvc-ohttp-relay"
    "pvc-client"
    "pvc-identity-server"
    "pvc-ohttp-gateway"
    "pvc-tee-llm")
TAG="latest"
REGISTRY="localhost:5000"
for i in "${image_name[@]}"; do
  echo "Tagging $i:$TAG -> ${REGISTRY}/$i:$TAG"
  docker tag "$i:$TAG" "${REGISTRY}/$i:$TAG"
  echo "Pushing ${REGISTRY}/$i:$TAG"
  docker push "${REGISTRY}/$i:$TAG"
done
```

You can close the proxy after the docker push.

## Deploy

Deploy PVC to minikube.

```
pushd deployment/minikube
./deploy.sh
popd
```

## Check The Result
You can check the logs of client to make sure all the services working properly. The client pod is a job and it should be completed after several restarts. 
```
minikube kubectl get pods
kubectl port-forward --address 0.0.0.0 svc/pvc-client 8083:8083
```

Open `localhost:8083` in your browser to access the client application.

## Clean Up Deployment
```
helm delete private-verifiable-compute
```

## Clean Up MiniKube Cluster
```
minikube delete --purge
```
