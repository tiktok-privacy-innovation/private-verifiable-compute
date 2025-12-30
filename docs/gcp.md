# Deploy PVC on Google Cloud Platform

PVC can be simply deployed on Google Cloud Platform (GCP).

## Cloud Setup
* A valid GCP account that has ability to create/destroy resources.

## Tools
* [Gcloud CLI](https://cloud.google.com/sdk/docs/install) Login to the GCP
  `gcloud auth login && gcloud auth application-default login && gcloud
  components install gke-gcloud-auth-plugin`
* [Terraform](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
  Terraform is an infrastructure as code tool that enables you to safely and
  predictably provision and manage infrastructure in any cloud.
* [Helm](https://helm.sh/docs/intro/install/) Helm is a package manager for
  Kubernetes that allows developers and operators to more easily package,
  configure, and deploy applications and services onto Kubernetes clusters.

## Prepare env variables.
Fill in the correct values relevant to your project in the `.env` file. 
```
cp env.example .env
```

- `project_id` The unique identifier for your project across all of Google Cloud.
- `region` A specific geographical location where you can host your resources, e.g., `us-east5`.
- `zone` A deployment area within a region, e.g., `us-east5-a`.

Configure the `pccs_url` value in the `pvc-client/sgx_default_qcnl.conf` to a aviable Intel PCCS server address. 

## Create Resources

The resources are created and managed by the project administrator who has the
`Owner` role in the GCP project. Make sure you have correctly defined
environment variables in the `.env`. Only the project administrator is
responsible to run these commands to create resources.

`resources/global` directory contains the global resources including: clusters
and service accounts. 
> [!IMPORTANT]
> These resource are global and only created once by admin. For the developers
> in the project, you can start with the next step.

```
pushd resources/global
terraform apply
popd
```

`resources/deployment` directory includes the resources releated to kunernates
including: kubernetes namespace, role. These resources are created under
different namespace. So the namespace parameter is required, and you can create
different deployments under different namespaces.

```shell 
pushd resources/deployment
./apply.sh --namespace=<namespace-to-deploy>
popd
```

## Pushing Images

```shell 
gcloud auth configure-docker us-docker.pkg.dev # authenticate to artifact registry
source .env
bazel run //:push_all_images --action_env=namespace=<namespace-to-deploy> --action_env=project_id=$project_id
```

> [!IMPORTANT]
> the `--action_env=namespace=<namespace-to-deploy>` and `--action_env=project_id=$project_id` flags are required.

You can also push images separately by this command. Replace `<app>` by the
directory name  (e.g., pvc_tee_llm)

```
bazel run //:push_<app>_image --action_env=namespace=<namespace-to-deploy>
```

### Deploy
```
pushd deployment
./deploy.sh --namespace=<namespace-to-deploy>
popd
```