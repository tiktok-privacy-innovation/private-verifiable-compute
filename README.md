# Private Verifiable Compute: Enabling Private AI Processing

Private Verifiable Compute (PVC) enables users to initiate a request to a
private and verifiable environment for context-aware AI processing with
sensitive data, where no one - including service providers - can access them.
With PVC in the cloud (PVCCloud), it unleashes full potentials of AI hardware in
the data center for complex AI tasks, such as large language models (LLMs),
generative AI and beyond - while guaranteeing user privacy and verifiable
transparency.

> [!NOTE]
> Private Verifiable Compute is an ongoing research project
> and currently under active development.

## Design Goals

*Private Processing*
- Data security: PVC must apply comprehensive security practices to protect
  confidentiality and integrity of complete data lifecycle, including data at
  rest, data in transit and data in use.
- Privacy preserving: PVC must apply comprehensive privacy enhancing
  technologies to ensure traffic anonymity, while providing privacy-preserving
  debugability and operations.
- Enforcement guarantees: PVC must apply technical enforcement measures to
  uphold privacy and security guarantees by ensuring only authorized and
  cryptographically measured code and model can be loaded and executed.
- No privileged access: PVC must not contain privileged interfaces that might
  enable employees of service providers to access data.

*Private Storage*
- User-controlled key encryption. Context data stored in PVC must be
  encrypted by keys owned by individual users, but not accessible by service
  providers.

*Verfiable Transparency*
- Code transparency and assurance: Code in PVC must be transparent to
  third-party auditing and maintain the highest level of software supply chain
  assurance.
- Verifiable privacy: Privacy and security properties enforced in PVC should be
  automatically verified through program analysis techniques.
- Remote attestation: Code and its execution environment must be remotely attested
  and can be verified by data owners and third-party auditors independently.

## Getting Started

- [Build Private Verifiable Compute](docs/build.md)
- [Try PVC with Minikube](docs/minikube.md)
- [Deploy PVC on Google Cloud Platform](docs/gcp.md)

# License

Private Verifiable Compute is licensed under the Apache License, Version 2.0.
See [LICENSE](LICENSE) for details.
