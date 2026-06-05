# PVC CLI

`pvc-cli` is a standalone Rust command-line client for Private Verifiable Compute. It reuses the existing PVC protocol flow for login, chat, document upload, and local session management.

## Build

Build the CLI from the workspace root:

```bash
cargo build -p pvc-cli
```

## Commands

### Login

Use `login` to configure endpoints, bootstrap a PVC session, and save local state for later commands.

```bash
cargo run -p pvc-cli -- login --token-env-var PVC_TOKEN
```

You can also provide the token directly or through stdin:

```bash
cargo run -p pvc-cli -- login --token "$PVC_TOKEN"
printf '%s' "$PVC_TOKEN" | cargo run -p pvc-cli -- login --token-stdin
```

Optional endpoint overrides:

```bash
cargo run -p pvc-cli -- login \
  --identity-server-url http://localhost:8000 \
  --gateway-url http://localhost:8082 \
  --relay-url http://localhost:8787 \
  --target-url localhost:9000 \
  --token-env-var PVC_TOKEN
```

### Attest

Verify the target server attestation and print the verified claims derived from the normalized attestation contract:

```bash
cargo run -p pvc-cli -- attest
```

Emit structured JSON output:

```bash
cargo run -p pvc-cli -- attest --output json
```

Provide endpoint overrides for a different target:

```bash
cargo run -p pvc-cli -- attest \
  --identity-server-url http://localhost:8000 \
  --gateway-url http://localhost:8082 \
  --relay-url http://localhost:8787 \
  --target-url localhost:9000
```

Provide an explicit base64 nonce to verify the `/v1/attestation` path:

```bash
cargo run -p pvc-cli -- attest --nonce <base64> --output json
```

When `--nonce` is omitted, the CLI uses the authenticated handshake flow and prints the verified claim set produced by the normalized handshake contract. When `--nonce` is provided, it exercises the explicit `/v1/attestation` contract, which expects a JSON request containing a base64-encoded 64-byte nonce.

On Minikube or other non-TEE environments, this command can still succeed if the server falls back to sample attestation evidence.

### Chat

Run `pvc-cli chat` with no prompt arguments to start an interactive conversation loop in the terminal:

```bash
cargo run -p pvc-cli -- chat
```

Type prompts, press Enter to send them, and use `exit` or `quit` to leave the session.

Send a single prompt through the saved PVC session and stream the response to stdout:

```bash
cargo run -p pvc-cli -- chat --prompt "Hello"
```

Read a single prompt from stdin:

```bash
printf 'Hello from stdin' | cargo run -p pvc-cli -- chat --prompt-stdin
```

Emit JSON output instead of human-readable terminal output:

```bash
cargo run -p pvc-cli -- chat --prompt "Hello" --output json
```

### Upload

Upload a local text file through the PVC document API:

```bash
cargo run -p pvc-cli -- upload path/to/file.txt
```

### Session

Inspect or clear the saved CLI session state:

```bash
cargo run -p pvc-cli -- session show
cargo run -p pvc-cli -- session show --output json
cargo run -p pvc-cli -- session clear
```

## Local state

`pvc-cli` stores its profile and session state under `~/.pvc/cli/`.

- `profile.json` stores endpoint configuration.
- `session.json` stores the active session metadata and redacted auth state.

Run `pvc-cli login` before using `attest`, `chat`, `upload`, or `session show`.

## Current limitations

- Interactive login is not supported yet; use `--token`, `--token-env-var`, or `--token-stdin`.
- The upload command uses best-effort whole-file reads for local text files; large-file streaming or chunked upload is out of scope for the initial version.
- The CLI depends on reachable PVC identity, relay, gateway, and target endpoints.
