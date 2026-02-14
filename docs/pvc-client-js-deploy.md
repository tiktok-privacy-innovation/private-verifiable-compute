# pvc-client-js static deployment and Nginx configuration

This document describes how to build the pvc-client-js static output, deploy it behind Nginx, and map the Vite dev proxy rules to Nginx in production.

## 1. Building static files

From the repo root or from `pvc-client-js`:

```bash
# from repo root
cd pvc-client-js
npm ci
npm run build
```

Output is written to **`pvc-client-js/dist/`**:

- `index.html` — Landing page
- `chat/index.html` — Chat Demo entry
- `assets/` — JS, CSS, WASM, etc.
- `landing.css` — Landing page styles (from `public/`)

## 2. Vite dev proxy vs production

In development, Vite’s `server.proxy` forwards the paths below to local services. In production, Nginx must perform the same forwarding.

| Frontend path           | Dev proxy target        | Production Nginx upstream (you configure) |
|-------------------------|-------------------------|-------------------------------------------|
| `/ohttp-gateway`        | `http://localhost:8082` | OHTTP Gateway                             |
| `/ohttp-relay`          | `http://localhost:8787` | OHTTP Relay                               |
| `/identity`             | `http://localhost:8000` | Identity Server                           |
| `/attestation-service`  | `http://localhost:8080` | Trustee Attestation service               |

These paths can be overridden at build time via environment variables (see **Environment variables** below).

## 3. Nginx configuration example

Serve `dist/` as the site root and reverse-proxy the four API paths to the corresponding backends.

**Option A: Dedicated server block (recommended)**

```nginx
# Upstream backends — change host/port to match your deployment
upstream ohttp_gateway { server localhost:8082; }
upstream ohttp_relay   { server localhost:8787; }
upstream identity      { server localhost:8000; }
# Attestation service: HTTP on port 80 (use https and :443 if your attestation is HTTPS)
upstream attestation   { server localhost:8080; }

server {
  listen 8888;
  listen [::]:8888;
  root /var/www/pvc-client-js;
  index index.html;

  # Static assets
  location / {
    try_files $uri $uri/ /index.html;
  }

  # Chat app: /chat/ → chat/index.html
  location /chat/ {
    try_files $uri $uri/ /chat/index.html;
  }

  # Proxy rules matching Vite: strip path prefix and forward to backend

  location /ohttp-gateway/ {
    proxy_pass http://ohttp_gateway/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }

  # Match both /ohttp-relay and /ohttp-relay/ (frontend uses /ohttp-relay without trailing slash)
  location /ohttp-relay {
    proxy_pass http://ohttp_relay/;
    proxy_http_version 1.1;
    proxy_set_header Host $proxy_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_pass_request_headers on;
    client_max_body_size 10m;
  }

  location /identity/ {
    proxy_pass http://identity/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }

  location /attestation-service/ {
    proxy_pass https://attestation/;
    proxy_http_version 1.1;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_connect_timeout 10s;
    proxy_read_timeout 30s;
  }
}
```

**Notes:**

- The trailing `/` in `proxy_pass http://ohttp_gateway/` strips the `/ohttp-gateway` prefix from the request URI when forwarding (same behavior as Vite’s `rewrite: path.replace(/^\/ohttp-gateway/, '')`). The same applies to the other locations.
- Keep `proxy_http_version 1.1;` if the backend uses HTTP/1.1 or WebSockets.

**Option B: Use the example file in the repo**

Copy the example config and adjust `root` and upstream `server` as needed:

```bash
cp pvc-client-js/nginx.conf.example /etc/nginx/sites-available/pvc-client-js
# Edit: set root and upstream server addresses
sudo ln -s /etc/nginx/sites-available/pvc-client-js /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 4. Environment variables (optional)

You can override the API base URLs used by the frontend at build time via Vite env vars:

| Variable                        | Default (relative)              | Description                    |
|---------------------------------|---------------------------------|--------------------------------|
| `VITE_IDENTITY_SERVER_URL`      | `/identity`                     | Identity server                |
| `VITE_OHTTP_GATEWAY_URL`       | `/ohttp-gateway`               | OHTTP Gateway                  |
| `VITE_OHTTP_RELAY_URL`         | `/ohttp-relay`                 | OHTTP Relay                    |
| `VITE_TARGET_SERVER_URL`       | `http://localhost:9000`        | Target TEE server (Chat)      |
| `VITE_ATTESTATION_SERVICE_URL` | `/attestation-service/attestation` | Trustee attestation service |
| `VITE_MODEL`                   | `Qwen/Qwen3-VL-4B-Thinking`    | Model name                     |

Example: build with absolute API URLs (frontend talks to backends directly; Nginx does not need to proxy these paths):

```bash
VITE_OHTTP_GATEWAY_URL=https://gateway.example.com \
VITE_OHTTP_RELAY_URL=https://relay.example.com \
VITE_IDENTITY_SERVER_URL=https://identity.example.com \
VITE_ATTESTATION_SERVICE_URL=https://attestation.example.com/attestation \
npm run build
```

If you keep relative paths (e.g. `/ohttp-gateway`), you must configure the Nginx reverse proxy as above.

## 5. Runtime config (set “env” at Nginx layer)

After building static JS, **build-time** `VITE_*` values are baked into the bundle. To change API URLs or model **per deployment without rebuilding**, the app loads **runtime config** from `/config.json` on startup.

**How it works:** The app fetches `GET /config.json` when it loads. If the file exists and is valid JSON, it overrides the built-in defaults. If the request fails (404 or timeout), built-in defaults are used.

**Nginx:** Ensure `/config.json` is served from the same `root` as the app (e.g. `dist/`). The file is copied from `public/config.json` when you run `npm run build`, so it will be at `dist/config.json`. To “set env at Nginx layer” for a given machine:

1. **Option A – static file:** After deploy, replace `dist/config.json` (or the file under your nginx `root`) with your environment-specific values. Nginx just serves it as a static file.
2. **Option B – different file per server:** Use a different `root` or `alias` per server so each server has its own `config.json` in that directory.
3. **Option C – generate at deploy:** In your deploy script, write `config.json` from env vars, e.g.  
   `echo '{"identityServerUrl":"/identity","ohttpGatewayUrl":"/ohttp-gateway",...}' > /var/www/pvc-client-js/config.json`

**config.json shape (all optional):**

```json
{
  "identityServerUrl": "/identity",
  "ohttpGatewayUrl": "/ohttp-gateway",
  "ohttpRelayUrl": "/ohttp-relay",
  "targetServerUrl": "http://localhost:9000",
  "attestationServiceUrl": "/attestation-service/attestation",
  "model": "Qwen/Qwen3-VL-4B-Thinking"
}
```

Use relative paths (e.g. `/ohttp-gateway`) when Nginx proxies those paths; use absolute URLs if the frontend talks to backends directly.

## 6. Summary

- **Build:** `cd pvc-client-js && npm run build`; output is in `dist/`.
- **Nginx:** Point `root` at `dist/`; use `try_files` for `/` and `/chat/`; reverse-proxy the API paths; serve `config.json` from the same root to override URLs/model at runtime (see §5).
- **Env vars:** Set `VITE_*` at build time for defaults, or use runtime `config.json` (same keys, no `VITE_` prefix) to override per deployment without rebuilding.
