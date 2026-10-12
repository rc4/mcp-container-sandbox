FROM --platform=linux/amd64 node:24-bookworm-slim
COPY --from=docker.io/cloudflare/sandbox:1.0.0 /usr/local/bin/sandbox-shim /usr/local/bin/sandbox-shim
COPY webhook.js /opt/webhook.mjs
CMD ["sleep", "infinity"]
