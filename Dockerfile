FROM node:22-alpine AS deps
WORKDIR /app

# Only copy files needed to resolve dependencies
COPY package.json package-lock.json* ./
# If you have a lockfile, npm ci is best; otherwise fallback to npm install
RUN if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi

FROM node:22-alpine
WORKDIR /app

# Install tini (defensive init) and curl (for HEALTHCHECK)
RUN apk add --no-cache tini curl

# Security: do not run as root
USER node

# Environment
ENV NODE_ENV=production \
    PORT=3000 \
    # Allow overriding the YAML path at runtime if desired
    CONFIG_PATH=/app/config/config.yml

# Create expected dirs (no secrets baked in; mount at runtime)
RUN mkdir -p /app/config /app/certs /app/src
# Ensure node owns them
RUN chown -R node:node /app

# Bring in application code (but NOT config/certs)
COPY --chown=node:node src/ ./src/
COPY --chown=node:node package.json README.md ./

# Bring in node_modules from build stage
COPY --from=deps /app/node_modules ./node_modules

# Healthcheck: hits the root which your app already serves
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:${PORT}/ || exit 1

EXPOSE 3000

# Use tini as PID 1 to handle signals/reaping
ENTRYPOINT ["/sbin/tini","--"]

# Read-only filesystem is recommended at runtime (set via `docker run`/Compose)
CMD ["node","src/server.js"]
