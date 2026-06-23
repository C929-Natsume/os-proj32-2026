# ---- Builder (deps) ----
FROM mcr.microsoft.com/devcontainers/javascript-node:20-bookworm AS deps
WORKDIR /app

# copy manifests (copy lock if present)
COPY package*.json ./

# install deps first (better cache); prefer npm ci if lockfile exists
RUN if [ -f package-lock.json ]; then \
    npm ci --no-audit --no-fund; \
    else \
    npm install --no-audit --no-fund; \
    fi

# ---- Build ----
FROM mcr.microsoft.com/devcontainers/javascript-node:20-bookworm AS builder
WORKDIR /app
ENV NODE_ENV=production

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# build-time vars for Next.js (public env must start with NEXT_PUBLIC_)
# Set defaults as needed; they can be overridden via --build-arg
ARG NEXT_PUBLIC_SQLOPT_SERVICE_URL
ARG EXTERNAL_BACKEND_URL
ARG NEXT_PUBLIC_DEFAULT_EMAIL
ARG NEXT_PUBLIC_DEFAULT_PASSWORD
ARG NEXT_PUBLIC_DEFAULT_NAME

ENV NEXT_PUBLIC_SQLOPT_SERVICE_URL=${NEXT_PUBLIC_SQLOPT_SERVICE_URL}
ENV EXTERNAL_BACKEND_URL=${EXTERNAL_BACKEND_URL}
ENV NEXT_PUBLIC_DEFAULT_EMAIL=${NEXT_PUBLIC_DEFAULT_EMAIL}
ENV NEXT_PUBLIC_DEFAULT_PASSWORD=${NEXT_PUBLIC_DEFAULT_PASSWORD}
ENV NEXT_PUBLIC_DEFAULT_NAME=${NEXT_PUBLIC_DEFAULT_NAME}

RUN npm run build

# ---- Runner ----
FROM mcr.microsoft.com/devcontainers/javascript-node:20-bookworm AS runner
WORKDIR /app
ENV NODE_ENV=production

## Create non-root user (Debian way) for security
RUN groupadd -r sqlopt && useradd -r -g sqlopt sqlopt

# Copy standalone output
# Next standalone build produces server files under .next/standalone
COPY --from=builder --chown=sqlopt:sqlopt /app/.next/standalone ./
# Public assets
COPY --from=builder --chown=sqlopt:sqlopt /app/public ./public
# Next static files
COPY --from=builder --chown=sqlopt:sqlopt /app/.next/static ./.next/static
# Optional: copy .env.example as base (real env should be provided at runtime)
# COPY --from=builder /app/.env.example ./.env

# Expose the Next.js default port
EXPOSE 3000

# Set runtime environment variables (can be overridden by docker run -e)
ENV PORT=3000
ENV HOSTNAME=0.0.0.0

USER sqlopt

# Run the Next standalone server
CMD ["node", "server.js"]
