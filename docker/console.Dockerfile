# The console, built from the repository root:  docker build -f docker/console.Dockerfile .
# Stages: deps installs packages, tools runs the setup scripts, build compiles, runtime serves.

FROM node:22-bookworm-slim AS deps
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Migrations, photo loading and first time setup. Used by the setup steps of every installation.
# The scripts need only the database client, at the exact version package.json pins, so the image stays small.
FROM node:22-bookworm-slim AS tools
WORKDIR /app/web
COPY web/package.json ./package.full.json
RUN node -e "const p = require('./package.full.json'); require('fs').writeFileSync('package.json', JSON.stringify({ name: 'htm-tools', private: true, dependencies: { postgres: p.dependencies.postgres } }))" \
 && npm install --ignore-scripts --no-audit --no-fund && npm cache clean --force && rm package.full.json
COPY web/scripts ./scripts
COPY web/seed ./seed
COPY supabase/migrations /app/supabase/migrations
RUN install -d -o node -g node -m 0755 /secrets
USER node
CMD ["node", "scripts/demo_setup.mjs"]

FROM deps AS build
COPY web/ ./
ENV NEXT_OUTPUT=standalone NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 HOSTNAME=0.0.0.0 PORT=3000
WORKDIR /app
# The application files belong to root, so the running console cannot change its own code.
COPY --from=build /app/web/.next/standalone ./
COPY --from=build /app/web/.next/static ./.next/static
COPY docker/env-entry.sh /usr/local/bin/env-entry
RUN mkdir -p .next/cache && chown node:node .next/cache
USER node
EXPOSE 3000
HEALTHCHECK --interval=5s --timeout=4s --start-period=20s --retries=12 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:3000/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
ENTRYPOINT ["/usr/local/bin/env-entry"]
CMD ["node", "server.js"]
