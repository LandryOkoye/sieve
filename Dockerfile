FROM node:24-alpine

ENV API_PORT=3001
WORKDIR /app

RUN corepack enable
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/api/package.json ./apps/api/package.json
COPY packages/contracts/package.json ./packages/contracts/package.json
COPY packages/detector/package.json ./packages/detector/package.json
COPY packages/chain-sui/package.json ./packages/chain-sui/package.json
COPY packages/evaluation/package.json ./packages/evaluation/package.json
COPY packages/threat-memory/package.json ./packages/threat-memory/package.json
RUN pnpm install --frozen-lockfile

COPY --chown=node:node apps/api ./apps/api
COPY --chown=node:node packages ./packages
COPY --chown=node:node db ./db
COPY --chown=node:node scripts ./scripts
USER node

EXPOSE 3001
CMD ["./apps/api/node_modules/.bin/tsx", "apps/api/src/server.ts"]
