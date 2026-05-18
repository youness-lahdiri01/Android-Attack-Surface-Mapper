# ─── Stage 1: Build React frontend ─────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY client/package*.json ./client/
RUN cd client && npm ci --prefer-offline
COPY client/ ./client/
WORKDIR /app/client
RUN npm run build
# Output: /app/public-react/

# ─── Stage 2: Backend only ──────────────────────────────────────────────────
# Used in docker-compose.prod.yml — nginx serves the frontend separately.
# Does NOT depend on the builder stage, so React is not rebuilt here.
FROM node:20-alpine AS server
WORKDIR /app
ENV NODE_ENV=production
COPY package*.json ./
RUN npm ci --omit=dev --prefer-offline
COPY server/ ./server/
EXPOSE 3000
CMD ["node", "server/index.js"]

# ─── Stage 3: Standalone (default) ──────────────────────────────────────────
# Single-container deployment: Express serves the API + the React build.
# docker build . → docker run -p 3000:3000 <image>
FROM server AS standalone
COPY --from=builder /app/public-react ./public-react
