# ─── Stage 1: Build React frontend ─────────────────────────────────────────
FROM node:20-alpine AS builder
WORKDIR /app
COPY client/package*.json ./client/
RUN cd client && npm ci --prefer-offline
COPY client/ ./client/
WORKDIR /app/client
RUN npm run build
# Output: /app/public-react/

# ─── Stage 2: nginx with baked-in static assets ──────────────────────────────
FROM nginx:alpine
COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY --from=builder /app/public-react /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
