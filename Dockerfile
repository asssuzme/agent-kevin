FROM node:20-alpine

WORKDIR /app

# Install deps first for better caching
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev --silent

# Copy app source
COPY src ./src
COPY public ./public
COPY scripts ./scripts

# Ensure reports dir exists (writes happen at runtime — ephemeral on App Runner, that's fine)
RUN mkdir -p reports

EXPOSE 3000

# Health check — App Runner uses HTTP path /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -O - http://localhost:3000/healthz || exit 1

CMD ["node", "src/server.js"]
