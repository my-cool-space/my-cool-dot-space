# Multi-stage build for production optimization
FROM node:18-alpine AS builder

# Set working directory
WORKDIR /app

# Install build dependencies and security updates
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Copy package files
COPY package*.json ./

# Install ALL dependencies (including devDependencies for build)
# Use npm install if package-lock.json doesn't exist, otherwise use npm ci
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm cache clean --force

# Copy source code
COPY . .

# Build Tailwind CSS for production
RUN npm run build:prod

# Production stage
FROM node:18-alpine AS production

# Install security updates and dumb-init for proper signal handling
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create app directory
WORKDIR /app

# Create non-root user with specific UID/GID for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S appuser -u 1001 -G nodejs

# Copy package files
COPY package*.json ./

# Install only production dependencies with security optimizations
# Use npm install if package-lock.json doesn't exist, otherwise use npm ci
RUN if [ -f package-lock.json ]; then npm ci --omit=dev --no-audit --no-fund; else npm install --only=production --no-audit --no-fund; fi && \
    npm cache clean --force && \
    rm -rf ~/.npm

# Copy built application from builder stage
COPY --from=builder --chown=appuser:nodejs /app/public/style.css ./public/style.css
COPY --chown=appuser:nodejs . .

# Remove development files and sensitive information
RUN rm -rf node_modules/.cache && \
    rm -rf .git && \
    rm -rf .env.example && \
    rm -rf *.md && \
    rm -rf Dockerfile* && \
    rm -rf docker-compose*.yml

# Create necessary directories and set proper permissions
RUN mkdir -p /app/logs /app/tmp && \
    chown -R appuser:nodejs /app && \
    chmod -R 755 /app && \
    chmod -R 777 /app/logs /app/tmp

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 3000

# Set production environment variables
ENV NODE_ENV=production
ENV PORT=3000
ENV NPM_CONFIG_LOGLEVEL=warn
ENV NODE_OPTIONS="--max-old-space-size=512"

# Add comprehensive health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e " \
    const http = require('http'); \
    const options = { \
      hostname: 'localhost', \
      port: 3000, \
      path: '/api/status', \
      timeout: 8000 \
    }; \
    const req = http.request(options, (res) => { \
      process.exit(res.statusCode === 200 ? 0 : 1); \
    }); \
    req.on('error', () => process.exit(1)); \
    req.on('timeout', () => process.exit(1)); \
    req.end();"

# Use dumb-init for proper signal handling and zombie reaping
ENTRYPOINT ["dumb-init", "--"]

# Start the application with production optimizations
CMD ["node", "app.js"]
