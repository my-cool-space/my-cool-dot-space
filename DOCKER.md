# Docker Deployment Guide

This guide explains how to run my-cool.space using Docker.

## Prerequisites

- Docker installed on your system
- Docker Compose (usually comes with Docker Desktop)
- Environment variables configured (see `.env.example`)

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd my-cool-dot-space
cp .env.example .env
# Edit .env with your configuration
```

### 2. Build and Run

```bash
# Development mode
docker-compose up --build

# Production mode
docker-compose -f docker-compose.prod.yml up --build -d
```

### 3. Access the Application

- Application: http://localhost:3000
- Health Check: http://localhost:3000/api/status

## Docker Commands

### Build the Image

```bash
docker build -t my-cool-space .
```

### Run the Container

```bash
docker run -p 3000:3000 --env-file .env my-cool-space
```

### Development with Live Reload

```bash
# Mount source code for development
docker-compose up
```

### Production Deployment

```bash
# Run in production mode with resource limits
docker-compose -f docker-compose.prod.yml up -d
```

## Environment Variables

Create a `.env` file with the following variables:

```env
# Required
APPWRITE_ENDPOINT=https://your-appwrite-instance.com/v1
APPWRITE_PROJECT_ID=your-project-id
APPWRITE_DATABASE_ID=your-database-id
APPWRITE_COLLECTION_ID=your-collection-id
APPWRITE_API_KEY=your-api-key

DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret

SESSION_SECRET=your-super-secret-session-key

# Optional
PORKBUN_API_KEY=your-porkbun-api-key
PORKBUN_SECRET_KEY=your-porkbun-secret-key
MAINTENANCE_MODE=false
NODE_ENV=production
PORT=3000
```

## Health Checks

The Docker container includes built-in health checks:

```bash
# Check container health
docker ps
# Look for "healthy" status

# Manual health check
curl http://localhost:3000/api/status
```

## Logs

```bash
# View logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f app
```

## Scaling

```bash
# Scale the application
docker-compose up --scale app=3
```

## Troubleshooting

### Container Won't Start

1. Check environment variables in `.env`
2. Verify all required services (Appwrite, Discord) are accessible
3. Check logs: `docker-compose logs`

### Health Check Failing

1. Verify the application is responding on port 3000
2. Check if required environment variables are set
3. Ensure Appwrite and Discord services are reachable

### Build Issues

```bash
# Clean build
docker-compose down
docker system prune -f
docker-compose build --no-cache
docker-compose up
```

## Security Notes

- The container runs as a non-root user (`appuser`)
- Environment variables should be kept secure
- Use Docker secrets in production environments
- Keep the base image updated regularly

## Production Deployment

For production deployment:

1. Use `docker-compose.prod.yml`
2. Set up proper SSL/TLS termination (nginx, traefik, etc.)
3. Configure proper logging
4. Set up monitoring and alerts
5. Use Docker secrets for sensitive data
6. Regular security updates

```bash
# Production deployment
docker-compose -f docker-compose.prod.yml up -d

# Update in production
docker-compose -f docker-compose.prod.yml pull
docker-compose -f docker-compose.prod.yml up -d
```

## Backup and Maintenance

```bash
# Backup volumes (if any)
docker run --rm -v my-cool-space_data:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz /data

# Update containers
docker-compose pull
docker-compose up -d

# Clean up unused resources
docker system prune -f
```
