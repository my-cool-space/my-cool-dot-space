#!/bin/bash

# Production deployment script for my-cool.space
# Usage: ./deploy-production.sh

set -e

echo "🚀 Starting production deployment for my-cool.space..."

# Configuration
COMPOSE_FILE="docker-compose.prod.yml"
ENV_FILE=".env.production"
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed!"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed!"
        exit 1
    fi
    
    if [ ! -f "$ENV_FILE" ]; then
        print_error "Production environment file ($ENV_FILE) not found!"
        print_warning "Please copy .env.production.example to $ENV_FILE and configure it."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Backup current deployment
backup_deployment() {
    print_status "Creating backup..."
    
    mkdir -p "$BACKUP_DIR"
    
    # Backup environment file
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "$BACKUP_DIR/"
    fi
    
    # Backup docker-compose file
    if [ -f "$COMPOSE_FILE" ]; then
        cp "$COMPOSE_FILE" "$BACKUP_DIR/"
    fi
    
    # Export current container data if running
    if docker-compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
        print_status "Exporting current container logs..."
        docker-compose -f "$COMPOSE_FILE" logs > "$BACKUP_DIR/container_logs.txt" 2>&1 || true
    fi
    
    print_success "Backup created in $BACKUP_DIR"
}

# Build and deploy
deploy() {
    print_status "Building production images..."
    
    # Build with no cache for production
    docker-compose -f "$COMPOSE_FILE" build --no-cache
    
    print_status "Stopping existing containers..."
    docker-compose -f "$COMPOSE_FILE" down --remove-orphans
    
    print_status "Starting production deployment..."
    docker-compose -f "$COMPOSE_FILE" up -d
    
    print_status "Waiting for services to be ready..."
    sleep 10
    
    # Health check
    print_status "Performing health checks..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker-compose -f "$COMPOSE_FILE" ps | grep -q "healthy\|Up"; then
            if curl -f http://localhost:3000/api/status &>/dev/null; then
                print_success "Application is healthy and responding!"
                break
            fi
        fi
        
        print_status "Health check attempt $attempt/$max_attempts..."
        sleep 10
        ((attempt++))
    done
    
    if [ $attempt -gt $max_attempts ]; then
        print_error "Health check failed after $max_attempts attempts"
        print_status "Checking container logs..."
        docker-compose -f "$COMPOSE_FILE" logs --tail=50
        exit 1
    fi
}

# Security checks
security_checks() {
    print_status "Performing security checks..."
    
    # Check for default secrets
    if grep -q "CHANGE_THIS" "$ENV_FILE"; then
        print_warning "Default secrets detected in $ENV_FILE"
        print_warning "Please update all CHANGE_THIS values before deploying to production"
    fi
    
    # Check NODE_ENV
    if ! grep -q "NODE_ENV=production" "$ENV_FILE"; then
        print_warning "NODE_ENV is not set to production in $ENV_FILE"
    fi
    
    # Check SSL configuration
    if ! grep -q "SECURE_COOKIES=true" "$ENV_FILE"; then
        print_warning "SECURE_COOKIES is not enabled in $ENV_FILE"
    fi
    
    print_success "Security checks completed"
}

# Cleanup old images and containers
cleanup() {
    print_status "Cleaning up old Docker resources..."
    
    # Remove unused images
    docker image prune -f
    
    # Remove unused volumes (be careful with this in production)
    # docker volume prune -f
    
    print_success "Cleanup completed"
}

# Show deployment status
show_status() {
    print_status "Deployment Status:"
    echo "===================="
    
    docker-compose -f "$COMPOSE_FILE" ps
    
    echo ""
    print_status "Application URLs:"
    echo "Health Check: http://localhost:3000/api/status"
    echo "Application: http://localhost:3000"
    
    echo ""
    print_status "Useful Commands:"
    echo "View logs: docker-compose -f $COMPOSE_FILE logs -f"
    echo "Stop services: docker-compose -f $COMPOSE_FILE down"
    echo "Restart services: docker-compose -f $COMPOSE_FILE restart"
    echo "Shell access: docker-compose -f $COMPOSE_FILE exec app sh"
}

# Main deployment process
main() {
    echo "=========================================="
    echo "🌟 my-cool.space Production Deployment"
    echo "=========================================="
    
    check_prerequisites
    security_checks
    backup_deployment
    deploy
    cleanup
    show_status
    
    echo ""
    print_success "🎉 Production deployment completed successfully!"
    print_status "Monitor the application logs with: docker-compose -f $COMPOSE_FILE logs -f"
}

# Run main function
main "$@"
