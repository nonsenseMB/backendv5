# Deployment Documentation Guide

## Deployment Strategies

### Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

# Build args
ARG BUILD_VERSION
ARG BUILD_DATE

# Labels
LABEL maintainer="team@example.com"
LABEL version="${BUILD_VERSION}"
LABEL build-date="${BUILD_DATE}"

# Environment
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Install dependencies
WORKDIR /app
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && \
    poetry config virtualenvs.create false && \
    poetry install --no-dev --no-interaction --no-ansi

# Copy application
COPY src/ ./src/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  backend:
    build: 
      context: .
      args:
        BUILD_VERSION: ${VERSION:-latest}
        BUILD_DATE: ${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/dbname
      - REDIS_URL=redis://redis:6379
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    ports:
      - "8000:8000"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_started
    restart: unless-stopped
    
  db:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=dbname
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user"]
      interval: 10s
      timeout: 5s
      retries: 5
      
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    volumes:
      - redis_data:/data

volumes:
  postgres_data:
  redis_data:
```

## Kubernetes Deployment

### Deployment Manifest

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nai-backend
  labels:
    app: nai-backend
    version: v5
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nai-backend
  template:
    metadata:
      labels:
        app: nai-backend
    spec:
      containers:
      - name: backend
        image: nai-backend:v5.0.0
        ports:
        - containerPort: 8000
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: nai-secrets
              key: database-url
        - name: REDIS_URL
          valueFrom:
            configMapKeyRef:
              name: nai-config
              key: redis-url
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

### Service Configuration

```yaml
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: nai-backend-service
spec:
  selector:
    app: nai-backend
  ports:
    - protocol: TCP
      port: 80
      targetPort: 8000
  type: LoadBalancer
```

## Environment Configuration

### Production Settings

```bash
# .env.production
# Database
DATABASE_URL=postgresql+asyncpg://prod_user:secure_pass@db.prod.internal:5432/nai_prod
DATABASE_POOL_SIZE=20
DATABASE_MAX_OVERFLOW=10

# Redis
REDIS_URL=redis://redis.prod.internal:6379/0
REDIS_MAX_CONNECTIONS=50

# Security
SECRET_KEY=<generated-secret-key>
ALLOWED_HOSTS=["api.nai.example.com"]
CORS_ORIGINS=["https://app.nai.example.com"]

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
LOG_FILE_PATH=/var/log/nai/backend.log
LOG_RETENTION_DAYS=90

# Performance
WORKERS=4
WORKER_CLASS=uvicorn.workers.UvicornWorker
WORKER_CONNECTIONS=1000
KEEPALIVE=5
```

### Staging Settings

```bash
# .env.staging
# Similar to production but with different endpoints
DATABASE_URL=postgresql+asyncpg://staging_user:pass@db.staging.internal:5432/nai_staging
LOG_LEVEL=DEBUG
```

## CI/CD Pipeline

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    tags:
      - 'v*'

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
        
      - name: Login to Registry
        uses: docker/login-action@v2
        with:
          registry: ${{ secrets.REGISTRY_URL }}
          username: ${{ secrets.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}
          
      - name: Build and push
        uses: docker/build-push-action@v4
        with:
          context: .
          push: true
          tags: |
            ${{ secrets.REGISTRY_URL }}/nai-backend:latest
            ${{ secrets.REGISTRY_URL }}/nai-backend:${{ github.ref_name }}
          cache-from: type=registry,ref=${{ secrets.REGISTRY_URL }}/nai-backend:buildcache
          cache-to: type=registry,ref=${{ secrets.REGISTRY_URL }}/nai-backend:buildcache,mode=max

  deploy:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Kubernetes
        uses: azure/k8s-deploy@v4
        with:
          manifests: |
            k8s/deployment.yaml
            k8s/service.yaml
          images: |
            ${{ secrets.REGISTRY_URL }}/nai-backend:${{ github.ref_name }}
```

## Monitoring Setup

### Prometheus Metrics

```python
# src/core/metrics.py
from prometheus_client import Counter, Histogram, Gauge

# Request metrics
request_count = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)

request_duration = Histogram(
    'http_request_duration_seconds',
    'HTTP request duration',
    ['method', 'endpoint']
)

# Business metrics
active_conversations = Gauge(
    'active_conversations_total',
    'Number of active conversations'
)

messages_processed = Counter(
    'messages_processed_total',
    'Total messages processed',
    ['model', 'status']
)
```

### Health Checks

```python
# src/api/health.py
from fastapi import APIRouter
from sqlalchemy import select

router = APIRouter()

@router.get("/health")
async def health_check():
    """Basic health check endpoint."""
    return {"status": "healthy"}

@router.get("/ready")
async def readiness_check(db: AsyncSession):
    """Readiness check including dependencies."""
    checks = {
        "database": False,
        "redis": False,
        "vector_store": False
    }
    
    # Check database
    try:
        await db.execute(select(1))
        checks["database"] = True
    except Exception:
        pass
    
    # Check Redis
    try:
        await redis.ping()
        checks["redis"] = True
    except Exception:
        pass
    
    # Check vector store
    try:
        vector_store.health_check()
        checks["vector_store"] = True
    except Exception:
        pass
    
    all_healthy = all(checks.values())
    return {
        "status": "ready" if all_healthy else "not ready",
        "checks": checks
    }
```

## Rollback Procedures

### Database Migrations

```bash
# Rollback last migration
alembic downgrade -1

# Rollback to specific revision
alembic downgrade abc123

# Show migration history
alembic history
```

### Kubernetes Rollback

```bash
# Check rollout history
kubectl rollout history deployment/nai-backend

# Rollback to previous version
kubectl rollback undo deployment/nai-backend

# Rollback to specific revision
kubectl rollout undo deployment/nai-backend --to-revision=2

# Monitor rollback
kubectl rollout status deployment/nai-backend
```

## Disaster Recovery

### Backup Strategy

```bash
# Database backup script
#!/bin/bash
# backup-db.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/postgres"
DB_NAME="nai_prod"

# Create backup
pg_dump $DATABASE_URL > "$BACKUP_DIR/backup_$DATE.sql"

# Compress
gzip "$BACKUP_DIR/backup_$DATE.sql"

# Upload to S3
aws s3 cp "$BACKUP_DIR/backup_$DATE.sql.gz" "s3://nai-backups/postgres/"

# Clean old local backups (keep last 7 days)
find $BACKUP_DIR -name "backup_*.sql.gz" -mtime +7 -delete
```

### Recovery Procedures

```bash
# Restore from backup
gunzip backup_20240120_120000.sql.gz
psql $DATABASE_URL < backup_20240120_120000.sql

# Verify data integrity
python scripts/verify_data_integrity.py
```