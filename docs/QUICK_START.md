# nAI Backend Quick Start Guide

Get up and running with the nAI Backend in 5 minutes!

## Prerequisites

- Docker & Docker Compose installed
- Python 3.11+ (for local development)
- 4GB RAM minimum
- Port 8000 available

## 1. Clone & Setup (1 minute)

```bash
# Clone the repository
git clone https://github.com/your-org/nai-backend.git
cd nai-backend

# Copy environment file
cp .env.example .env
```

## 2. Start Services (2 minutes)

```bash
# Start all services with Docker Compose
docker-compose up -d

# Wait for services to be ready
docker-compose ps

# Check health
curl http://localhost:8000/health
```

## 3. Access the API (1 minute)

### Swagger UI

Open <http://localhost:8000/docs> in your browser

### Health Check

```bash
curl http://localhost:8000/api/v1/health/ready | python -m json.tool
```

## 4. Create Your First API Key (1 minute)

### Login (get a JWT token)

```bash
# Login with test credentials
TOKEN=$(curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin@example.com", "password": "admin123"}' \
  | jq -r '.access_token')
```

### Create API Key

```bash
# Create an API key
API_KEY=$(curl -X POST http://localhost:8000/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My First Key", "expires_in_days": 30}' \
  | jq -r '.key')

echo "Your API Key: $API_KEY"
```

## 5. Make Your First API Call

```bash
# Use the API key
curl http://localhost:8000/api/v1/auth/me \
  -H "Authorization: Bearer $API_KEY"
```

## What's Next?

### For Developers

1. **Set up local development**:

   ```bash
   # Install dependencies
   make install-dev

   # Run tests
   make test

   # Start dev server
   make dev
   ```

2. **Read the docs**:
   - [Developer Guide](./development/DEVELOPER_GUIDE.md)
   - [API Reference](./api/API_REFERENCE.md)
   - [Architecture Overview](./architecture/README.md)

### For DevOps

1. **Deploy to production**:
   - [Deployment Guide](./deployment/DEPLOYMENT_GUIDE.md)
   - [Security Hardening](./security/SECURITY_HARDENING.md)
   - [Monitoring Setup](./deployment/MONITORING.md)

2. **Configure services**:
   - Set up SSL/TLS
   - Configure backups
   - Set up monitoring

### For API Users

1. **Explore the API**:
   - Interactive docs: <http://localhost:8000/docs>
   - OpenAPI spec: <http://localhost:8000/openapi.json>
   - [API Reference](./api/API_REFERENCE.md)

2. **Client libraries**:

   ```python
   # Python example
   from nai_client import APIClient

   client = APIClient(api_key="your-api-key")
   user = await client.get_current_user()
   ```

## Common Commands

```bash
# Docker operations
docker-compose up -d        # Start services
docker-compose down         # Stop services
docker-compose logs -f app  # View logs

# Database
make db-upgrade            # Run migrations
make db-reset              # Reset database

# Development
make run                   # Run locally
make test                  # Run tests
make format                # Format code
make lint                  # Check code quality

# Build & Deploy
make docker-build          # Build Docker image
make docker-push           # Push to registry
```

## Troubleshooting

### Services won't start

```bash
# Check logs
docker-compose logs

# Ensure ports are free
lsof -i :8000
lsof -i :5432
lsof -i :6379
```

### Database connection errors

```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Test connection
docker exec -it postgres psql -U nai -d nai_db -c "SELECT 1;"
```

### API returns 401 Unauthorized

- Check your token/API key is valid
- Ensure Authorization header format: `Bearer <token>`
- Token may be expired - login again

## Support

- 📖 Documentation: [docs/README.md](./README.md)
- 🐛 Issues: [GitHub Issues](https://github.com/your-org/nai-backend/issues)
- 💬 Discord: [Join our community](https://discord.gg/your-invite)
- 📧 Email: <support@example.com>

---

**Ready to build something amazing? 🚀**
