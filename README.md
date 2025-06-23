# nAI Backend - Enterprise LLM Platform

## 🎯 Project Vision

Eine vollständig tenant-isolierte Enterprise-Plattform für KI-gestützte Zusammenarbeit, die es Unternehmen ermöglicht, maßgeschneiderte LLM-Workflows zu erstellen und nahtlos in ihre bestehende IT-Infrastruktur zu integrieren.

## 🏗️ Kernprinzipien

1. **100% Multi-Tenant Isolation**
   - Keine gemeinsam genutzten Ressourcen
   - Vollständige Datentrennung auf allen Ebenen
   - Tenant-spezifische Verschlüsselung

2. **Enterprise-First Design**
   - Integration mit SharePoint, Office 365, Google Workspace
   - Unternehmens-Compliance und Audit-Trails (Datenschutz, DSGVO)
   - On-Premise Deployment möglich

3. **Zero Configuration Files**
   - Alle Konfigurationen in der Datenbank
   - Verschlüsselte Secrets mit Tenant-spezifischem Salt
   - Versionierte Konfigurationsänderungen

4. **Flexible Berechtigungen**
   - Rollenbasierte Zugriffskontrolle (RBAC)
   - Team-basierte Kollaboration
   - Dynamische Berechtigungsprüfung für Datenquellen

## 🚀 Quick Start

### Prerequisites

- Python 3.11
- Conda
- PostgreSQL
- Redis
- Docker (optional)

### Setup

1. **Environment Setup**
   ```bash
   # Environment is already created at ./env
   conda activate ./env
   ```

2. **Install Dependencies**
   ```bash
   poetry install
   ```

3. **Environment Variables**
   Create a `.env` file based on `.env.example`:
   ```
   DATABASE_URL=postgresql+asyncpg://user:password@localhost/dbname
   REDIS_URL=redis://localhost:6379
   SECRET_KEY=your-secret-key
   ```

4. **Database Migrations**
   ```bash
   alembic upgrade head
   ```

5. **Run Application**
   ```bash
   make run
   # or
   uvicorn src.main:app --reload
   ```

## 🔧 Technische Architektur

### Project Structure

```
.
├── src/                    # Source code
│   ├── api/               # API endpoints and middleware
│   │   ├── v1/           # API Version 1
│   │   ├── middleware/   # Auth, logging, audit middleware
│   │   └── schemas/      # Pydantic schemas
│   ├── application/       # Application services
│   ├── core/             # Core utilities
│   │   ├── auth/        # JWT, OAuth2, API Keys
│   │   ├── audit/       # Audit logging
│   │   ├── logging/     # Structured logging
│   │   └── tracing/     # OpenTelemetry
│   ├── domain/           # Domain models & business logic
│   │   ├── tenant/      # Multi-tenant models
│   │   ├── teams/       # Team collaboration
│   │   ├── flows/       # LangGraph workflows
│   │   └── memory/      # Memory systems
│   ├── infrastructure/   # External services
│   │   ├── database/    # PostgreSQL repositories
│   │   ├── cache/       # Redis caching
│   │   ├── vectors/     # Milvus vector storage
│   │   └── llm/         # LLM providers
│   └── services/         # Business logic implementation
├── tests/                # Test suite
├── alembic/             # Database migrations
├── docs/                # Documentation
└── scripts/             # Utility scripts
```

### Tech Stack

- **Framework**: FastAPI
- **Database**: PostgreSQL with AsyncPG
- **Cache**: Redis
- **Vector Store**: Milvus
- **LLM Orchestration**: LangGraph
- **Authentication**: OAuth2, JWT, API Keys
- **Monitoring**: OpenTelemetry
- **Testing**: Pytest with async support

## 👥 Nutzerrollen & Hierarchie

### Rollen-Struktur
```
Tenant
├── Admin (Vollzugriff, Nutzerverwaltung, Billing)
├── Moderator
│   ├── Flow-Erstellung und -Verwaltung
│   ├── Tool-Konfiguration
│   ├── Zentrale Informationsbereitstellung
│   └── Nutzergruppen-Management
├── Team Owner
│   ├── Team-Verwaltung
│   ├── Team-Ressourcen
│   └── Team-spezifische Flows
├── Team Member
│   ├── Team-Ressourcen nutzen
│   └── Team-Chats
└── User
    ├── Persönliche Chats
    ├── Zugewiesene Flows nutzen
    └── Persönlicher Speicher
```

## 🎯 Hauptanwendungsfälle

### Für Endnutzer
1. **Persönlicher KI-Assistent**
   - Fragen zu Unternehmensdaten
   - Dokumentenerstellung
   - Datenanalyse

2. **Team-Kollaboration**
   - Gemeinsame Projekt-Chats
   - Geteilte Wissensbasis
   - Koordinierte Workflows

### Für Moderatoren
1. **Flow-Management**
   - Workflow-Erstellung ohne Code
   - Tool-Integration
   - Berechtigungsverwaltung

2. **Wissensmanagement**
   - Zentrale Knowledge Bases
   - Nutzergruppen-spezifische Inhalte
   - Qualitätssicherung

## 🔧 Development

### Available Commands

```bash
make help          # Show all available commands
make dev-install   # Install all dependencies
make test          # Run tests
make lint          # Run linter
make format        # Format code
make type-check    # Run type checker
make clean         # Clean cache files
make run           # Run the application
make migrate       # Run database migrations
```

### API Documentation

Once the application is running, visit:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

### Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/unit/test_auth.py
```

## 🚀 Deployment

### Docker

```bash
docker build -t nai-backend .
docker run -p 8000:8000 --env-file .env nai-backend
```

### Production

See [DEPLOYMENT.md](docs/deployment/DEPLOYMENT_GUIDE.md) for production deployment guidelines.

## 🔒 Security

- Multi-tenant isolation at all levels
- Encrypted secrets with tenant-specific salt
- Row-level security in PostgreSQL
- API rate limiting
- Comprehensive audit logging

## 📊 Monitoring

- OpenTelemetry integration
- Structured JSON logging
- Performance metrics
- Health endpoints

## 🤝 Contributing

Please read our contributing guidelines before submitting PRs.

## 📄 License

Proprietary - All rights reserved