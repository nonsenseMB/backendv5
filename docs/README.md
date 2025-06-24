# nAI Backend - Enterprise LLM Platform Documentation

Welcome to the nAI Backend documentation! This platform enables enterprises to build and deploy custom LLM-powered workflows with full multi-tenant isolation.

## 🎯 Project Overview

nAI Backend is an enterprise-ready platform for creating AI-powered applications using LangGraph workflows, with seamless integration into existing corporate infrastructure (SharePoint, Office 365, Google Workspace).

**Key Features:**
- 🤖 **LangGraph-based AI Workflows** - Build complex agent systems without code
- 👥 **Team Collaboration** - Shared workspaces and knowledge bases
- 🏢 **Enterprise Integration** - SharePoint, O365, Google Workspace
- 🔒 **100% Multi-Tenant** - Complete data isolation per tenant
- 🛡️ **Security First** - Enterprise-grade security and compliance

## 🚀 Quick Start

1. **Understanding the Vision** → Start with [PROJECT_VISION.md](../PROJECT_VISION.md)
2. **Development Roadmap** → See [FEATURE_ROADMAP.md](../FEATURE_ROADMAP.md)
3. **Quick Implementation** → Check [QUICK_WINS.md](../QUICK_WINS.md)
4. **Development Tasks** → Review [DEVELOPMENT_HIERARCHY.md](../DEVELOPMENT_HIERARCHY.md)

## 📚 Documentation Structure

### Core Guides

- **[Setup Checklist](./SETUP_CHECKLIST.md)** - Get started quickly ⭐
- **[Team Guide](./TeamGuide.md)** - Development processes and workflows
- **[Documentation Guide](./DocumentationGuide.md)** - How to write documentation

### Technical Documentation

- **[Architecture](./architecture/)** - System design and decisions
  - [Decisions (ADRs)](./architecture/decisions/) - Architecture decision records
  - [Diagrams](./architecture/diagrams/) - System diagrams

- **[API](./api/)** - API documentation
  - [API Reference](./api/API_REFERENCE.md) - Complete API documentation ⭐
  - [API Documentation](./api/API_DOCUMENTATION.md) - Implemented endpoints
  - [OpenAPI Spec](./api/openapi.yaml) - Machine-readable API specification
  - [Authentication](./api/authentication/) - Auth flows and security
  - [Endpoints](./api/endpoints/) - REST API reference
  - [Examples](./api/examples/) - Code examples

- **[Features](./features/)** - Feature-specific documentation
  - [Authentication](./features/authentication/) - Auth system
  - [Team Management](./features/team-management/) - Teams and collaboration ⭐
  - [Logging](./features/logging/) - Structured logging with GDPR compliance
  - [Chat](./features/chat/) - Chat functionality
  - [Memory](./features/memory/) - Vector memory system
  - [Agents](./features/agents/) - AI agent system

### Development & Operations

- **[Development](./development/)** - Developer resources
  - [Developer Guide](./development/DEVELOPER_GUIDE.md) - Complete development reference ⭐
  - [Code Quality Guide](./development/code-quality-guide.md) - Linting, formatting, testing
  - [Python 3.13 Features](./development/python-3.13-features.md) - New Python features guide
  - [Sprint Planning](./development/sprint-planning/) - Development sprints
  - [Status Updates](./development/status-updates/) - Sprint progress

- **[Deployment](./deployment/)** - Deployment guides
  - [Deployment Guide](./deployment/DEPLOYMENT_GUIDE.md) - Production deployment ⭐
  - [Docker Setup](./deployment/docker.md) - Complete Docker guide
  - Kubernetes, monitoring setup (coming soon)

- **[Security](./security/)** - Security documentation
  - [Security Hardening](./security/SECURITY_HARDENING.md) - Security configuration ⭐
  - [Authentication](./security/authentication/) - Auth security details

- **[Maintenance](./maintenance/)** - Operational procedures
  - [Migration Guide v3→v4](./maintenance/migration-v3-to-v4.md) - Upgrade from v3
  - Database, upgrades, backups

- **[Issues](./issues/)** - Problem tracking
  - Known issues, workarounds, post-mortems

## 🎯 Documentation Philosophy

1. **Documentation First** - Document before coding
2. **Keep It Current** - Update docs with code changes
3. **Be Specific** - Include examples and edge cases
4. **Think of the Reader** - Write for your future self

## 📊 Documentation Status

### Completed ✅

- Team processes and workflows
- Documentation standards
- Code quality guidelines
- Architecture decision template
- Python 3.11 setup
- Docker setup guide
- Health check endpoints
- JWT & API Key authentication
- Security hardening (rate limiting, CORS, headers)
- Complete API documentation
- Production deployment guide
- Developer guide

### Completed (Sprint 1-3) ✅
- Multi-tenant authentication system
- OAuth2 with Authentik integration
- API Key management
- JWT token system
- Tenant management APIs
- Security middleware (CORS, Rate Limiting, Headers)
- Comprehensive logging and tracing
- Audit system
- Teams CRUD API (Sprint 200) ✅

### In Progress (Sprint 4) ⚠️
- LangGraph integration
- Chat conversation system
- Tool registry and execution
- Knowledge base for moderators
- LLM provider abstraction (Claude, OpenAI)

### Upcoming (Sprint 5+) 🔴
- Advanced team collaboration features (real-time sync)
- Vector store integration (Milvus)
- SharePoint/O365 integration
- Google Workspace connector
- MCP gateway
- Canvas editor
- Visual flow builder

## 🔍 Finding Information

### By Role

- **New Developer**: Start with [Quick Start](./QUICK_START.md) then [Developer Guide](./development/DEVELOPER_GUIDE.md)
- **API User**: See [API Reference](./api/API_REFERENCE.md)
- **DevOps**: Check [Deployment Guide](./deployment/DEPLOYMENT_GUIDE.md)
- **Security Engineer**: Review [Security Hardening](./security/SECURITY_HARDENING.md)
- **Team Member**: Read [Team Guide](./TeamGuide.md)

### By Topic

- **What is the project vision?** → [PROJECT VISION](../PROJECT_VISION.md)
- **What are we building next?** → [FEATURE ROADMAP](../FEATURE_ROADMAP.md)
- **How to implement Sprint 4?** → [QUICK WINS](../QUICK_WINS.md)
- **Task difficulty overview?** → [DEVELOPMENT HIERARCHY](../DEVELOPMENT_HIERARCHY.md)
- **How to get started quickly?** → [Quick Start](./QUICK_START.md)
- **How to set up development?** → [Setup Checklist](./SETUP_CHECKLIST.md)
- **How to contribute?** → [Team Guide](./TeamGuide.md)
- **API reference?** → [API Reference](./api/API_REFERENCE.md)
- **How to deploy?** → [Deployment Guide](./deployment/DEPLOYMENT_GUIDE.md)
- **Security configuration?** → [Security Hardening](./security/SECURITY_HARDENING.md)
- **Architecture decisions?** → [ADRs](./architecture/decisions/)
- **Known issues?** → [Issues](./issues/)

## 🤝 Contributing to Docs

1. Follow the standards in [DocumentationGuide.md](./DocumentationGuide.md)
2. Use provided templates
3. Keep documentation close to code
4. Update docs in the same PR as code changes
5. Get docs reviewed like code

## 📝 Documentation Checklist

For every feature or change:

- [ ] README updated
- [ ] Docs updated
- [ ] Architecture diagrams updated
- [ ] Examples provided
- [ ] Troubleshooting guide updated
- [ ] Configuration documented

## 🆘 Need Help?

- Can't find something? Check the search function
- Still stuck? Ask in #nai-dev Slack channel
- Found an error? Submit a PR or create an issue

---

**Remember**: Good documentation is an investment in the project's future. Take the time to do it right!

*Last updated: 2025-06-22*

---

**Version**: 4.1.0 - Enterprise LLM Platform
**Project Lead**: Mike Berndt <berndt.mike@gmail.com>
**Current Sprint**: Sprint 4 - LangGraph Foundation
