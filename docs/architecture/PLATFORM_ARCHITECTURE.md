# nAI Platform Architecture
## Enterprise AI Platform with Multi-LLM Support

## Overview

Die nAI Platform ist eine Enterprise-grade AI-Lösung, die es Unternehmen ermöglicht, ihre eigene AI-Infrastruktur aufzubauen und zu verwalten. Die Plattform unterstützt multiple LLM-Provider, bietet ein ausgeklügeltes Memory-System und ermöglicht Team-Kollaboration in Echtzeit.

## Kernkomponenten

### 1. Multi-LLM Integration Layer

```mermaid
graph TB
    subgraph "LLM Providers"
        OpenAI[OpenAI API]
        Anthropic[Anthropic API]
        Google[Google Gemini]
        Azure[Azure OpenAI]
        Ollama[Ollama Local]
    end
    
    subgraph "Integration Layer"
        LLMRouter[LLM Router]
        KeyVault[Encrypted Key Storage]
        RateLimit[Rate Limiter]
        CostTracker[Cost Tracker]
    end
    
    subgraph "Application Layer"
        Agents[Agent System]
        Conversations[Conversations]
        Tools[Tool Execution]
    end
    
    OpenAI --> LLMRouter
    Anthropic --> LLMRouter
    Google --> LLMRouter
    Azure --> LLMRouter
    Ollama --> LLMRouter
    
    LLMRouter --> KeyVault
    LLMRouter --> RateLimit
    LLMRouter --> CostTracker
    
    LLMRouter --> Agents
    LLMRouter --> Conversations
    LLMRouter --> Tools
```

#### Key Features:
- **Sichere API-Key Verwaltung**: AES-256 Verschlüsselung
- **Provider-agnostisch**: Einheitliche Schnittstelle für alle LLMs
- **Cost Tracking**: Detaillierte Kostenerfassung pro Tenant/User/Team
- **Rate Limiting**: Schutz vor Überlastung und Kostenkontrolle

### 2. Memory Architecture

```mermaid
graph LR
    subgraph "Memory Layers"
        STM[Short-Term Memory<br/>4h TTL]
        LTM[Long-Term Memory<br/>Permanent]
        Vector[Vector Memory<br/>Milvus]
        Graph[Knowledge Graph<br/>Apache AGE]
    end
    
    subgraph "Sources"
        Conv[Conversations]
        Docs[Documents]
        Pref[User Preferences]
    end
    
    Conv --> STM
    STM --> |Summarization| LTM
    Docs --> Vector
    Vector --> Graph
    Pref --> LTM
    
    STM --> |Query| Response[AI Response]
    LTM --> |Query| Response
    Vector --> |Semantic Search| Response
    Graph --> |Relationships| Response
```

#### Memory Types:

1. **Short-Term Memory (STM)**
   - Lebensdauer: 4 Stunden nach letzter Aktivität
   - Zweck: Aktiver Konversationskontext
   - Automatische Bereinigung

2. **Long-Term Memory (LTM)**
   - Persistente Speicherung wichtiger Fakten
   - User Preferences (global)
   - Gelernte Muster und Präferenzen

3. **Vector Memory (Milvus)**
   - Semantic Search über Dokumente
   - Embedding-basierte Ähnlichkeitssuche
   - Skalierbar für Millionen von Dokumenten

4. **Knowledge Graph (Apache AGE)**
   - Beziehungen zwischen Entitäten
   - "Welche anderen Dokumente hat dieser Autor geschrieben?"
   - Dokumenten-Level Rechteverwaltung

### 3. Agent System (LangGraph)

```mermaid
graph TB
    subgraph "Agent Definition"
        Config[JSON Config]
        Tools[Tool Registry]
        Memory[Memory Access]
        LLM[LLM Selection]
    end
    
    subgraph "LangGraph Runtime"
        Loader[Dynamic Loader]
        Graph[Graph Executor]
        State[State Manager]
    end
    
    subgraph "Execution"
        Input[User Input]
        Process[Processing]
        Output[Response]
    end
    
    Config --> Loader
    Tools --> Loader
    Memory --> Loader
    LLM --> Loader
    
    Loader --> Graph
    Graph --> State
    
    Input --> Process
    Process --> Graph
    Graph --> Output
```

#### Agent Features:
- **Dynamisches Laden**: Agents werden zur Laufzeit geladen
- **JSON-basierte Definition**: UI-Editor für Agent-Konfiguration
- **Tool Integration**: Zugriff auf definierte Tools und MCP Server
- **Team Agents**: Ein Agent pro Team mit spezifischem Verhalten

### 4. Real-time Collaboration

```mermaid
sequenceDiagram
    participant User1
    participant User2
    participant WebSocket
    participant Backend
    participant AI
    
    User1->>WebSocket: Connect (JWT)
    WebSocket->>Backend: Authenticate
    Backend->>WebSocket: Channel Assignment
    
    User1->>WebSocket: Send Message
    WebSocket->>Backend: Process Message
    Backend->>AI: Generate Response
    AI->>Backend: AI Response
    Backend->>WebSocket: Broadcast Update
    WebSocket->>User1: Update
    WebSocket->>User2: Update
    
    Note over WebSocket: Real-time sync for<br/>- Conversations<br/>- Documents<br/>- Team Activities
```

#### WebSocket Features:
- **JWT Authentication**: Sichere Verbindungen
- **Channel-basiert**: Teams, Conversations, Documents
- **Real-time Updates**: Sofortige Synchronisation
- **Presence Tracking**: Wer arbeitet gerade woran

### 5. Document Processing & AI Writing

```mermaid
graph LR
    subgraph "Document Sources"
        Upload[File Upload]
        SharePoint[SharePoint]
        GDrive[Google Drive]
        Create[AI Creation]
    end
    
    subgraph "Processing Pipeline"
        Extract[Text Extraction]
        Chunk[Chunking]
        Embed[Embedding]
        Index[Indexing]
    end
    
    subgraph "AI Writing"
        TipTap[TipTap Editor]
        AIAssist[AI Assistant]
        Collab[Collaboration]
    end
    
    Upload --> Extract
    SharePoint --> Extract
    GDrive --> Extract
    
    Extract --> Chunk
    Chunk --> Embed
    Embed --> Index
    
    Create --> TipTap
    TipTap <--> AIAssist
    TipTap --> Collab
```

#### Document Features:
- **Multi-Source Integration**: SharePoint, Google Drive, etc.
- **Rechteverwaltung**: Dokumenten-Level Permissions
- **AI Writing Assistant**: Kollaboratives Schreiben mit AI
- **TipTap Integration**: Rich-Text Editor mit AI-Features

## Technologie-Stack

### Backend
- **Framework**: FastAPI (Python)
- **Async**: Full async/await support
- **WebSockets**: Real-time communication
- **LangGraph**: Agent orchestration

### Datenbanken
- **Primary**: PostgreSQL 14+
- **Graph**: Apache AGE (PostgreSQL Extension)
- **Vector**: Milvus
- **Cache**: Redis

### Security
- **Authentication**: Authentik (passwordless)
- **Encryption**: AES-256 für API Keys
- **RLS**: Row-Level Security in PostgreSQL
- **Sandbox**: Sichere Tool-Execution

### Integration
- **MCP**: Model Context Protocol für externe Tools
- **OAuth**: Für externe Service-Integration
- **Webhooks**: Event-driven Architecture

## Deployment Architecture

```mermaid
graph TB
    subgraph "Client Layer"
        Web[Web App]
        Mobile[Mobile App]
    end
    
    subgraph "API Gateway"
        Kong[Kong/Traefik]
        WS[WebSocket Server]
    end
    
    subgraph "Application Tier"
        API1[API Server 1]
        API2[API Server 2]
        Worker1[Worker 1]
        Worker2[Worker 2]
    end
    
    subgraph "Data Tier"
        PG[(PostgreSQL)]
        Milvus[(Milvus)]
        Redis[(Redis)]
    end
    
    subgraph "External Services"
        Auth[Authentik]
        LLMs[LLM APIs]
        MCP[MCP Servers]
    end
    
    Web --> Kong
    Mobile --> Kong
    Web --> WS
    Mobile --> WS
    
    Kong --> API1
    Kong --> API2
    WS --> API1
    WS --> API2
    
    API1 --> PG
    API2 --> PG
    API1 --> Milvus
    API2 --> Milvus
    API1 --> Redis
    API2 --> Redis
    
    Worker1 --> PG
    Worker2 --> PG
    Worker1 --> Milvus
    Worker2 --> Milvus
    
    API1 --> Auth
    API2 --> Auth
    API1 --> LLMs
    API2 --> LLMs
    Worker1 --> MCP
    Worker2 --> MCP
```

## Skalierung

### Horizontal Scaling
- **API Server**: Stateless, beliebig skalierbar
- **Worker**: Queue-basiert, auto-scaling
- **WebSocket**: Sticky Sessions mit Redis Pub/Sub

### Datenbank Scaling
- **PostgreSQL**: Read Replicas für Queries
- **Milvus**: Distributed Mode für große Deployments
- **Redis**: Cluster Mode für High Availability

## Performance Optimierungen

### Token-Optimierung
1. **Conversation Checkpoints**: Alle 50 Nachrichten
2. **Summarization**: Automatische Zusammenfassung
3. **Selective Context**: Nur relevante Memory-Teile laden

### Caching Strategy
1. **Redis**: Session Data, STM
2. **PostgreSQL**: Materialized Views für Analytics
3. **Milvus**: Pre-computed Embeddings

### Async Processing
1. **Document Processing**: Background Jobs
2. **Knowledge Graph Updates**: Async Integration
3. **Usage Tracking**: Batch Updates

## Monitoring & Observability

### Metrics
- **Application**: Prometheus metrics
- **Database**: pg_stat_statements
- **LLM Usage**: Custom tracking per provider

### Logging
- **Structured Logging**: JSON format
- **Trace IDs**: Request tracing
- **Audit Trail**: Compliance logging

### Alerting
- **Cost Alerts**: Bei Überschreitung von Limits
- **Performance**: Slow queries, high latency
- **Security**: Failed auth attempts

## Disaster Recovery

### Backup Strategy
1. **PostgreSQL**: Daily backups, PITR
2. **Milvus**: Snapshot backups
3. **Document Storage**: Object Storage mit Versioning

### High Availability
1. **Multi-AZ Deployment**: Verfügbarkeit
2. **Auto-Failover**: Für kritische Komponenten
3. **Data Replication**: Cross-region für Enterprise

---

**Document Version**: 1.0  
**Last Updated**: 2025-01-23  
**Status**: Architecture Blueprint