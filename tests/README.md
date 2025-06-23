# Backend v5 Tests

Diese Testsuite bietet umfassende Tests für die FastAPI-Anwendung, organisiert nach Testtypen.

## Teststruktur

```
tests/
├── unit/               # Unit Tests für einzelne Komponenten
├── integration/        # Integrationstests für API-Endpoints
├── e2e/               # End-to-End Tests für komplette Workflows
├── load/              # Lasttests für Performance unter Stress
├── benchmarks/        # Detaillierte Performance-Benchmarks
└── conftest.py        # Test-Fixtures und Konfiguration
```

## Tests ausführen

### Alle Tests
```bash
poetry run pytest
```

### Spezifische Testkategorien

#### Unit Tests
```bash
poetry run pytest tests/unit/
```

#### Integration Tests
```bash
poetry run pytest tests/integration/
```

#### End-to-End Tests
```bash
poetry run pytest tests/e2e/
```

#### Load Tests
```bash
poetry run pytest tests/load/ -v
```

#### Benchmarks
```bash
poetry run pytest tests/benchmarks/ -v
```

### Mit Coverage
```bash
poetry run pytest --cov=src --cov-report=html
```

### Nur schnelle Tests (ohne Load/Benchmarks)
```bash
poetry run pytest -m "not slow"
```

## Testbeschreibungen

### Unit Tests (`tests/unit/`)
- **test_main.py**: Testet die Hauptanwendung, Konfiguration und einzelne Endpoints isoliert

### Integration Tests (`tests/integration/`)
- **test_api_integration.py**: Testet das Zusammenspiel der API-Komponenten mit echten Dependencies

### End-to-End Tests (`tests/e2e/`)
- **test_user_workflows.py**: Simuliert komplette Benutzer-Workflows vom Start bis Ende

### Load Tests (`tests/load/`)
- **test_api_load.py**: Testet API-Performance unter Last
  - Concurrent requests
  - Sustained load
  - Traffic spikes
  - Mixed endpoints

### Benchmarks (`tests/benchmarks/`)
- **test_performance_benchmarks.py**: Detaillierte Performance-Messungen
  - Response-Zeit-Statistiken
  - Memory-Effizienz
  - Connection-Pooling
  - JSON-Serialisierung
  - Skalierung mit concurrent users

## Testanforderungen

Die Tests setzen folgendes voraus:
- Python 3.11+
- Alle Dependencies aus pyproject.toml installiert
- Umgebungsvariablen in .env gesetzt (DATABASE_URL, SECRET_KEY)

## Performance-Ziele

Die Tests validieren folgende Performance-Ziele:
- Durchschnittliche Response-Zeit < 10ms
- 95. Perzentil < 20ms
- 99. Perzentil < 50ms
- 100% Success-Rate unter normaler Last
- Memory-Leak-frei (< 50MB Increase bei 1000 Requests)