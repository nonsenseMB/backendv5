Die Testordner sind für verschiedene Testarten organisiert:

  1. benchmarks/ - Performance-Tests zur Messung von Antwortzeiten und Ressourcenverbrauch

  2. e2e/ - End-to-End-Tests für komplette Benutzer-Workflows

  3. integration/ - Integrationstests für das Zusammenspiel verschiedener Komponenten:
  - api/, auth/, core/audit/, documents/, infrastructure/database/

  4. load/ - Lasttests zur Simulation hoher Benutzerzahlen und Stressszenarien

  5. unit/ - Unit-Tests für einzelne Komponenten in Isolation:
  - Spiegelt die Anwendungsarchitektur wider
  - Testet API-Middleware, Domain-Logik, Services und Infrastructure-Layer