```markdown
# 🧠 AI-Powered Migration Assessment Tool

Create a real-time **Digital Twin** of your infrastructure to accelerate cloud modernization and migration planning. This CLI-driven tool ingests server/application data, correlates system dependencies, and exports an enriched graph to **Neo4j** for visualization and impact analysis.

---

## 🚀 Key Features

- 🧩 Modular architecture (Linux, Windows, DB ingestion via pluggable agents)
- 🔐 Secure credential handling with keyring / secrets manager
- 🌐 Graph-based Digital Twin (system, app, network, service, and DB layers)
- 🗃️ SQLite for staging, Neo4j for visualization
- 📦 Configurable via `knowledge_base.yaml`
- 🧪 Dry-run mode for safe testing

---

## 📦 Installation

```bash
git clone https://github.com/org/ai-migration-assessment-tool-v2.git
cd ai-migration-assessment-tool-v2
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## ⚙️ Configuration

### 🔐 Step 1: Setup Credentials

```bash
python setup_credentials.py
```

Stores encrypted host credentials in your system keyring.

### 📋 Step 2: Define Inventory

Edit `inventory.csv`:

```csv
ip,os_type,user
192.168.1.10,linux,admin
192.168.1.11,windows,Administrator
```

### 🧠 Step 3: Edit `knowledge_base.yaml`

Define:

* Neo4j credentials via environment variables
* Paths for config file discovery
* Database metadata (e.g., PostgreSQL, MySQL)

---

## 🛠️ Usage

```bash
python src/main.py \
  --inventory inventory.csv \
  --db assessment_history.db \
  --dry-run false \
  --export true
```

> Use `--dry-run true` to simulate without collecting or writing data.

---

## 🧬 Digital Twin: End-to-End Flow

```mermaid
graph TD
    A[Inventory CSV] --> B[Agent Ingestion (SSH/WinRM)]
    B --> C[SQLite Storage]
    C --> D[Correlation Engine]
    D --> E[NetworkX Graph]
    E --> F[Neo4j Export]
```

---

## 🧠 Example Cypher Queries (Neo4j)

```cypher
MATCH (s:Server)-[:RUNS_ON]->(p:Process) RETURN s, p LIMIT 10;

MATCH (d:Database)-[:HOSTED_ON]->(s:Server) RETURN d.name, s.ip;
```

---

## 🔄 Extending the Tool

To add support for a new OS or Database:

1. Create a new ingestion agent class inheriting from `BaseIngestionAgent`
2. Update `knowledge_base.yaml` with discovery metadata
3. Register the new phase in `main.py` or the orchestration pipeline

---

## 🔒 Security Considerations

* ✅ Passwords never hardcoded — stored in system keyring or `.env`
* 🔐 Neo4j secrets loaded via env vars
* 🚫 Logging excludes sensitive data
* 🧪 Dry-run mode avoids actual changes

---

## 📈 Roadmap

* [x] Modular OS-level ingestion
* [x] Graph correlation (processes, ports, IPC, network)
* [x] Digital Twin with Neo4j
* [ ] App config parsing
* [ ] DB introspection (PostgreSQL, MySQL, Oracle)
* [ ] Interactive Web UI (planned)

---

## 🤝 Contributing

We welcome PRs and discussions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) (planned) for guidelines.

---

## 📄 License

MIT License. See [LICENSE](LICENSE).

---

## 🧪 Sample Output (Graph Screenshot)

*Add a screenshot of the Neo4j Browser showing a server–process–app relationship graph.*

---
```