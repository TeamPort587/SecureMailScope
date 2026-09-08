# SecureMailScope

SecureMailScope is an end-to-end security analysis and monitoring platform designed for inspecting, dissecting, and analyzing email protocols, payloads, and associated network traffic for threats, anomalies, and compliance violations.

---

## Purpose of the Project

Modern email infrastructure faces sophisticated threat vectors ranging from phishing, spoofing, and malicious attachments to anomalous protocol behavior. SecureMailScope provides a unified workflow to:
- Ingest and parse email network traffic captures and message payloads.
- Run multi-layered detection and heuristics analysis against email artifacts.
- Deliver real-time visualization, alert dashboards, and detailed threat telemetry to security analysts.

---

## Repository Structure

```text
.
├── .gitignore
├── README.md
├── LICENSE
│
├── frontend/                   # React frontend application
│   └── .gitkeep
│
├── gateway/                    # Node.js API gateway and orchestration service
│   └── .gitkeep
│
├── analysis/                   # Python/Django analysis backend and detection engine
│   └── .gitkeep
│
├── data/                       # Local datasets, sample captures, and testing fixtures
│   └── .gitkeep
│
├── docs/                       # Project specifications, contracts, and documentation
│   ├── contracts/
│   │   ├── node-django.json    # API contract between Gateway and Analysis engine
│   │   ├── django-result.json  # Schema definition for analysis engine results
│   │   └── node-react.json     # API contract between Frontend and Gateway
│   │
│   ├── architecture.md         # High-level system architecture and component design
│   ├── dataset-manifest.yaml   # Catalog and metadata for test/benchmark datasets
│   └── demo-checklist.md       # Operational checklist for testing and demonstrations
│
└── .github/
    └── workflows/              # GitHub Actions CI/CD pipelines
        └── .gitkeep
```

---

## Service Responsibilities

### 1. Frontend (`frontend/`)
- **Technology**: React (JavaScript/TypeScript)
- **Role**: Provides the interactive web application interface for security analysts.
- **Responsibilities**:
  - File upload interface for network captures (PCAP) and email data.
  - Interactive dashboards displaying threat metrics, detection summaries, and log streams.
  - Visualizing inspection reports and individual message breakdowns.

### 2. Gateway (`gateway/`)
- **Technology**: Node.js
- **Role**: Central communication bridge and orchestration layer.
- **Responsibilities**:
  - Authenticating and authorizing client sessions.
  - Validating incoming requests against predefined API schemas.
  - Proxying and queueing analysis requests to the Python/Django analysis service.
  - Managing real-time communications (e.g., WebSockets / SSE) back to the frontend.

### 3. Analysis Engine (`analysis/`)
- **Technology**: Python / Django
- **Role**: Computational and analytical powerhouse.
- **Responsibilities**:
  - Parsing PCAP/PCAPNG streams, SMTP/IMAP/POP3 sessions, and raw MIME messages.
  - Executing threat detection algorithms, signature matches, and heuristic models.
  - Storing and producing structured inspection results and threat indicators.

### 4. Data (`data/`)
- **Role**: Dataset management and test payloads.
- **Responsibilities**:
  - Housing sample datasets, benchmark fixtures, and test captures locally during development.
  - Kept strictly out of version control (except `.gitkeep` and documentation references in `docs/dataset-manifest.yaml`) to avoid repository bloat and potential leakage of sensitive captures.

---

## API Contracts

All inter-service communication is governed by schemas located in [`docs/contracts/`](file:///docs/contracts/):
- **`node-react.json`**: Defines endpoints, payloads, and response structures between the React frontend and Node.js gateway.
- **`node-django.json`**: Defines the communication protocol and task submission payload from Node.js gateway to Django analysis service.
- **`django-result.json`**: Specifies the standardized output format emitted by the analysis engine.

*All services must adhere to these schemas. Any breaking changes to payloads must be reflected in the contract files via pull request before implementation.*

---

## Team Development Workflow

To ensure code quality and stability, all contributors must adhere to the following workflow guidelines:

### Branch Naming Conventions
Always branch off the latest `main` branch. Use descriptive branch names prefixed with the category:
- `feature/<feature-name>`: New functionality or enhancements (e.g., `feature/pcap-parser`)
- `bugfix/<issue-name>`: Bug fixes (e.g., `bugfix/auth-token-refresh`)
- `hotfix/<critical-issue>`: Immediate production fixes
- `docs/<doc-topic>`: Documentation updates (e.g., `docs/update-architecture`)
- `refactor/<module-name>`: Code refactoring without behavioral changes

### Pull Requests & Branch Protection
> [!IMPORTANT]
> **Direct pushes to `main` are strictly prohibited.**
> All changes must be proposed via Pull Requests (PRs) from feature branches.

1. **Create a Branch**: `git checkout -b feature/your-feature-name`
2. **Develop & Test**: Implement changes with appropriate tests in the respective service directory.
3. **Commit**: Use Conventional Commits (detailed below).
4. **Open a PR**: Submit a Pull Request targeting `main`. PRs require review and passing automated CI checks before merging.

### Conventional Commits
All commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```text
<type>(<scope>): <short summary>

[optional body]

[optional footer(s)]
```

Common types:
- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation updates
- `style`: Formatting, missing semicolons, etc. (no code change)
- `refactor`: Refactoring production code without behavior change
- `test`: Adding or updating tests
- `chore`: Maintenance tasks, dependency updates, build tooling

*Examples*:
- `feat(analysis): implement MIME attachment extractor`
- `fix(gateway): resolve CORS error on file upload endpoint`
- `docs(contracts): update node-django contract draft`
