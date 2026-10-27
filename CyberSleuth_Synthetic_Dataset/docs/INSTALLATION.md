# CyberSleuth AI — Installation & Setup Guide

This guide provides complete, step-by-step setup instructions for all four project team members and evaluating faculty. It covers both single-command Docker deployment and modular manual installation.

---

## 1. System Requirements & Prerequisites

Ensure the target host meets the following baseline requirements:
- **Operating System**: Windows 10/11, Ubuntu 22.04 LTS+, or macOS (Apple Silicon / Intel)
- **Memory (RAM)**: Minimum 8 GB (16 GB recommended for running local vector embeddings)
- **Disk Storage**: 5 GB free disk space
- **Software Dependencies**:
  - [Python 3.11 or 3.12](https://www.python.org/downloads/)
  - [Node.js 18 LTS or 20 LTS](https://nodejs.org/) (includes npm 9+)
  - [PostgreSQL 15+](https://www.postgresql.org/download/) with [pgvector extension](https://github.com/pgvector/pgvector)
  - [Git](https://git-scm.com/)
  - [Docker Desktop](https://www.docker.com/products/docker-desktop/) (recommended for containerized run)

---

## 2. Option A: Containerized Setup via Docker Compose (Recommended)

Docker Compose provisions PostgreSQL with `pgvector`, the FastAPI backend, and the React frontend simultaneously.

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-team/cybersleuth-ai.git
cd cybersleuth-ai
```

### Step 2: Configure Environment Variables
Copy the template `.env.example` to `.env`:
```bash
cp .env.example .env
```
Populate required environment keys:
```env
# Application
PROJECT_NAME="CyberSleuth AI"
ENVIRONMENT="development"
SECRET_KEY="generate_a_secure_random_jwt_secret_key"

# Database Configuration
POSTGRES_USER=cybersleuth
POSTGRES_PASSWORD=cybersleuth_secure_pass
POSTGRES_DB=cybersleuth_db
POSTGRES_PORT=5432
DATABASE_URL=postgresql+asyncpg://cybersleuth:cybersleuth_secure_pass@db:5432/cybersleuth_db

# LLM & RAG Configuration
GEMINI_API_KEY="your-google-gemini-api-key"
EMBEDDING_MODEL="sentence-transformers/all-MiniLM-L6-v2"
```

### Step 3: Launch Services
```bash
docker-compose up --build
```

### Step 4: Verify Deployment
Once containers are healthy, access:
- **Frontend Dashboard**: `http://localhost:3000`
- **FastAPI OpenAPI Interactive Docs**: `http://localhost:8000/docs`
- **Health Check Probe**: `http://localhost:8000/api/v1/health`

---

## 3. Option B: Local Developer Manual Installation

Use this option when developing individual components (Frontend, Backend, or AI pipeline).

### 3.1 Backend Setup (Member 2)
```bash
# Navigate to backend directory
cd backend

# Create and activate Python virtual environment
python -m venv venv

# Windows:
.\venv\Scripts\activate
# Linux/macOS:
# source venv/bin/activate

# Upgrade pip and install backend requirements
pip install --upgrade pip
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start FastAPI development server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 3.2 Frontend Setup (Member 3)
```bash
# In a separate terminal window:
cd frontend

# Install npm dependencies
npm install

# Configure environment file
echo "VITE_API_BASE_URL=http://localhost:8000/api/v1" > .env.local

# Launch Vite development server
npm run dev
```
Open `http://localhost:5173` in your browser.

### 3.3 AI & RAG Pipeline Setup (Member 1)
```bash
# Navigate to ai directory
cd ai

# Install AI dependencies
pip install langgraph langchain-google-genai sentence-transformers pgvector

# Initialize vector index in PostgreSQL
python -m rag.initialize_vector_db --knowledge-dir data/mitre_attack/
```

---

## 4. Loading Member 4 Synthetic Datasets

Member 4 provides labeled synthetic datasets for immediate demonstration and testing:

```bash
# Ingest the core 12-scenario synthetic dataset
python -m scripts.ingest_dataset --file data/all_events.json

# Ingest expanded suspicious attack scenarios (SCN019-SCN026)
python -m scripts.ingest_dataset --file datasets/expanded_suspicious_events.json

# Ingest control-group baseline benign activity (100 events)
python -m scripts.ingest_dataset --file datasets/large_scale_benign_baseline.json
```

---

## 5. Verification & Running Quality Assurance

Verify that your local installation passes all test suites:

```bash
# Run Member 4's complete test suite (106 unit & integration tests)
python -m pytest tests/ -v

# Run full evaluation benchmark & generate performance report
python -m evaluation.run_evaluation --mode full --output-dir evaluation/results
```

---

## 6. Common Troubleshooting FAQ

### 1. PostgreSQL `pgvector` Extension Error
- **Symptom**: `ERROR: extension "vector" is not available`
- **Resolution**: Ensure you are using the official `pgvector/pgvector:pg15` container image, or on manual installations run:
  ```bash
  sudo apt-get install postgresql-15-pgvector
  # Then in psql:
  CREATE EXTENSION IF NOT EXISTS vector;
  ```

### 2. CORS Errors in Frontend Console
- **Symptom**: `Cross-Origin Request Blocked: The Same Origin Policy disallows reading the remote resource`
- **Resolution**: In `backend/app/main.py`, verify `CORSMiddleware` includes `http://localhost:3000` and `http://localhost:5173` in `allow_origins`.

### 3. Port Conflicts (8000 or 5432 in use)
- **Windows**: Run `netstat -ano | findstr :8000` to find the process PID and kill it via `taskkill /PID <PID> /F`.
- Alternatively, adjust the port in `docker-compose.yml` (e.g., `"8001:8000"`).

### 4. Gemini API Rate Limiting / 429
- **Resolution**: For offline academic testing, set `MOCK_LLM=true` in `.env` to engage Member 4's deterministic mock agent harness.
