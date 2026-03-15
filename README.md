# Zeno AI — East African Agricultural Trade Intelligence System

> An AI-powered economic decision support system for forecasting, comparative analysis, and scenario planning across East African agricultural commodities.

🔗 **Live Demo:** [https://your-frontend.vercel.app](https://haraka-frontend.vercel.app/landing_page)  
🎥 **Demo Video:** [[Drive link](https://drive.google.com/file/d/1lDBtvqLmfQXmTXnqtYvilXrClPpOm0Q2/view?usp=sharing)]  
🐳 **Backend Image:** `docker pull simplykevine/zeno-decision-tool:latest`

---

## 🧠 What It Does

| Feature | Description |
|---|---|
| **Forecasting** | Predicts coffee and maize prices using Prophet time-series models |
| **Comparative Analysis** | Compares trade performance between East African countries |
| **Scenario Analysis** | Simulates policy impacts (subsidies, tariffs, shocks) |
| **Economist Dashboard** | Real-time maize market intelligence with 6 AI panels |
| **RAG Knowledge Base** | Retrieves context from trade policy documents via pgvector |

---

## 🏗️ Architecture

```
Next.js Frontend (Vercel)
        ↓
FastAPI Backend (Google Cloud Run)
        ↓
┌───────────────────────────────┐
│  Google Gemini (AI Reasoning) │
│  Supabase PostgreSQL          │
│  pgvector (RAG Embeddings)    │
│  Prophet (Forecasting Model)  │
└───────────────────────────────┘
```

---

## ⚙️ How to Run Locally

### Prerequisites
- Python 3.11+
- Node.js 18+
- A `.env` file (see below)

### 1. Clone the repo
```bash
git clone https://github.com/simplykevine/Haraka-ai.git
cd Haraka-ai
```

### 2. Set up Python environment
```bash
python -m venv venv
source venv/bin/activate        
pip install -r requirements.txt
```

### 3. Create your `.env` file
```env
GOOGLE_API_KEY=your_gemini_api_key
DATABASE_URL=your_supabase_postgresql_url
GOOGLE_GENAI_USE_VERTEXAI=FALSE
```

### 4. Run the backend
```bash
uvicorn zeno_agent.agent:app --port 8080 --reload
```

### 5. Run the frontend
```bash
cd frontend        
npm install
npm run dev
```

### 6. Open in browser
```
Frontend: http://localhost:3000
Backend:  http://localhost:8080
API Docs: http://localhost:8080/docs
```

---

## 🐳 Run with Docker
```bash
docker pull simplykevine/zeno-decision-tool:latest
docker run -p 8080:8080 \
  -e GOOGLE_API_KEY=your_key \
  -e DATABASE_URL=your_db_url \
  simplykevine/zeno-decision-tool:latest
```

---

## 🚀 Deployment

Deployed on **Google Cloud Run** via GitHub Actions CI/CD.

| Component | Platform |
|---|---|
| Frontend | Vercel |
| Backend | Google Cloud Run (`europe-west1`) |
| Database | Supabase PostgreSQL |
| Container Registry | Docker Hub |
| CI/CD | GitHub Actions |

**Verify deployment:**
```bash
curl https://your-cloud-run-url/healthz
# → {"status":"ok"}
```

---

## 🧪 API Testing (Postman)

Import `zeno-demo-postman-collection.json` from the repo root.

Key endpoints:
```
POST /query                          - Main AI query endpoint
GET  /dashboard/economist            - Dashboard data
POST /dashboard/economist/analyze    - Dashboard AI analysis
GET  /healthz                        - Health check
```

---

## 📊 Data Sources

| Source | Data |
|---|---|
| World Bank API | GDP, CPI, Inflation |
| FAO FAOSTAT API | Coffee/Maize production volumes |
| World Bank Commodity Prices | Live coffee & maize USD prices |
| Supabase (internal) | Historical East African trade data |