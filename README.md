# Linux IDS Platform 🛡️

Plataforma de Detecção e Análise de Intrusões (IDS) em Linux com dashboard web em tempo real, API REST e coleta contínua de logs de autenticação.

## ✅ Funcionalidades

- Dashboard web responsivo (Bootstrap 5 + Chart.js)
- Métricas de segurança em tempo real:
  - total de alertas
  - alertas críticos
  - alertas nas últimas 24h
  - IPs únicos
- Tabela de alertas recentes
- Gráficos por tipo e severidade
- Lista de IPs mais ameaçadores
- API REST para alertas, estatísticas e logs
- Coletor de logs (`/var/log/auth.log`) em thread de background
- Motor de análise para:
  - brute force
  - port scan
  - privilege escalation (sudo/su)
  - acessos em horários incomuns
- Persistência em SQLite com índices

---

## 📁 Estrutura

```
linux-ids-platform/
├── analysis_engine/
├── backend/
│   ├── routes/
│   ├── app.py
│   ├── config.py
│   └── database.py
├── frontend/
│   ├── css/
│   ├── js/
│   └── index.html
├── logs_collector/
├── config.py
├── requirements.txt
├── Dockerfile
└── docker-compose.yml
```

---

## 🚀 Execução local

### Pré-requisitos
- Python 3.8+
- Linux com acesso ao arquivo de log de autenticação

### Instalação

```bash
pip install -r requirements.txt
python backend/app.py
```

Acesse:
- Dashboard: http://localhost:5000
- Health check: http://localhost:5000/health

---

## 🔌 Endpoints da API

### Alertas
- `GET /api/alerts/` — lista alertas (filtros: `threat_type`, `severity`, `status`, `limit`)
- `GET /api/alerts/<id>` — obtém alerta por ID
- `PUT /api/alerts/<id>/status` — atualiza status
- `GET /api/alerts/count` — contagem por tipo/severidade (24h)

### Estatísticas
- `GET /api/stats/overview`
- `GET /api/stats/by-type`
- `GET /api/stats/by-severity`
- `GET /api/stats/top-ips`

### Logs
- `GET /api/logs/` — lista logs (filtros: `severity`, `source_file`, `limit`)
- `GET /api/logs/<id>` — obtém log por ID

### Sistema
- `GET /api` — informações da API
- `GET /health` — status da aplicação e banco

---

## ⚙️ Configuração

Principais variáveis de ambiente:
- `FLASK_ENV` (`development` | `production`)
- `HOST` (default: `0.0.0.0`)
- `PORT` (default: `5000`)
- `DATABASE_PATH` (default: `backend/ids_platform.db`)
- `AUTH_LOG_FILE` (default: `/var/log/auth.log`)
- `BRUTE_FORCE_THRESHOLD`
- `BRUTE_FORCE_WINDOW`
- `PORT_SCAN_THRESHOLD`
- `PORT_SCAN_WINDOW`

---

## 🐳 Docker

### Build e run

```bash
docker build -t linux-ids-platform .
docker run -p 5000:5000 linux-ids-platform
```

### Docker Compose

```bash
docker-compose up --build
```

---

## 🧪 Dependências

Arquivo `requirements.txt`:
- Flask 2.3.3
- Flask-CORS
- watchdog
- psutil
- requests
- python-dotenv
- Werkzeug

---

## 📄 Licença

MIT
