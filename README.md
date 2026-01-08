# Security Gatekeeper

AI Security Gatekeeper with PII Redaction, Rate Limiting & Audit Logging.

## Features

- **PII Redaction**: Automatically detects and masks PII (emails, names, phone numbers, etc.) for non-privileged users using Microsoft Presidio
- **Role-Based Rate Limiting**: Configurable request quotas per role with Redis-backed sliding window
- **Audit Logging**: Full request/response tracking with PostgreSQL for compliance
- **Centralized Middleware**: All security concerns handled in a single `SecurityGatekeeperMiddleware` (except admin audit endpoints, which are excluded)
- **Hexagonal Architecture**: Clean separation of concerns with ports and adapters pattern

## Tech Stack

- **Backend**: FastAPI, Python 3.11+
- **PII Detection**: Microsoft Presidio with spaCy NLP
- **Database**: PostgreSQL 16 (audit logs)
- **Cache**: Redis 7 (rate limiting)

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)

### Run with Docker Compose

```bash
# Clone and navigate to the project
cd security-governance-gatekeeper

# Copy environment file
cp .env.example .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f app
```

The API will be available at `http://localhost:8000`

### Local Development

```bash
# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e .

# Download spaCy model
python -m spacy download en_core_web_sm

# Start PostgreSQL and Redis (via Docker)
docker-compose up -d db redis

# Start the application
uvicorn security_governance_gatekeeper.api.main:app --reload
```

## API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

## Authentication (Mock)

Use HTTP headers to simulate different users:

| Header | Description | Example |
|--------|-------------|---------|
| `X-User-ID` | User identifier | `user_123` |
| `X-User-Role` | Role: `admin` or `junior_intern` | `admin` |
| `X-Department` | Department name | `engineering` |

### Roles

| Role | PII Redaction | Rate Limit |
|------|---------------|------------|
| `admin` | Disabled (sees raw PII) | None |
| `junior_intern` | Enabled | 10 requests/hour |

## API Endpoints

### Demo Endpoints

Test PII detection and redaction with sample data or custom text.

#### Using Swagger UI (Recommended)

1. Navigate to **http://localhost:8000/docs** in your browser
2. Click on any endpoint to expand it
3. Click **"Try it out"** button
4. For authentication, add these headers in the **Parameters** section:
   - `X-User-ID`: `user_123` (or any user identifier)
   - `X-User-Role`: `admin` or `junior_intern`
   - `X-Department`: `engineering` (or any department)
5. Fill in any required request body parameters
6. Click **"Execute"** to send the request
7. View the response directly in the UI with syntax highlighting

**Benefits of Swagger UI:**
- Interactive interface with auto-completion
- Built-in request/response validation
- Easy header management
- No need to format JSON manually
- Real-time API documentation

#### Using curl Commands

```bash
# English PII demo (junior intern: PII redacted; admin: sees raw PII)
curl -H "X-User-ID: user_123" \
     -H "X-User-Role: junior_intern" \
     -H "X-Department: engineering" \
     http://localhost:8000/demo/english

# Italian PII demo
curl -H "X-User-ID: user_123" \
     -H "X-User-Role: admin" \
     -H "X-Department: engineering" \
     http://localhost:8000/demo/italian

# Custom text analysis (specify language: en or it)
curl -X POST http://localhost:8000/demo/custom \
     -H "X-User-ID: user_123" \
     -H "X-User-Role: junior_intern" \
     -H "X-Department: engineering" \
     -H "Content-Type: application/json" \
     -d '{"text": "Contact John at john@example.com or 555-123-4567"}'

# Get supported languages
curl http://localhost:8000/demo/languages

# Rate limit demo (junior intern: 10 req/hour)
for i in {1..12}; do 
  curl -s -H "X-User-ID: user_123" \
       -H "X-User-Role: junior_intern" \
       -H "X-Department: engineering" \
       http://localhost:8000/demo/english
done
# 11th+ requests will get 429: Rate limit exceeded
```

### Admin Audit Endpoints

Monitor request activity and audit logs. **Admin only** (requires `X-User-Role: admin`).

```bash
# Get audit logs for a specific user
curl -H "X-User-ID: admin_user" \
     -H "X-User-Role: admin" \
     -H "X-Department: security" \
     "http://localhost:8000/admin/audit/logs/user_123?limit=50"

# Get usage statistics by department (last 7 days)
curl -H "X-User-ID: admin_user" \
     -H "X-User-Role: admin" \
     -H "X-Department: security" \
     "http://localhost:8000/admin/audit/usage-by-department?days=7"

# Non-admin access denied
curl -H "X-User-ID: user_123" \
     -H "X-User-Role: junior_intern" \
     -H "X-Department: engineering" \
     http://localhost:8000/admin/audit/logs/user_123
# {"detail": "Admin access required"}
```

**Note:** Admin audit endpoints are excluded from the SecurityGatekeeperMiddleware. These routes do not apply PII redaction, rate limiting, or audit logging middleware logic.

### Health Check

```bash
curl http://localhost:8000/health
# {"status": "healthy"}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | `postgresql+asyncpg://gatekeeper:gatekeeper@localhost:5432/gatekeeper` | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `ROLES_CONFIG_PATH` | `config/roles.yaml` | Path to role policies |
| `DEBUG` | `false` | Enable debug mode |

### Role Policies (config/roles.yaml)

```yaml
roles:
  admin:
    pii_redaction_enabled: false
    rate_limit: null

  junior_intern:
    pii_redaction_enabled: true
    rate_limit:
      requests_per_hour: 10
      window_seconds: 3600
```



## Project Structure

```
security-governance-gatekeeper/
├── src/security_governance_gatekeeper/
│   ├── adapters/              # Port implementations
│   │   ├── persistence/       # PostgreSQL audit adapter
│   │   ├── pii/               # Presidio adapter
│   │   └── rate_limiting/     # Redis adapter
│   ├── api/
│   │   ├── main.py            # FastAPI app + config
│   │   ├── middleware/        # SecurityGatekeeperMiddleware
│   │   └── routers/           # Admin audit endpoints
│   ├── domain/                # Business logic
│   │   ├── models.py          # Domain entities
│   │   ├── policies.py        # Role policy registry
│   │   └── exceptions.py      # Domain exceptions
│   └── interfaces/            # Ports (abstract interfaces)
├── config/
│   └── roles.yaml             # Role policies
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Architecture

This project follows **Hexagonal Architecture** (Ports & Adapters):

- **Ports** (`interfaces/`): Abstract contracts defining capabilities
- **Adapters** (`adapters/`): Concrete implementations of ports
- **Domain** (`domain/`): Pure business logic, independent of infrastructure

```
┌─────────────────────────────────────────────────────────┐
│                      FastAPI Layer                       │
│            SecurityGatekeeperMiddleware                 │
│     (PII redaction, rate limiting, audit logging)       │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                    Domain Layer                          │
│  (models, policies, exceptions)                         │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                   Interfaces (Ports)                     │
│  PIIRedactorPort │ RateLimiterPort │ AuditLoggerPort   │
└────────────────────────┬────────────────────────────────┘
                         │
┌────────────────────────▼────────────────────────────────┐
│                   Adapters Layer                         │
│        Presidio │ Redis │ PostgreSQL                    │
└─────────────────────────────────────────────────────────┘
```

## License

MIT
