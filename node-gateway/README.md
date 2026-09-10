# SecureMailScope — Node.js API Gateway

Central API gateway for the SecureMailScope platform. Handles JWT authentication, PCAP file uploads, Django analysis orchestration, PostgreSQL persistence, and data retrieval APIs.

## Architecture

```
React Frontend  ←→  Node Gateway  ←→  Django Analysis API
                         ↕
                    PostgreSQL
```

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Configure environment
cp .env.example .env
# Edit .env with your PostgreSQL credentials and JWT secret

# 3. Run database migrations
npm run migrate

# 4. Start development server (mock Django enabled by default)
npm run dev
```

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/health` | No | Service health check |
| `POST` | `/api/auth/register` | No | Register a new user |
| `POST` | `/api/auth/login` | No | Login and receive JWT |
| `POST` | `/api/analyze` | Yes | Upload PCAP for analysis |
| `GET` | `/api/analyses` | Yes | List user's analyses |
| `GET` | `/api/analyses/:id` | Yes | Get analysis detail |
| `GET` | `/api/analyses/:id/export` | Yes | Export full analysis JSON |

## Environment Variables

See [`.env.example`](.env.example) for all configurable values.

Key variables:
- `DATABASE_URL` — PostgreSQL connection string
- `JWT_SECRET` — Secret for signing JWTs (must be changed in production)
- `DJANGO_BASE_URL` — Django analysis service URL
- `DJANGO_INTERNAL_KEY` — Service-to-service auth key
- `USE_MOCK_DJANGO` — Set `true` for development without Django
- `MAX_UPLOAD_SIZE_MB` — Maximum upload file size

## Testing

```bash
npm test
```

## Mock Django Mode

Set `USE_MOCK_DJANGO=true` in `.env` to use deterministic mock responses. This allows gateway development and testing without a running Django service.
