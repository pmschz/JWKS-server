# JWKS Server (Enhanced Security Assignment)

This implementation includes:
- JWKS serving with only unexpired public keys
- JWT issuance via `POST /auth` and `POST /auth?expired=1`
- AES encryption of private key material in SQLite using `NOT_MY_KEY`
- User registration with UUIDv4 password generation and Argon2 hashing
- Authentication request logging to `auth_logs`
- Time-window rate limiting on `POST /auth` (10 req/sec/IP)

## Required Environment Variable

PowerShell:

```powershell
$env:NOT_MY_KEY="replace-with-strong-secret"
```

## Endpoints

- `GET /.well-known/jwks.json`
- `GET /jwks`
- `POST /register`
- `POST /auth`
- `POST /auth?expired=1`

### POST /register

Request JSON:

```json
{ "username": "MyCoolUsername", "email": "MyCoolEmail@example.com" }
```

Response JSON:

```json
{ "password": "UUIDv4-value" }
```

### POST /auth

Request JSON:

```json
{ "username": "MyCoolUsername" }
```

Notes:
- `POST /auth` is rate-limited to 10 requests/second/IP.
- Only successful auth requests are inserted into `auth_logs`.

## Run

```bash
npm install
npm run dev
```

## Tests and Coverage

```bash
npm test
npm run test:coverage
```

## Lint

```bash
npm run lint
```

## Deliverables

- GitHub repo link
- Screenshot of Gradebot client run against your server
- Screenshot of coverage output
- Include identifying information in screenshots
