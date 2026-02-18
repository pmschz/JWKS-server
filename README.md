# JWKS Server (Educational Assignment)

A simple RESTful JWKS server that:
- Serves **JWKS** with **only unexpired** public keys
- Issues **JWTs** on `POST /auth` with a header `kid` pointing to the signing key
- Issues **expired tokens** on `POST /auth?expired=1` signed with an **expired key**
- Implements key **expiry** and moves expired keys to a separate store
- Provides tests with **>80% coverage**
- Linted via **ESLint**

## Endpoints

- `GET /.well-known/jwks.json` – JWKS with unexpired public keys
- `GET /jwks` – Same as above (convenience)
- `POST /auth` – Issues a valid JWT signed with an **active** key
- `POST /auth?expired=1` – Issues an **expired** JWT signed with an **expired** key

> The assignment does not require real user authentication; `/auth` accepts empty body.

## Run locally

```bash
npm install
npm run dev
# Server at http://localhost:8080
```

## Example

```bash
# Fetch JWKS
curl http://localhost:8080/.well-known/jwks.json

# Get a token
curl -X POST http://localhost:8080/auth

# Get an expired token
curl -X POST "http://localhost:8080/auth?expired=1"
```

## Tests & Coverage

```bash
npm test
npm run test:coverage
```

Expected coverage: >= 80%

## Lint

```bash
npm run lint
```

## Docker

```bash
docker build -t jwks-server .
docker run -p 8080:8080 jwks-server
```

## Notes

- JWTs include `kid` in the header. The JWKS endpoint serves only **unexpired** keys.
- Expired tokens are signed by an **expired** key and have `exp` in the past; consumers should fail validation.
- In production you would persist keys and use a rotation policy integrated with your KMS or HSM.

## Deliverables reminder
- Push this repo to GitHub.
- Add screenshot(s) of the provided blackbox test client running against your server.
- Add screenshot of Jest coverage (include identifying info as required).
