import request from 'supertest';
import argon2 from 'argon2';
import { decodeProtectedHeader, importJWK, jwtVerify, compactVerify } from 'jose';
import { createApp } from '../src/server.js';

let app;
let keyManager;
let db;

beforeAll(async () => {
  const ctx = await createApp({
    dbPath: ':memory:',
    encryptionSecret: 'test-secret'
  });
  app = ctx.app;
  keyManager = ctx.keyManager;
  db = ctx.db;
});

afterAll(async () => {
  if (keyManager) keyManager.stop();
  if (db) await db.close();
});

async function registerUser ({ username = 'alice', email = 'alice@example.com' } = {}) {
  const res = await request(app)
    .post('/register')
    .send({ username, email })
    .expect(201);

  expect(res.body).toHaveProperty('password');
  return res.body.password;
}

describe('register endpoint', () => {
  test('POST /register creates user with argon2 hash and returns UUID password', async () => {
    const password = await registerUser({ username: 'new-user', email: 'new-user@example.com' });
    expect(password).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i);

    const user = await db.get('SELECT * FROM users WHERE username = ?', ['new-user']);
    expect(user).toBeTruthy();
    expect(user.password_hash.startsWith('$argon2')).toBe(true);
    await expect(argon2.verify(user.password_hash, password)).resolves.toBe(true);
  });

  test('POST /register returns 409 on duplicate username', async () => {
    await registerUser({ username: 'dup-user', email: 'dup-user@example.com' });

    const res = await request(app)
      .post('/register')
      .send({ username: 'dup-user', email: 'other@example.com' })
      .expect(409);

    expect(res.body).toEqual({ error: 'user_exists_or_email_conflict' });
  });

  test('POST /register returns 400 when username missing', async () => {
    const res = await request(app)
      .post('/register')
      .send({ email: 'missing@example.com' })
      .expect(400);

    expect(res.body).toEqual({ error: 'username_required' });
  });

  test('GET /register returns 405', async () => {
    const res = await request(app).get('/register').expect(405);
    expect(res.headers.allow).toBe('POST');
  });
});

describe('jwks endpoints', () => {
  test('GET /healthz returns ok', async () => {
    const res = await request(app).get('/healthz').expect(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  test('GET /.well-known/jwks.json returns active keys only', async () => {
    const res = await request(app).get('/.well-known/jwks.json').expect(200);
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys.length).toBeGreaterThan(0);

    for (const k of res.body.keys) {
      expect(k).toHaveProperty('kid');
      expect(k).toHaveProperty('kty', 'RSA');
      expect(k).toHaveProperty('alg', 'RS256');
      expect(k).toHaveProperty('use', 'sig');
    }
  });

  test('GET /jwks returns jwks format', async () => {
    const res = await request(app).get('/jwks').expect(200);
    expect(Array.isArray(res.body.keys)).toBe(true);
  });

  test('POST /jwks returns 405', async () => {
    await request(app).post('/jwks').expect(405);
  });

  test('GET /jwks returns 500 when key manager throws', async () => {
    const original = keyManager.getActiveJWKS.bind(keyManager);
    keyManager.getActiveJWKS = async () => {
      throw new Error('jwks-error');
    };

    const res = await request(app).get('/jwks').expect(500);
    expect(res.body).toEqual({ error: 'internal_error' });

    keyManager.getActiveJWKS = original;
  });
});

describe('/auth endpoint', () => {
  beforeAll(async () => {
    await registerUser({ username: 'token-user', email: 'token-user@example.com' });
  });

  test('POST /auth returns valid JWT and logs auth request', async () => {
    const before = await db.get('SELECT COUNT(*) AS total FROM auth_logs');

    const res = await request(app)
      .post('/auth')
      .send({ username: 'token-user' })
      .expect(200);

    const { token, kid, expired } = res.body;
    expect(expired).toBe(false);

    const header = decodeProtectedHeader(token);
    expect(header.kid).toBe(kid);
    expect(header.alg).toBe('RS256');

    const jwks = await keyManager.getActiveJWKS();
    const jwk = jwks.keys.find(k => k.kid === kid);
    const keyLike = await importJWK(jwk, 'RS256');
    const { payload } = await jwtVerify(token, keyLike);
    expect(payload).toHaveProperty('username', 'token-user');

    const after = await db.get('SELECT COUNT(*) AS total FROM auth_logs');
    expect(after.total).toBeGreaterThan(before.total);
  });

  test('POST /auth?expired=1 returns expired token', async () => {
    const res = await request(app)
      .post('/auth?expired=1')
      .send({ username: 'token-user' })
      .expect(200);

    const { token, kid, expired } = res.body;
    expect(expired).toBe(true);

    const expiredRec = await keyManager.getExpiredSigningKey();
    expect(expiredRec.kid).toBe(kid);

    const keyLike = await importJWK(expiredRec.publicJwk, 'RS256');
    const verified = await compactVerify(token, keyLike);
    const payloadJson = JSON.parse(new TextDecoder().decode(verified.payload));
    expect(payloadJson.exp * 1000).toBeLessThanOrEqual(Date.now());
  });

  test('POST /auth returns 400 when username missing', async () => {
    const before = await db.get('SELECT COUNT(*) AS total FROM auth_logs');

    const res = await request(app)
      .post('/auth')
      .send({})
      .expect(400);

    expect(res.body).toEqual({ error: 'username_required' });

    const after = await db.get('SELECT COUNT(*) AS total FROM auth_logs');
    expect(after.total).toBe(before.total);
  });

  test('POST /auth returns 401 when user unknown', async () => {
    await request(app)
      .post('/auth')
      .send({ username: 'unknown-user' })
      .expect(401);
  });

  test('POST /auth enforces rate limiting', async () => {
    let last;
    for (let i = 0; i < 11; i++) {
      last = await request(app)
        .post('/auth')
        .set('X-Forwarded-For', '198.51.100.8')
        .send({ username: 'token-user' });
    }
    expect(last.status).toBe(429);
    expect(last.body).toEqual({ error: 'too_many_requests' });
  });

  test('GET /auth returns 405', async () => {
    const res = await request(app).get('/auth').expect(405);
    expect(res.headers.allow).toBe('POST');
  });

  test('POST /auth returns 500 when signing key retrieval fails', async () => {
    const original = keyManager.getSigningKey.bind(keyManager);
    keyManager.getSigningKey = async () => {
      throw new Error('boom');
    };

    const res = await request(app)
      .post('/auth')
      .send({ username: 'token-user' })
      .expect(500);

    expect(res.body).toEqual({ error: 'internal_error' });
    keyManager.getSigningKey = original;
  });

  test('POST /register returns 500 when user creation throws unexpectedly', async () => {
    const originalRun = db.run.bind(db);
    db.run = async (...args) => {
      if (String(args[0]).startsWith('INSERT INTO users')) {
        throw new Error('db-fail');
      }
      return originalRun(...args);
    };

    const res = await request(app)
      .post('/register')
      .send({ username: 'x-user', email: 'x@example.com' })
      .expect(500);

    expect(res.body).toEqual({ error: 'internal_error' });
    db.run = originalRun;
  });
});
