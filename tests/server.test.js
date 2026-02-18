import request from 'supertest';
import { createApp } from '../src/server.js';
import { decodeProtectedHeader, importJWK, jwtVerify, compactVerify } from 'jose';

let app;
let keyManager;

beforeAll(async () => {
  const res = await createApp();
  app = res.app;
  keyManager = res.keyManager;
});

afterAll(() => {
  if (keyManager) keyManager.stop();
});

describe('JWKS endpoint', () => {
  test('GET /healthz returns ok', async () => {
    const res = await request(app).get('/healthz').expect(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  test('returns only unexpired keys', async () => {
    const res = await request(app).get('/.well-known/jwks.json').expect(200);
    expect(res.body).toHaveProperty('keys');
    expect(Array.isArray(res.body.keys)).toBe(true);
    expect(res.body.keys.length).toBeGreaterThan(0);

    for (const k of res.body.keys) {
      expect(k).toHaveProperty('kid');
      expect(k).toHaveProperty('use', 'sig');
      expect(k).toHaveProperty('alg', 'RS256');
      expect(k).toHaveProperty('kty', 'RSA');
      expect(k).toHaveProperty('n');
      expect(k).toHaveProperty('e');
    }

    const expiredKids = new Set(Array.from(keyManager.expired.keys()));
    for (const k of res.body.keys) {
      expect(expiredKids.has(k.kid)).toBe(false);
    }
  });

  test('GET /jwks returns same shape as well-known endpoint', async () => {
    const jwksRes = await request(app).get('/jwks').expect(200);
    expect(jwksRes.body).toHaveProperty('keys');
    expect(Array.isArray(jwksRes.body.keys)).toBe(true);
  });

  test('POST /.well-known/jwks.json returns 405 and Allow header', async () => {
    const res = await request(app).post('/.well-known/jwks.json').expect(405);
    expect(res.headers.allow).toBe('GET');
    expect(res.body).toEqual({ error: 'method_not_allowed' });
  });
});

describe('/auth endpoint', () => {
  test('POST /auth returns a valid, unexpired JWT with kid', async () => {
    const res = await request(app).post('/auth').expect(200);
    expect(res.body).toHaveProperty('token');
    const { token, kid, expired } = res.body;
    expect(expired).toBe(false);

    const header = decodeProtectedHeader(token);
    expect(header).toHaveProperty('kid', kid);
    expect(header).toHaveProperty('alg', 'RS256');

    const jwks = keyManager.getActiveJWKS();
    const jwk = jwks.keys.find(k => k.kid === kid);
    expect(jwk).toBeTruthy();

    const keyLike = await importJWK(jwk, 'RS256');
    const { payload } = await jwtVerify(token, keyLike);
    expect(payload).toHaveProperty('sub', 'user-123');
    expect(payload.exp * 1000).toBeGreaterThan(Date.now());
  });

  test('POST /auth?expired=1 returns an expired JWT signed with expired key', async () => {
    const res = await request(app).post('/auth?expired=1').expect(200);
    const { token, kid, expired } = res.body;
    expect(expired).toBe(true);

    const header = decodeProtectedHeader(token);
    expect(header.kid).toBe(kid);

    expect(keyManager.expired.has(kid)).toBe(true);
    const expiredRec = keyManager.expired.get(kid);

    const keyLike = await importJWK(expiredRec.publicJwk, 'RS256');
    const verified = await compactVerify(token, keyLike);
    expect(verified).toBeTruthy();

    const payloadJson = JSON.parse(new TextDecoder().decode(verified.payload));
    expect(payloadJson.exp * 1000).toBeLessThanOrEqual(Date.now());
  });

  test('POST /auth returns 500 when signing key retrieval throws', async () => {
    const originalGetSigningKey = keyManager.getSigningKey.bind(keyManager);
    keyManager.getSigningKey = async () => {
      throw new Error('boom');
    };

    const res = await request(app).post('/auth').expect(500);
    expect(res.body).toEqual({ error: 'internal_error' });

    keyManager.getSigningKey = originalGetSigningKey;
  });

  test('GET /auth returns 405 and Allow header', async () => {
    const res = await request(app).get('/auth').expect(405);
    expect(res.headers.allow).toBe('POST');
    expect(res.body).toEqual({ error: 'method_not_allowed' });
  });
});
