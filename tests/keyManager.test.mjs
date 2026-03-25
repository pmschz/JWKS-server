import { KeyManager } from '../src/keyManager.js';

describe('KeyManager (DB-backed)', () => {
  let km;
  beforeAll(async () => {
    km = new KeyManager();
    await km.init();
  });

  it('should provide a valid signing key', async () => {
    const key = await km.getSigningKey();
    expect(key).toBeDefined();
    expect(key.privateKey).toBeDefined();
    expect(key.publicJwk).toBeDefined();
    expect(key.kid).toBeDefined();
    expect(key.expiresAt).toBeInstanceOf(Date);
  });

  it('should provide a valid expired signing key', async () => {
    const key = await km.getExpiredSigningKey();
    expect(key).toBeDefined();
    expect(key.privateKey).toBeDefined();
    expect(key.publicJwk).toBeDefined();
    expect(key.kid).toBeDefined();
    expect(key.expiresAt).toBeInstanceOf(Date);
    expect(key.expiresAt.getTime()).toBeLessThan(Date.now());
  });

  it('should return all valid keys in JWKS', async () => {
    const jwks = await km.getActiveJWKS();
    expect(jwks).toBeDefined();
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBeGreaterThan(0);
    for (const k of jwks.keys) {
      expect(k.kid).toBeDefined();
      expect(k.kty).toBe('RSA');
    }
  });
});
