import { openDb } from '../src/db.js';
import { decryptText } from '../src/crypto.js';
import { KeyManager, KeyRecord } from '../src/keyManager.js';

describe('KeyManager', () => {
  let db;

  afterEach(async () => {
    if (db) {
      await db.close();
      db = null;
    }
  });

  test('constructor validates required dependencies', () => {
    expect(() => new KeyManager({ encryptionSecret: 'x' })).toThrow('db is required');
    expect(() => new KeyManager({ db: {} })).toThrow('NOT_MY_KEY must be configured');
  });

  test('getSigningKey throws when active key cannot be resolved', async () => {
    db = await openDb(':memory:');
    const km = new KeyManager({ db, encryptionSecret: 'test-secret' });
    km._ensureActiveKey = async () => {};
    await expect(km.getSigningKey()).rejects.toThrow('No valid signing key found');
  });

  test('getExpiredSigningKey throws when expired key cannot be resolved', async () => {
    db = await openDb(':memory:');
    const km = new KeyManager({ db, encryptionSecret: 'test-secret' });
    km._ensureExpiredKey = async () => {};
    await expect(km.getExpiredSigningKey()).rejects.toThrow('No expired signing key found');
  });

  test('KeyRecord expiration helper works', () => {
    const rec = new KeyRecord({
      kid: '1',
      privateKey: {},
      publicJwk: {},
      expiresAt: new Date('2000-01-01T00:00:00.000Z')
    });

    expect(rec.isExpired(new Date('1999-01-01T00:00:00.000Z'))).toBe(false);
    expect(rec.isExpired(new Date('2001-01-01T00:00:00.000Z'))).toBe(true);
  });

  test('init creates both active and expired keys', async () => {
    db = await openDb(':memory:');
    const km = new KeyManager({
      db,
      encryptionSecret: 'test-secret',
      activeTtlSec: 60,
      expiredOffsetSec: -60
    });
    await km.init();

    const active = await db.get('SELECT COUNT(*) AS total FROM keys WHERE exp > ?', [Math.floor(Date.now() / 1000)]);
    const expired = await db.get('SELECT COUNT(*) AS total FROM keys WHERE exp <= ?', [Math.floor(Date.now() / 1000)]);

    expect(active.total).toBeGreaterThan(0);
    expect(expired.total).toBeGreaterThan(0);
    km.stop();
  });

  test('getSigningKey and getExpiredSigningKey return valid key records', async () => {
    db = await openDb(':memory:');
    const km = new KeyManager({ db, encryptionSecret: 'test-secret' });
    await km.init();

    const activeRec = await km.getSigningKey();
    const expiredRec = await km.getExpiredSigningKey();

    expect(activeRec.kid).toBeTruthy();
    expect(activeRec.publicJwk.alg).toBe('RS256');
    expect(expiredRec.kid).toBeTruthy();
    expect(expiredRec.expiresAt.getTime()).toBeLessThanOrEqual(Date.now());
    km.stop();
  });

  test('stores encrypted private key payload in DB', async () => {
    db = await openDb(':memory:');
    const km = new KeyManager({ db, encryptionSecret: 'test-secret' });
    await km.init();

    const row = await db.get('SELECT key FROM keys LIMIT 1');
    expect(row.key).toMatch(/^[^:]+:[^:]+:[^:]+$/);

    const decrypted = decryptText(row.key, 'test-secret');
    const parsed = JSON.parse(decrypted);
    expect(parsed).toHaveProperty('kty', 'RSA');

    km.stop();
  });
});
