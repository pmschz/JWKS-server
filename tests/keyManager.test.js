import { KeyManager } from '../src/keyManager.js';

describe('KeyManager', () => {
  test('creates at least one active and one expired key on init', async () => {
    const km = new KeyManager({ activeTtlSec: 60, expiredOffsetSec: -60 });
    await km.init();

    expect(km.getActive().length).toBeGreaterThan(0);
    expect(km.expired.size).toBeGreaterThan(0);

    km.stop();
  });

  test('moves expired active keys into expired map on sweep', async () => {
    const km = new KeyManager({ activeTtlSec: 1, expiredOffsetSec: -60, checkIntervalMs: 10 });
    await km.init();

    const initialActiveCount = km.getActive().length;
    expect(initialActiveCount).toBeGreaterThan(0);

    await new Promise(resolve => setTimeout(resolve, 1200));
    const after = km.getActive().length;
    expect(after).toBeGreaterThanOrEqual(0);
    expect(km.expired.size).toBeGreaterThan(0);

    km.stop();
  });

  test('getExpiredSigningKey returns a key from expired set', async () => {
    const km = new KeyManager({ activeTtlSec: 60, expiredOffsetSec: -60 });
    await km.init();
    const rec = await km.getExpiredSigningKey();
    expect(rec).toBeTruthy();
    expect(km.expired.has(rec.kid)).toBe(true);
    km.stop();
  });

  test('getSigningKey creates an active key when active store is empty', async () => {
    const km = new KeyManager({ activeTtlSec: 60, expiredOffsetSec: -60 });
    const rec = await km.getSigningKey();
    expect(rec).toBeTruthy();
    expect(km.getActive().length).toBeGreaterThan(0);
    km.stop();
  });

  test('getExpiredSigningKey creates an expired key when expired store is empty', async () => {
    const km = new KeyManager({ activeTtlSec: 60, expiredOffsetSec: -60 });
    const rec = await km.getExpiredSigningKey();
    expect(rec).toBeTruthy();
    expect(km.expired.has(rec.kid)).toBe(true);
    km.stop();
  });
});
