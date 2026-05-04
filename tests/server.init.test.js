import { createApp } from '../src/server.js';

describe('server initialization', () => {
  test('throws when NOT_MY_KEY is missing', async () => {
    await expect(createApp({ dbPath: ':memory:', encryptionSecret: '' }))
      .rejects
      .toThrow('NOT_MY_KEY must be configured');
  });

  test('supports environment defaults for secret and db path', async () => {
    const oldKey = process.env.NOT_MY_KEY;
    const oldDb = process.env.DB_PATH;

    process.env.NOT_MY_KEY = 'env-secret';
    process.env.DB_PATH = ':memory:';

    const ctx = await createApp();
    expect(ctx.app).toBeTruthy();
    await ctx.db.close();

    process.env.NOT_MY_KEY = oldKey;
    process.env.DB_PATH = oldDb;
  });
});
