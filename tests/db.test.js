import {
  createUser,
  getUserByUsername,
  insertAuthLog,
  insertKey,
  getAllValidKeys,
  getKey,
  openDb,
  updateLastLogin
} from '../src/db.js';

describe('db helpers', () => {
  let db;

  beforeEach(async () => {
    db = await openDb(':memory:');
  });

  afterEach(async () => {
    if (db) await db.close();
  });

  test('key insert and retrieval handles active/expired', async () => {
    const now = Math.floor(Date.now() / 1000);
    await insertKey(db, 'enc-key-1', now + 3600);
    await insertKey(db, 'enc-key-2', now - 3600);

    const active = await getKey(db, false);
    const expired = await getKey(db, true);
    const all = await getAllValidKeys(db);

    expect(active).toBeTruthy();
    expect(expired).toBeTruthy();
    expect(all.length).toBeGreaterThan(0);
  });

  test('user creation and auth log insert work', async () => {
    const userId = await createUser(db, {
      username: 'db-user',
      email: null,
      passwordHash: 'hash'
    });

    const user = await getUserByUsername(db, 'db-user');
    expect(user.id).toBe(userId);

    await updateLastLogin(db, user.id);
    const updated = await getUserByUsername(db, 'db-user');
    expect(updated.last_login).toBeTruthy();

    await insertAuthLog(db, { requestIp: '127.0.0.1', userId });
    const log = await db.get('SELECT * FROM auth_logs LIMIT 1');
    expect(log.request_ip).toBe('127.0.0.1');
    expect(log.user_id).toBe(userId);
  });
});
