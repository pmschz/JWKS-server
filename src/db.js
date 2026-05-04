import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

const DEFAULT_DB_FILE = 'totally_not_my_privateKeys.db';

export async function openDb (dbFile = process.env.DB_PATH || DEFAULT_DB_FILE) {
  const db = await open({
    filename: dbFile,
    driver: sqlite3.Database
  });

  await db.exec('PRAGMA journal_mode = WAL;');
  await db.exec('PRAGMA busy_timeout = 5000;');

  await db.exec(`
    CREATE TABLE IF NOT EXISTS keys(
      kid INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT NOT NULL,
      exp INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      email TEXT UNIQUE,
      date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      last_login TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS auth_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      request_ip TEXT NOT NULL,
      request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      user_id INTEGER,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  return db;
}

export async function insertKey (db, encryptedKeyPayload, exp) {
  await db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [encryptedKeyPayload, exp]);
}

export async function getKey (db, expired = false) {
  const now = Math.floor(Date.now() / 1000);
  if (expired) {
    return db.get('SELECT * FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', [now]);
  }
  return db.get('SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', [now]);
}

export async function getAllValidKeys (db) {
  const now = Math.floor(Date.now() / 1000);
  return db.all('SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC', [now]);
}

export async function createUser (db, { username, email, passwordHash }) {
  const result = await db.run(
    'INSERT INTO users(username, password_hash, email) VALUES (?, ?, ?)',
    [username, passwordHash, email ?? null]
  );
  return result.lastID;
}

export async function getUserByUsername (db, username) {
  return db.get('SELECT * FROM users WHERE username = ?', [username]);
}

export async function updateLastLogin (db, userId) {
  await db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [userId]);
}

export async function insertAuthLog (db, { requestIp, userId }) {
  await db.run(
    'INSERT INTO auth_logs(request_ip, user_id) VALUES (?, ?)',
    [requestIp, userId]
  );
}
