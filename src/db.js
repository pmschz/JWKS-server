// SQLite database utility for JWKS server
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

const DB_FILE = 'totally_not_my_privateKeys.db';
const TABLE_SCHEMA = `CREATE TABLE IF NOT EXISTS keys(
    kid INTEGER PRIMARY KEY AUTOINCREMENT,
    key BLOB NOT NULL,
    exp INTEGER NOT NULL
)`;

export async function openDb() {
  const db = await open({
    filename: DB_FILE,
    driver: sqlite3.Database
  });
  await db.exec(TABLE_SCHEMA);
  return db;
}

export async function insertKey(db, keyPem, exp) {
  // Use parameterized query to prevent SQL injection
  await db.run('INSERT INTO keys (key, exp) VALUES (?, ?)', [keyPem, exp]);
}

export async function getKey(db, expired = false) {
  const now = Math.floor(Date.now() / 1000);
  if (expired) {
    return db.get('SELECT * FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1', [now]);
  } else {
    return db.get('SELECT * FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', [now]);
  }
}

export async function getAllValidKeys(db) {
  const now = Math.floor(Date.now() / 1000);
  return db.all('SELECT * FROM keys WHERE exp > ?', [now]);
}
