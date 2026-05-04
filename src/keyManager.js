import { generateKeyPair, exportJWK, importJWK } from 'jose';
import { decryptText, encryptText } from './crypto.js';
import { getAllValidKeys, getKey, insertKey } from './db.js';

export class KeyRecord {
  constructor ({ kid, privateKey, publicJwk, expiresAt }) {
    this.kid = kid;
    this.privateKey = privateKey;
    this.publicJwk = publicJwk;
    this.expiresAt = expiresAt;
  }

  isExpired (at = new Date()) {
    return this.expiresAt.getTime() <= at.getTime();
  }
}

export class KeyManager {
  constructor ({
    db,
    encryptionSecret,
    activeTtlSec = 15 * 60,
    expiredOffsetSec = -5 * 60
  } = {}) {
    if (!db) throw new Error('db is required');
    if (!encryptionSecret) throw new Error('NOT_MY_KEY must be configured');

    this.db = db;
    this.encryptionSecret = encryptionSecret;
    this.activeTtlSec = activeTtlSec;
    this.expiredOffsetSec = expiredOffsetSec;
  }

  async init () {
    await this._ensureActiveKey();
    await this._ensureExpiredKey();
  }

  stop () {
    // No periodic timer in DB-backed manager.
  }

  async _createKey (expiresInSec) {
    const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const privateJwk = await exportJWK(privateKey);

    const exp = Math.floor((Date.now() + (expiresInSec * 1000)) / 1000);
    const encryptedPayload = encryptText(JSON.stringify(privateJwk), this.encryptionSecret);
    await insertKey(this.db, encryptedPayload, exp);
  }

  async _ensureActiveKey () {
    const active = await getKey(this.db, false);
    if (!active) {
      await this._createKey(this.activeTtlSec);
    }
  }

  async _ensureExpiredKey () {
    const expired = await getKey(this.db, true);
    if (!expired) {
      await this._createKey(this.expiredOffsetSec);
    }
  }

  async _rowToKeyRecord (row) {
    const decrypted = decryptText(row.key, this.encryptionSecret);
    const privateJwk = JSON.parse(decrypted);
    const privateKey = await importJWK(privateJwk, 'RS256');

    const publicJwk = {
      kty: 'RSA',
      n: privateJwk.n,
      e: privateJwk.e,
      use: 'sig',
      alg: 'RS256',
      kid: String(row.kid)
    };

    return new KeyRecord({
      kid: String(row.kid),
      privateKey,
      publicJwk,
      expiresAt: new Date(row.exp * 1000)
    });
  }

  async getSigningKey () {
    await this._ensureActiveKey();
    const row = await getKey(this.db, false);
    if (!row) throw new Error('No valid signing key found');
    return this._rowToKeyRecord(row);
  }

  async getExpiredSigningKey () {
    await this._ensureExpiredKey();
    const row = await getKey(this.db, true);
    if (!row) throw new Error('No expired signing key found');
    return this._rowToKeyRecord(row);
  }

  async getActiveJWKS () {
    const rows = await getAllValidKeys(this.db);
    const keys = await Promise.all(rows.map(async row => {
      const rec = await this._rowToKeyRecord(row);
      return rec.publicJwk;
    }));
    return { keys };
  }
}
