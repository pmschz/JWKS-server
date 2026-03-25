
import crypto from 'crypto';
import { generateKeyPair, exportJWK, importPKCS8, exportPKCS8 } from 'jose';
import { openDb, insertKey, getKey, getAllValidKeys } from './db.js';

/**
 * Represents a single RSA key pair + metadata.
 */
export class KeyRecord {
  constructor ({ kid, privateKey, publicJwk, expiresAt }) {
    this.kid = kid;
    this.privateKey = privateKey; // KeyLike
    this.publicJwk = publicJwk; // { kty, n, e, alg, use, kid }
    this.expiresAt = expiresAt; // Date
  }

  isExpired (at = new Date()) {
    return this.expiresAt.getTime() <= at.getTime();
  }
}

/**
 * Manages active and expired keys, handles expiry & rotation.
 */

export class KeyManager {
  constructor({
    activeTtlSec = 15 * 60, // 15 minutes
    expiredOffsetSec = -5 * 60 // expired 5 minutes ago
  } = {}) {
    this.activeTtlSec = activeTtlSec;
    this.expiredOffsetSec = expiredOffsetSec;
    this.db = null;
  }


  async init() {
    this.db = await openDb();
    // Ensure at least one active and one expired key exist in DB
    await this._ensureActiveKey();
    await this._ensureExpiredKey();
  }


  stop() {
    // No-op for DB version
  }


  async _createKey(expiresInSec) {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const pem = await exportPKCS8(privateKey);
    const exp = Math.floor((Date.now() + (expiresInSec * 1000)) / 1000);
    await insertKey(this.db, pem, exp);
  }


  async _ensureActiveKey() {
    const key = await getKey(this.db, false);
    if (!key) {
      await this._createKey(this.activeTtlSec);
    }
  }

  async _ensureExpiredKey() {
    const key = await getKey(this.db, true);
    if (!key) {
      await this._createKey(this.expiredOffsetSec);
    }
  }


  async getSigningKey() {
    const keyRow = await getKey(this.db, false);
    if (!keyRow) throw new Error('No valid signing key found');
    return this._rowToKeyRecord(keyRow);
  }

  async getExpiredSigningKey() {
    const keyRow = await getKey(this.db, true);
    if (!keyRow) throw new Error('No expired signing key found');
    return this._rowToKeyRecord(keyRow);
  }

  async getActiveJWKS() {
    const rows = await getAllValidKeys(this.db);
    const keys = await Promise.all(rows.map(async row => {
      const rec = await this._rowToKeyRecord(row);
      return rec.publicJwk;
    }));
    return { keys };
  }

  async _rowToKeyRecord(row) {
    // row: { kid, key, exp }
    const privateKey = await importPKCS8(row.key, 'RS256');
    // For JWKS, we need the public JWK. We'll re-export from privateKey.
    const publicJwk = await exportJWK(privateKey);
    publicJwk.kty = publicJwk.kty || 'RSA';
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';
    publicJwk.kid = String(row.kid);
    const expiresAt = new Date(row.exp * 1000);
    return new KeyRecord({ kid: String(row.kid), privateKey, publicJwk, expiresAt });
  }
}
