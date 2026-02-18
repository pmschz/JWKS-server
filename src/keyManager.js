import crypto from 'crypto';
import { generateKeyPair, exportJWK } from 'jose';

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
  constructor ({
    activeTtlSec = 15 * 60, // 15 minutes
    expiredOffsetSec = -5 * 60, // expired 5 minutes ago
    checkIntervalMs = 2000
  } = {}) {
    this.active = new Map(); // kid -> KeyRecord
    this.expired = new Map(); // kid -> KeyRecord
    this.activeTtlSec = activeTtlSec;
    this.expiredOffsetSec = expiredOffsetSec;
    this.checkIntervalMs = checkIntervalMs;
    this._timer = null;
  }

  async init () {
    // Ensure at least one active and one expired key exist
    await this._ensureActiveKey();
    await this._ensureExpiredKey();

    // Periodic expiry sweep
    this._timer = setInterval(() => {
      this._sweep();
    }, this.checkIntervalMs);
  }

  stop () {
    if (this._timer) clearInterval(this._timer);
  }

  async _createKey (expiresInSec) {
    const { publicKey, privateKey } = await generateKeyPair('RS256', { modulusLength: 2048 });
    const kid = crypto.randomUUID();
    const publicJwk = await exportJWK(publicKey);
    publicJwk.kty = publicJwk.kty || 'RSA';
    publicJwk.use = 'sig';
    publicJwk.alg = 'RS256';
    publicJwk.kid = kid;

    const expiresAt = new Date(Date.now() + (expiresInSec * 1000));
    return new KeyRecord({ kid, privateKey, publicJwk, expiresAt });
  }

  async _ensureActiveKey () {
    if (this.getActive().length === 0) {
      const rec = await this._createKey(this.activeTtlSec);
      this.active.set(rec.kid, rec);
    }
  }

  async _ensureExpiredKey () {
    if (this.expired.size === 0) {
      const rec = await this._createKey(this.expiredOffsetSec);
      this.expired.set(rec.kid, rec);
    }
  }

  _sweep (now = new Date()) {
    for (const [kid, rec] of this.active.entries()) {
      if (rec.isExpired(now)) {
        this.active.delete(kid);
        this.expired.set(kid, rec);
      }
    }
    if (this.getActive().length === 0) {
      this._createKey(this.activeTtlSec).then(r => this.active.set(r.kid, r));
    }
  }

  getActive (now = new Date()) {
    return Array.from(this.active.values()).filter(r => !r.isExpired(now));
  }

  getActiveJWKS (now = new Date()) {
    return {
      keys: this.getActive(now).map(r => r.publicJwk)
    };
  }

  async getSigningKey () {
    let actives = this.getActive();
    if (actives.length === 0) {
      await this._ensureActiveKey();
      actives = this.getActive();
    }
    return actives[0];
  }

  async getExpiredSigningKey () {
    if (this.expired.size === 0) {
      await this._ensureExpiredKey();
    }
    return Array.from(this.expired.values())[0];
  }
}
