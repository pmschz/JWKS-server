import crypto from 'crypto';
import express from 'express';
import argon2 from 'argon2';
import { SignJWT } from 'jose';
import {
  createUser,
  getUserByUsername,
  insertAuthLog,
  updateLastLogin
} from './db.js';

class SlidingWindowRateLimiter {
  constructor ({ maxRequests = 10, windowMs = 1000 } = {}) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.byIp = new Map();
  }

  isAllowed (ip, now = Date.now()) {
    const key = ip || 'unknown';
    const threshold = now - this.windowMs;
    const current = (this.byIp.get(key) || []).filter(ts => ts > threshold);

    if (current.length >= this.maxRequests) {
      this.byIp.set(key, current);
      return false;
    }

    current.push(now);
    this.byIp.set(key, current);
    return true;
  }
}

export function makeRoutes (keyManager, db) {
  const router = express.Router();
  const limiter = new SlidingWindowRateLimiter({ maxRequests: 10, windowMs: 1000 });

  const argon2Options = {
    type: argon2.argon2id,
    timeCost: Number(process.env.ARGON2_TIME_COST || 3),
    memoryCost: Number(process.env.ARGON2_MEMORY_COST || 65536),
    parallelism: Number(process.env.ARGON2_PARALLELISM || 1),
    hashLength: Number(process.env.ARGON2_HASH_LENGTH || 32)
  };

  const methodNotAllowed = (allow) => (req, res) => {
    res.set('Allow', allow);
    res.status(405).json({ error: 'method_not_allowed' });
  };

  router.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
  });

  router.route('/.well-known/jwks.json')
    .get(async (req, res, next) => {
      try {
        const jwks = await keyManager.getActiveJWKS();
        res.json(jwks);
      } catch (err) {
        next(err);
      }
    })
    .all(methodNotAllowed('GET'));

  router.route('/jwks')
    .get(async (req, res, next) => {
      try {
        const jwks = await keyManager.getActiveJWKS();
        res.json(jwks);
      } catch (err) {
        next(err);
      }
    })
    .all(methodNotAllowed('GET'));

  router.route('/register')
    .post(async (req, res, next) => {
      try {
        const { username, email } = req.body || {};
        if (!username || typeof username !== 'string') {
          return res.status(400).json({ error: 'username_required' });
        }

        const password = crypto.randomUUID();
        const passwordHash = await argon2.hash(password, argon2Options);
        await createUser(db, { username, email, passwordHash });

        res.status(201).json({ password });
      } catch (err) {
        if (err && err.code === 'SQLITE_CONSTRAINT') {
          return res.status(409).json({ error: 'user_exists_or_email_conflict' });
        }
        next(err);
      }
    })
    .all(methodNotAllowed('POST'));

  router.route('/auth')
    .post(async (req, res, next) => {
      try {
        const requestIp = req.ip || req.socket.remoteAddress || 'unknown';
        if (!limiter.isAllowed(requestIp)) {
          return res.status(429).json({ error: 'too_many_requests' });
        }

        const { username } = req.body || {};
        if (!username || typeof username !== 'string') {
          return res.status(400).json({ error: 'username_required' });
        }

        const userRecord = await getUserByUsername(db, username);
        if (!userRecord) {
          return res.status(401).json({ error: 'invalid_user' });
        }

        const wantExpired = 'expired' in req.query;
        let keyRecord;
        if (wantExpired) {
          keyRecord = await keyManager.getExpiredSigningKey();
        } else {
          keyRecord = await keyManager.getSigningKey();
        }

        const exp = Math.floor(keyRecord.expiresAt.getTime() / 1000);
        const token = await new SignJWT({
          sub: String(userRecord.id),
          username: userRecord.username
        })
          .setProtectedHeader({ alg: 'RS256', kid: keyRecord.kid })
          .setIssuedAt()
          .setExpirationTime(exp)
          .sign(keyRecord.privateKey);

        await insertAuthLog(db, { requestIp, userId: userRecord.id });
        await updateLastLogin(db, userRecord.id);

        res.json({
          token,
          kid: keyRecord.kid,
          expiresAt: new Date(exp * 1000).toISOString(),
          expired: wantExpired
        });
      } catch (err) {
        next(err);
      }
    })
    .all(methodNotAllowed('POST'));

  return router;
}
