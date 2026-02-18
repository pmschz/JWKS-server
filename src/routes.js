import express from 'express';
import { SignJWT } from 'jose';

export function makeRoutes (keyManager) {
  const router = express.Router();

  const methodNotAllowed = (allow) => (req, res) => {
    res.set('Allow', allow);
    res.status(405).json({ error: 'method_not_allowed' });
  };

  router.get('/healthz', (req, res) => {
    res.json({ status: 'ok' });
  });

  router.route('/.well-known/jwks.json')
    .get((req, res) => {
      const jwks = keyManager.getActiveJWKS();
      res.json(jwks);
    })
    .all(methodNotAllowed('GET'));

  router.route('/jwks')
    .get((req, res) => {
      const jwks = keyManager.getActiveJWKS();
      res.json(jwks);
    })
    .all(methodNotAllowed('GET'));

  router.route('/auth')
    .post(async (req, res, next) => {
      try {
        const wantExpired = 'expired' in req.query;

        let keyRecord;
        let exp;
        if (wantExpired) {
          keyRecord = await keyManager.getExpiredSigningKey();
          exp = Math.floor(keyRecord.expiresAt.getTime() / 1000);
        } else {
          keyRecord = await keyManager.getSigningKey();
          exp = Math.floor(keyRecord.expiresAt.getTime() / 1000);
        }

        const user = { sub: 'user-123', name: 'Demo User' };

        const token = await new SignJWT({ ...user })
          .setProtectedHeader({ alg: 'RS256', kid: keyRecord.kid })
          .setIssuedAt()
          .setExpirationTime(exp)
          .sign(keyRecord.privateKey);

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
