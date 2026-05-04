import express from 'express';
import morgan from 'morgan';
import { KeyManager } from './keyManager.js';
import { makeRoutes } from './routes.js';
import { openDb } from './db.js';

export async function createApp ({
  dbPath = process.env.DB_PATH,
  encryptionSecret = process.env.NOT_MY_KEY
} = {}) {
  if (!encryptionSecret) {
    throw new Error('NOT_MY_KEY must be configured');
  }

  const app = express();
  app.set('trust proxy', true);

  // middleware
  app.use(express.json());
  app.use(morgan('dev'));

  const db = await openDb(dbPath);

  // key manager
  const km = new KeyManager({
    db,
    encryptionSecret
  });
  await km.init();

  // routes
  app.use(makeRoutes(km, db));

  // error handler
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'internal_error' });
  });

  return {
    app,
    keyManager: km,
    db
  };
}
