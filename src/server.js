import express from 'express';
import morgan from 'morgan';
import { KeyManager } from './keyManager.js';
import { makeRoutes } from './routes.js';

export async function createApp () {
  const app = express();

  // middleware
  app.use(express.json());
  app.use(morgan('dev'));

  // key manager
  const km = new KeyManager();
  await km.init();

  // routes
  app.use(makeRoutes(km));

  // error handler
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    console.error(err);
    res.status(500).json({ error: 'internal_error' });
  });

  return { app, keyManager: km };
}
