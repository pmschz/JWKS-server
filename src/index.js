import { createApp } from './server.js';

const PORT = process.env.PORT || 8080;

const bootstrap = async () => {
  const { app } = await createApp();
  app.listen(PORT, () => {
    console.log(`JWKS server listening on http://localhost:${PORT}`);
  });
};

bootstrap().catch((e) => {
  console.error('Failed to start server:', e);
  process.exit(1);
});
