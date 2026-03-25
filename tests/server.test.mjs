import request from 'supertest';
import { createApp } from '../src/server.js';

describe('Server', () => {
  let app;
  beforeAll(async () => {
    const res = await createApp();
    app = res.app;
  });

  it('GET /healthz returns ok', async () => {
    const res = await request(app).get('/healthz');
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ok');
  });

  // ...existing tests...
});
