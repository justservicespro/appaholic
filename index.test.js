const test = require('node:test');
const assert = require('node:assert/strict');

test('GET / serves the landing page', async () => {
  const app = require('./index.js');
  const server = app.listen(0);

  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });

  const { port } = server.address();

  try {
    const response = await fetch(`http://127.0.0.1:${port}/`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(body, /<!DOCTYPE html>/i);
  } finally {
    await new Promise((resolve, reject) => server.close(err => (err ? reject(err) : resolve())));
  }
});

test('GET /auth serves the sign-in page', async () => {
  const app = require('./index.js');
  const server = app.listen(0);

  await new Promise((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });

  const { port } = server.address();

  try {
    const response = await fetch(`http://127.0.0.1:${port}/auth`);
    const body = await response.text();

    assert.equal(response.status, 200);
    assert.match(body, /sign in|signin|auth/i);
  } finally {
    await new Promise((resolve, reject) => server.close(err => (err ? reject(err) : resolve())));
  }
});
