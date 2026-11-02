import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';

const { Server } = createRequire(import.meta.url)('ssh2');

test('tryKeyboard 应通过真实 SSH 事件应答密码和多轮 MFA 提示', async () => {
  const hostKey = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  }).privateKey;
  const clients = new Set();
  const answers = [];
  const server = new Server({ hostKeys: [hostKey] }, (client) => {
    clients.add(client);
    client.on('error', () => {});
    client.on('close', () => clients.delete(client));
    client.on('authentication', (ctx) => {
      if (ctx.method !== 'keyboard-interactive') {
        ctx.reject(['keyboard-interactive']);
        return;
      }
      ctx.prompt([{ prompt: 'Password: ', echo: false }], (responses) => {
        answers.push(responses);
        if (responses[0] !== 'test-password') {
          ctx.reject();
          return;
        }
        ctx.prompt([{ prompt: 'Passcode or option (1-1): ', echo: true }], (responses) => {
          answers.push(responses);
          if (responses[0] === '1') ctx.accept();
          else ctx.reject();
        });
      });
    });
  });
  const manager = SSHConnectionManager.getInstance();
  const originalOtp = process.env.SSH_MCP_2FA_CODE;

  try {
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    process.env.SSH_MCP_2FA_CODE = '1';
    manager.setConfig({
      default: {
        host: '127.0.0.1',
        port: server.address().port,
        username: 'test',
        password: 'test-password',
        tryKeyboard: true,
        connectionTimeoutMs: 3000,
      },
    });

    await manager.connect();
    assert.deepEqual(answers, [['test-password'], ['1']]);
    assert.ok(manager.getClient());
  } finally {
    if (originalOtp === undefined) delete process.env.SSH_MCP_2FA_CODE;
    else process.env.SSH_MCP_2FA_CODE = originalOtp;
    manager.disconnect();
    for (const client of clients) client.end();
    await new Promise((resolve) => server.close(resolve));
  }
});
