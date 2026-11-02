import { describe, it, before, afterEach } from 'node:test';
import assert from 'node:assert';
import { EventEmitter } from 'node:events';
import { setTimeout as delay } from 'node:timers/promises';
import { SSHConnectionManager } from '../build/services/ssh-connection-manager.js';
import { ToolError } from '../build/utils/tool-error.js';

class FakeExecStream extends EventEmitter {
  constructor() {
    super();
    this.stderr = new EventEmitter();
  }

  close() {
    this.emit('close');
  }
}

class FakeShellChannel extends EventEmitter {
  constructor() {
    super();
    this.stderr = new EventEmitter();
    this.writes = [];
  }

  write(data) {
    this.writes.push(data);
    this.emit('write', data);
    return true;
  }

  close() {
    this.emit('close');
  }
}

class FakeClient extends EventEmitter {
  constructor(handlers = {}) {
    super();
    this.handlers = handlers;
    this.connectCalls = [];
    this.execCalls = [];
    this.shellCalls = [];
    this.endCalls = 0;
  }

  connect(config) {
    this.connectCalls.push(config);
    this.handlers.onConnect?.(config, this);
  }

  exec(command, optionsOrCallback, maybeCallback) {
    const hasOptions = typeof optionsOrCallback !== 'function';
    const options = hasOptions ? optionsOrCallback : undefined;
    const callback = hasOptions ? maybeCallback : optionsOrCallback;
    this.execCalls.push({ command, options });
    this.handlers.onExec?.({ command, options, callback }, this);
  }

  shell(options, callback) {
    this.shellCalls.push(options);
    this.handlers.onShell?.({ options, callback }, this);
  }

  sftp(callback) {
    this.handlers.onSftp?.(callback, this);
  }

  end() {
    this.endCalls += 1;
    this.emit('close');
  }

  destroy() {
    this.endCalls += 1;
    this.emit('close');
  }
}

function createPasswordConfig(overrides = {}) {
  return {
    name: 'exec',
    host: '192.168.1.100',
    port: 22,
    username: 'devuser',
    password: 'devpass',
    transportMode: 'exec',
    ...overrides,
  };
}

function extractMarkerId(payload, prefix) {
  const match = payload.match(new RegExp(`${prefix}(.+?)__`));
  return match?.[1];
}

function emitShellCommandResult(channel, commandId, output, exitCode) {
  channel.emit(
    'data',
    Buffer.from(
      `__MCP_BEGIN__${commandId}__\r\n${output}\n__MCP_END__${commandId}__RC__${exitCode}__\r\n`,
    ),
  );
}

describe('script parameter, EOL normalization and parse-error diagnostics', () => {
  let manager;
  let originalCreateClient;
  let originalScheduleStatusCollection;

  before(() => {
    manager = SSHConnectionManager.getInstance();
    originalCreateClient = manager.createClient;
    originalScheduleStatusCollection = manager.scheduleStatusCollection;
  });

  afterEach(() => {
    manager.disconnect();
    manager.createClient = originalCreateClient;
    manager.scheduleStatusCollection = originalScheduleStatusCollection;
  });

  function setupExec(handlers) {
    const client = new FakeClient({
      onConnect: () => setImmediate(() => client.emit('ready')),
      onExec: handlers.onExec,
    });
    manager.createClient = () => client;
    manager.scheduleStatusCollection = () => {};
    manager.setConfig({ exec: createPasswordConfig({ name: 'exec' }) });
    return client;
  }

  it('script передаётся как base64-обёртка без изменения кавычек', async () => {
    const script =
      "echo hi\ndocker exec c python3 -c \"print('nested')\"\n";
    const expectedEncoded = Buffer.from(script, 'utf8').toString('base64');

    const client = setupExec({
      onExec: ({ command, callback }) => {
        const stream = new FakeExecStream();
        callback(undefined, stream);
        setImmediate(() => {
          stream.emit('data', Buffer.from('hi\n'));
          stream.emit('exit', 0);
          stream.emit('close', 0);
        });
      },
    });

    const result = await manager.executeCommand(undefined, undefined, 'exec', {
      script,
    });

    assert.strictEqual(result, 'hi');
    assert.strictEqual(client.execCalls.length, 1);
    assert.strictEqual(
      client.execCalls[0].command,
      `printf %s '${expectedEncoded}' | base64 -d | bash`,
    );
    // Обёртка декодируется обратно в исходный скрипт.
    const decoded = Buffer.from(
      client.execCalls[0].command.match(/printf %s '([^']+)'/)[1],
      'base64',
    ).toString('utf8');
    assert.strictEqual(decoded, script);
  });

  it('script + directory: cd подставляется перед обёрткой', async () => {
    const script = 'pwd\n';
    const expectedEncoded = Buffer.from(script, 'utf8').toString('base64');

    const client = setupExec({
      onExec: ({ command, callback }) => {
        const stream = new FakeExecStream();
        callback(undefined, stream);
        setImmediate(() => {
          stream.emit('data', Buffer.from('/tmp\n'));
          stream.emit('exit', 0);
          stream.emit('close', 0);
        });
      },
    });

    await manager.executeCommand(undefined, '/tmp', 'exec', { script });

    assert.strictEqual(
      client.execCalls[0].command,
      `cd -- '/tmp' && printf %s '${expectedEncoded}' | base64 -d | bash`,
    );
  });

  it('CRLF в cmdString нормализуется в LF перед отправкой', async () => {
    const client = setupExec({
      onExec: ({ command, callback }) => {
        const stream = new FakeExecStream();
        callback(undefined, stream);
        setImmediate(() => {
          stream.emit('data', Buffer.from('a\nb\n'));
          stream.emit('exit', 0);
          stream.emit('close', 0);
        });
      },
    });

    await manager.executeCommand("printf 'a\r\nb'\r\n", undefined, 'exec');

    const sent = client.execCalls[0].command;
    assert.ok(!sent.includes('\r'), `command must not contain CR: ${JSON.stringify(sent)}`);
    assert.ok(sent.includes("printf 'a\nb'"));
  });

  it('ошибка парсинга bash дополняется подсказкой и командой', async () => {
    const client = setupExec({
      onExec: ({ command, callback }) => {
        const stream = new FakeExecStream();
        callback(undefined, stream);
        setImmediate(() => {
          stream.stderr.emit(
            'data',
            Buffer.from("bash: -c: line 10: syntax error near unexpected token `('\n"),
          );
          stream.emit('exit', 2);
          stream.emit('close', 2);
        });
      },
    });

    await assert.rejects(
      () => manager.executeCommand('echo "unclosed', undefined, 'exec'),
      (error) => {
        assert.ok(error instanceof ToolError);
        assert.strictEqual(error.code, 'COMMAND_EXECUTION_ERROR');
        assert.match(error.message, /syntax error/);
        assert.match(error.message, /\[hint\]/);
        assert.match(error.message, /one level of shell quoting/);
        assert.match(error.message, /`script` parameter/);
        assert.match(error.message, /\[command as executed\] echo "unclosed/);
        return true;
      },
    );
  });

  it('обычная ошибка без syntax error не получает подсказку', async () => {
    const client = setupExec({
      onExec: ({ callback }) => {
        const stream = new FakeExecStream();
        callback(undefined, stream);
        setImmediate(() => {
          stream.stderr.emit(
            'data',
            Buffer.from('cat: nope: No such file or directory\n'),
          );
          stream.emit('exit', 1);
          stream.emit('close', 1);
        });
      },
    });

    await assert.rejects(
      () => manager.executeCommand('cat nope', undefined, 'exec'),
      (error) => {
        assert.strictEqual(error.code, 'COMMAND_EXECUTION_ERROR');
        assert.ok(!error.message.includes('[hint]'));
        return true;
      },
    );
  });

  it('script работает и в shell-режиме (одной строкой через base64)', async () => {
    const script = "docker exec c python3 -c \"print('nested')\"\n";
    const expectedEncoded = Buffer.from(script, 'utf8').toString('base64');
    const channel = new FakeShellChannel();
    let commandPayload = null;

    channel.on('write', (payload) => {
      const readyId = extractMarkerId(payload, '__MCP_READY__');
      if (readyId) {
        setImmediate(() => {
          channel.emit('data', Buffer.from(`__MCP_READY__${readyId}__\n`));
        });
        return;
      }
      if (payload.includes('__MCP_BEGIN__')) {
        commandPayload = payload;
        const commandId = extractMarkerId(payload, '__MCP_BEGIN__');
        setImmediate(() =>
          emitShellCommandResult(channel, commandId, 'nested', 0),
        );
      }
    });

    const client = new FakeClient({
      onConnect: () => setImmediate(() => client.emit('ready')),
      onShell: ({ callback }) => callback(undefined, channel),
    });

    manager.createClient = () => client;
    manager.scheduleStatusCollection = () => {};
    manager.setConfig({
      shell: createPasswordConfig({ name: 'shell', transportMode: 'shell' }),
    });

    await manager.connect('shell');

    const result = await manager.executeCommand(undefined, undefined, 'shell', {
      script,
    });

    assert.strictEqual(result, 'nested');
    assert.ok(commandPayload);
    assert.ok(commandPayload.includes(`printf %s '${expectedEncoded}' | base64 -d | bash`));
    // Сырой многострочный скрипт не должен попасть в поток shell.
    assert.ok(!commandPayload.includes('docker exec c'));
  });

  it('пустая команда отклоняется с COMMAND_VALIDATION_FAILED', async () => {
    manager.createClient = () => new FakeClient();
    manager.scheduleStatusCollection = () => {};
    manager.setConfig({ exec: createPasswordConfig({ name: 'exec' }) });

    await assert.rejects(
      () => manager.executeCommand(undefined, undefined, 'exec'),
      (error) => {
        assert.ok(error instanceof ToolError);
        assert.strictEqual(error.code, 'COMMAND_VALIDATION_FAILED');
        return true;
      },
    );
  });
});
