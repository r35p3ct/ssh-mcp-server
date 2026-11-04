import { describe, it } from 'node:test';
import assert from 'node:assert';
import { buildApprovalSchema } from '../build/tools/execute-command.js';

describe('approval elicitation schema', () => {
  it('помещает команду в форму как read-only поле', () => {
    const command = "mkdir -p /tmp/demo && echo 'nested (quote)'";
    const schema = buildApprovalSchema(command);

    assert.strictEqual(schema.type, 'object');
    assert.deepStrictEqual(schema.required, ['choice']);

    const commandField = schema.properties.command;
    assert.strictEqual(commandField.type, 'string');
    assert.deepStrictEqual(commandField.enum, [command]);
    assert.deepStrictEqual(commandField.enumNames, [command]);
  });

  it('выбор разрешения не зависит от поля команды', () => {
    const schema = buildApprovalSchema('reboot');

    const choice = schema.properties.choice;
    assert.strictEqual(choice.type, 'string');
    assert.deepStrictEqual(choice.enum, [
      'once',
      'session_command',
      'session_all',
      'deny',
    ]);
    assert.strictEqual(choice.default, 'once');
  });

  it('длинные команды обрезаются в превью формы', () => {
    const long = 'x'.repeat(800);
    const schema = buildApprovalSchema(long);

    const preview = schema.properties.command.enum[0];
    assert.ok(preview.length < 800, 'preview must be truncated');
    assert.ok(preview.endsWith('…(truncated)'));
    // Полная команда остаётся в message — её добавляет buildApprovalMessage.
    assert.strictEqual(preview.startsWith('x'.repeat(10)), true);
  });
});
