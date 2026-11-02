import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert';
import {
  classifyCommand,
  describeRisk,
  normalizeEol,
  approveAllForSession,
  approveCommandForSession,
  isSessionAllApproved,
  isSessionApproved,
  createPendingConfirmation,
  consumePendingConfirmation,
  resetGuardSession,
} from '../build/utils/command-guard.js';

describe('Command Guard: classification', () => {
  describe('read commands pass without approval', () => {
    const readCases = [
      'ls -la',
      'cat /etc/hostname',
      'df -h',
      'docker ps -a',
      'docker logs mycontainer',
      'docker inspect mycontainer',
      'git status',
      'git log --oneline',
      'systemctl status nginx',
      'journalctl -u nginx -n 50',
      'curl https://example.com',
      'apt list --installed',
      'pip show requests',
      'grep -r foo /var/log | wc -l',
      'ls > /dev/null',
      'echo done 2>/dev/null',
      'ps aux | head -20',
    ];

    for (const cmd of readCases) {
      it(`read: ${cmd}`, () => {
        assert.strictEqual(classifyCommand(cmd), 'read');
      });
    }
  });

  describe('user-level writes require approval', () => {
    const writeCases = [
      'rm file.txt',
      'mkdir -p /opt/app',
      'mv a b',
      'sed -i \'s/a/b/\' /etc/app.conf',
      "find /tmp -name '*.log' -delete",
      "bash -c 'echo hi'",
      'python3 /opt/script.py',
      'echo hi > out.txt',
      'echo hi >> out.txt',
      'tee /etc/motd < x',
      'wget https://example.com/file.zip',
      'curl -o out.bin https://example.com',
      'sqlite3 db.sqlite "SELECT 1;"',
      'docker rm mycontainer',
      'docker stop mycontainer',
      'git commit -m x',
      'tar -xzf archive.tar.gz',
      'echo $(whoami)',
    ];

    for (const cmd of writeCases) {
      it(`user-write: ${cmd}`, () => {
        assert.strictEqual(classifyCommand(cmd), 'user-write');
      });
    }
  });

  describe('system-impacting writes require approval', () => {
    const systemCases = [
      'mkfs.ext4 /dev/sdb1',
      'mkfs -t ext4 /dev/sdb1',
      'dd if=image.img of=/dev/sda',
      'fdisk /dev/sdb',
      'parted /dev/sdb mklabel gpt',
      'wipefs /dev/sdb1',
      'reboot',
      'shutdown -h now',
      'mount /dev/sdb1 /mnt',
      'umount /mnt',
      'iptables -A INPUT -j DROP',
      'useradd bob',
      'passwd bob',
      'apt install nginx',
      'apt-get upgrade -y',
      'dnf install htop',
      'systemctl restart nginx',
      'systemctl stop nginx',
      'service nginx restart',
    ];

    for (const cmd of systemCases) {
      it(`system-write: ${cmd}`, () => {
        assert.strictEqual(classifyCommand(cmd), 'system-write');
      });
    }
  });

  it('самый высокий риск среди сегментов побеждает', () => {
    assert.strictEqual(
      classifyCommand('ls /tmp && mkfs.ext4 /dev/sdb1'),
      'system-write',
    );
    assert.strictEqual(
      classifyCommand('ls /tmp\ndocker ps\necho x > file'),
      'user-write',
    );
  });

  it('describeRisk даёт понятные подписи', () => {
    assert.match(describeRisk('read'), /read-only/);
    assert.match(describeRisk('user-write'), /modifies/);
    assert.match(describeRisk('system-write'), /SYSTEM-IMPACTING/);
  });

  it('normalizeEol приводит CRLF и CR к LF', () => {
    assert.strictEqual(normalizeEol('a\r\nb\rc\nd'), 'a\nb\nc\nd');
  });
});

describe('Command Guard: session approvals', () => {
  beforeEach(() => {
    resetGuardSession();
  });

  it('разрешение конкретной команды действует только на неё', () => {
    approveCommandForSession('rm /tmp/x');
    assert.ok(isSessionApproved('rm /tmp/x'));
    assert.ok(!isSessionApproved('rm /tmp/y'));
    assert.ok(!isSessionAllApproved());
  });

  it('approveAll разрешает всё до сброса сессии', () => {
    assert.ok(!isSessionApproved('rm -rf /tmp/build'));
    approveAllForSession();
    assert.ok(isSessionApproved('rm -rf /tmp/build'));
    assert.ok(isSessionAllApproved());
    resetGuardSession();
    assert.ok(!isSessionApproved('rm -rf /tmp/build'));
  });

  it('pending confirmation работает только для той же команды и одноразово', () => {
    const id = createPendingConfirmation('rm /tmp/x');

    assert.ok(!consumePendingConfirmation(id, 'rm /tmp/y'));
    assert.ok(consumePendingConfirmation(id, 'rm /tmp/x'));
    assert.ok(!consumePendingConfirmation(id, 'rm /tmp/x'));

    const other = createPendingConfirmation('mkdir /tmp/z');
    resetGuardSession();
    assert.ok(!consumePendingConfirmation(other, 'mkdir /tmp/z'));
  });
});
