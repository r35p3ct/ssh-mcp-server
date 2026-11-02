import { randomUUID } from "node:crypto";

/**
 * Command guard.
 *
 * Philosophy: nothing is ever hard-blocked (disk formatting, partitioning etc.
 * are legitimate operations). Instead commands are classified into three risk
 * levels:
 *   - "read"         — safe to run without asking
 *   - "user-write"   — modifies user-level state (files, dirs, processes)
 *   - "system-write" — impacts the system itself (disks, services, network,
 *                      packages, users, kernel)
 *
 * Non-read commands require user approval (once / for session / all for
 * session). Classification is best-effort: anything we cannot prove to be
 * read-only (subshells, unknown verbs, redirects) is treated as a write, so
 * the approval prompt is the real safety net.
 */

export type CommandRisk = "read" | "user-write" | "system-write";

export function normalizeEol(command: string): string {
  return command.replace(/\r\n?/g, "\n");
}

/** Verbs that are pure reads on a server. */
const READ_VERBS = new Set([
  "ls",
  "cat",
  "less",
  "more",
  "head",
  "tail",
  "grep",
  "egrep",
  "fgrep",
  "rg",
  "find",
  "which",
  "whereis",
  "df",
  "du",
  "free",
  "uptime",
  "ps",
  "top",
  "htop",
  "who",
  "whoami",
  "w",
  "id",
  "uname",
  "hostname",
  "date",
  "cal",
  "pwd",
  "env",
  "printenv",
  "history",
  "stat",
  "file",
  "tree",
  "nproc",
  "lscpu",
  "lsblk",
  "blkid",
  "ss",
  "netstat",
  "nmap",
  "ping",
  "traceroute",
  "mtr",
  "dig",
  "nslookup",
  "arp",
  "route",
  "journalctl",
  "dmesg",
  "echo",
  "printf",
  "vmstat",
  "iostat",
  "sar",
  "last",
  "lastlog",
  "curl",
  "lsof",
  "pgrep",
  "wc",
  "sort",
  "uniq",
  "cut",
  "tr",
  "column",
  "md5sum",
  "sha256sum",
  "sha1sum",
  "cksum",
  "basename",
  "dirname",
  "realpath",
  "readlink",
  "awk",
  "sed",
  "xargs",
  "diff",
  "cmp",
  "comm",
  "join",
  "seq",
  "yes",
  "true",
  "false",
  "test",
  "sleep",
  "wait",
  "factor",
  "groups",
  "getent",
  "iconv",
  "bc",
  "expr",
])

/** Verbs whose effect depends on the subcommand (second word). */
const AMBIGUOUS_VERBS = new Set([
  "ip",
  "git",
  "systemctl",
  "service",
  "rc-service",
  "docker",
  "podman",
  "kubectl",
  "helm",
  "apt",
  "apt-get",
  "yum",
  "dnf",
  "zypper",
  "apk",
  "snap",
  "brew",
  "npm",
  "pnpm",
  "yarn",
  "pip",
  "pip3",
  "cargo",
  "gem",
])

/** Ambiguous verbs that impact the OS itself when used non-read. */
const SYSTEM_MANAGERS = new Set([
  "systemctl",
  "service",
  "rc-service",
  "apt",
  "apt-get",
  "yum",
  "dnf",
  "zypper",
  "apk",
  "snap",
])

/** Read-only subcommands for ambiguous verbs. */
const READ_SUBCOMMAND =
  /^(show|status|list|ls|log|logs|diff|blame|branch|print|get|current|search|help|ps|inspect|info|version|stats|top|describe|check|verify|--help|-h|--version|-v)\b/i

/** Verbs that directly impact the system (disks, services, kernel, users). */
const SYSTEM_VERBS = new Set([
  "mkfs",
  "mke2fs",
  "mkswap",
  "fdisk",
  "sfdisk",
  "cfdisk",
  "gdisk",
  "sgdisk",
  "parted",
  "partprobe",
  "wipefs",
  "shred",
  "dd",
  "blkdiscard",
  "hdparm",
  "badblocks",
  "losetup",
  "reboot",
  "shutdown",
  "poweroff",
  "halt",
  "init",
  "telinit",
  "iptables",
  "ip6tables",
  "nft",
  "ufw",
  "firewall-cmd",
  "mount",
  "umount",
  "swapon",
  "swapoff",
  "modprobe",
  "rmmod",
  "insmod",
  "depmod",
  "sysctl",
  "lvm",
  "pvcreate",
  "pvremove",
  "vgcreate",
  "vgremove",
  "vgchange",
  "lvcreate",
  "lvremove",
  "lvextend",
  "lvreduce",
  "cryptsetup",
  "mdadm",
  "tune2fs",
  "resize2fs",
  "fsck",
  "e2fsck",
  "useradd",
  "userdel",
  "usermod",
  "groupadd",
  "groupdel",
  "groupmod",
  "passwd",
  "visudo",
  "hostnamectl",
  "timedatectl",
  "localectl",
  "grub",
  "grub-install",
  "grub2-install",
  "update-grub",
  "dpkg",
  "rpm",
  "pacman",
])

/** Interpreters and shells — arbitrary code, cannot be proven read-only. */
const INTERPRETERS = new Set([
  "bash",
  "sh",
  "dash",
  "ash",
  "zsh",
  "fish",
  "ksh",
  "csh",
  "tcsh",
  "python",
  "python2",
  "python3",
  "node",
  "perl",
  "ruby",
  "php",
  "lua",
])

/** Tokens ignored before the actual verb (repeatedly). */
const IGNORED_PREFIXES = new Set([
  "sudo",
  "nohup",
  "command",
  "env",
  "nice",
  "exec",
  "time",
  "stdbuf",
])

const SEGMENT_SPLIT = /\r?\n|&&|\|\||[;|&]/

const RISK_ORDER: Record<CommandRisk, number> = {
  read: 0,
  "user-write": 1,
  "system-write": 2,
}

function worstRisk(a: CommandRisk, b: CommandRisk): CommandRisk {
  return RISK_ORDER[a] >= RISK_ORDER[b] ? a : b;
}

function stripWrappers(segment: string): string {
  return segment
    .replace(/^[{(\s]+/, "")
    .replace(/[\s;})&]+$/, "")
    .trim();
}

function resolveVerb(tokens: string[]): {
  verb: string;
  rest: string;
} {
  let index = 0;
  while (index < tokens.length) {
    const token = tokens[index];
    if (IGNORED_PREFIXES.has(token)) {
      index += 1;
      continue;
    }
    if (token === "timeout" && tokens[index + 1] && /^\d+$/.test(tokens[index + 1])) {
      index += 2;
      continue;
    }
    // Environment variable assignments: VAR=value cmd
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token) && index < tokens.length - 1) {
      index += 1;
      continue;
    }
    break;
  }
  return {
    verb: (tokens[index] || "").toLowerCase(),
    rest: tokens.slice(index).join(" "),
  };
}

/** Redirects to a real file make a segment a write; /dev/null is harmless. */
function isRedirectWrite(segment: string): boolean {
  const cleaned = segment
    .replace(/\d*&?>+\s*\/dev\/null/g, "")
    .replace(/\d*&?>+\s*"\/dev\/null"/g, "")
    .replace(/\d*>>&?\s*\d+/g, ""); // e.g. 2>&1
  return /[0-9]?&?>{1,2}/.test(cleaned);
}

function hasSubshell(command: string): boolean {
  return /\$\(/.test(command) || /`/.test(command);
}

function classifySegment(segment: string): CommandRisk {
  const s = stripWrappers(segment);
  if (!s) {
    return "read";
  }

  if (isRedirectWrite(s)) {
    return "user-write";
  }

  const tokens = s.split(/\s+/);
  const { verb, rest } = resolveVerb(tokens);

  if (!verb) {
    return "user-write";
  }

  if (verb.startsWith("mkfs")) {
    return "system-write";
  }

  if (SYSTEM_VERBS.has(verb)) {
    return "system-write";
  }

  if (INTERPRETERS.has(verb)) {
    return "user-write";
  }

  if (AMBIGUOUS_VERBS.has(verb)) {
    const secondWord = (tokens[tokens.indexOf(verb) + 1] || "").toLowerCase();
    if (secondWord && READ_SUBCOMMAND.test(secondWord)) {
      return "read";
    }
    return SYSTEM_MANAGERS.has(verb) ? "system-write" : "user-write";
  }

  if (READ_VERBS.has(verb)) {
    // Read verbs with write side-effects.
    if (verb === "find" && /(^|\s)-(delete|exec|execdir|ok)\b/.test(rest)) {
      return "user-write";
    }
    if (verb === "sed" && /(^|\s)-[a-zA-Z]*i[a-zA-Z]*(\s|$)/.test(rest)) {
      return "user-write";
    }
    if (
      (verb === "curl" || verb === "wget") &&
      /(^|\s)(-o|-O|--output|-T|--upload-file|--remote-name)/.test(rest)
    ) {
      return "user-write";
    }
    return "read";
  }

  // Unknown verb — fail closed.
  return "user-write";
}

/**
 * Classify a full command line (may contain several segments joined by
 * newlines, `;`, `&&`, `||`, `|`). Returns the worst risk across segments.
 */
export function classifyCommand(command: string): CommandRisk {
  let risk: CommandRisk = "read";
  for (const segment of command.split(SEGMENT_SPLIT)) {
    risk = worstRisk(risk, classifySegment(segment));
  }
  if (risk === "read" && hasSubshell(command)) {
    // A read-looking command that spawns a subshell can do anything.
    risk = "user-write";
  }
  return risk;
}

export function describeRisk(risk: CommandRisk): string {
  switch (risk) {
    case "read":
      return "read-only";
    case "user-write":
      return "modifies files or processes on the server";
    case "system-write":
      return "SYSTEM-IMPACTING: disks, services, network, packages or users";
  }
}

// ---------------------------------------------------------------------------
// Session approval state (process lifetime)
// ---------------------------------------------------------------------------

const sessionApprovedCommands = new Set<string>();
let sessionAllApproved = false;
const pendingConfirmations = new Map<
  string,
  { command: string; createdAt: number }
>();

const PENDING_CONFIRMATION_TTL_MS = 10 * 60 * 1000;
const PENDING_CONFIRMATION_MAX = 50;

export function isSessionAllApproved(): boolean {
  return sessionAllApproved;
}

export function approveAllForSession(): void {
  sessionAllApproved = true;
}

export function approveCommandForSession(command: string): void {
  sessionApprovedCommands.add(command);
}

export function isSessionApproved(command: string): boolean {
  return sessionAllApproved || sessionApprovedCommands.has(command);
}

/**
 * Register a pending confirmation for a command and return its id.
 * Used when the client cannot show interactive prompts.
 */
export function createPendingConfirmation(command: string): string {
  const now = Date.now();
  for (const [id, entry] of pendingConfirmations) {
    if (now - entry.createdAt > PENDING_CONFIRMATION_TTL_MS) {
      pendingConfirmations.delete(id);
    }
  }
  if (pendingConfirmations.size >= PENDING_CONFIRMATION_MAX) {
    const oldest = pendingConfirmations.keys().next().value;
    if (oldest !== undefined) {
      pendingConfirmations.delete(oldest);
    }
  }
  const id = `confirm_${randomUUID()}`;
  pendingConfirmations.set(id, { command, createdAt: now });
  return id;
}

/**
 * Consume a pending confirmation. Returns true only when the id exists,
 * is fresh, and was issued for exactly this command. A retry with a
 * mismatched command does not burn the token.
 */
export function consumePendingConfirmation(
  id: string,
  command: string,
): boolean {
  const entry = pendingConfirmations.get(id);
  if (!entry) {
    return false;
  }
  if (Date.now() - entry.createdAt > PENDING_CONFIRMATION_TTL_MS) {
    pendingConfirmations.delete(id);
    return false;
  }
  if (entry.command !== command) {
    return false;
  }
  pendingConfirmations.delete(id);
  return true;
}

export function resetGuardSession(): void {
  sessionApprovedCommands.clear();
  sessionAllApproved = false;
  pendingConfirmations.clear();
}
