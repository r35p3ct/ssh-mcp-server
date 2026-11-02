import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { SSHConnectionManager } from "../services/ssh-connection-manager.js";
import { Logger } from "../utils/logger.js";
import { ToolError, toToolError } from "../utils/tool-error.js";
import {
  CommandRisk,
  approveAllForSession,
  approveCommandForSession,
  classifyCommand,
  consumePendingConfirmation,
  createPendingConfirmation,
  describeRisk,
  isSessionApproved,
  normalizeEol,
} from "../utils/command-guard.js";

const APPROVAL_CHOICE_SCHEMA = {
  type: "object" as const,
  properties: {
    choice: {
      type: "string" as const,
      title: "Approval",
      description: "Approve execution of this command",
      enum: ["once", "session_command", "session_all", "deny"],
      enumNames: [
        "Allow once",
        "Allow this command for the session",
        "Allow ALL commands for the session",
        "Deny",
      ],
      default: "once",
    },
  },
  required: ["choice"],
};

type Decision = { allowed: true } | { allowed: false; payload: Record<string, unknown> };

function buildApprovalMessage(command: string, risk: CommandRisk): string {
  const truncated =
    command.length > 2000 ? `${command.slice(0, 2000)}…(truncated)` : command;
  return [
    `SSH guard: this command ${describeRisk(risk)}.`,
    "",
    truncated,
  ].join("\n");
}

/**
 * Guard gate: read commands pass silently; write commands require user
 * approval. Prefers interactive MCP elicitation; when the client does not
 * support it, returns a confirmation id the caller must echo back.
 */
async function approveCommand(
  server: McpServer,
  command: string,
  confirmationId?: string,
  rememberApproval?: boolean,
): Promise<Decision> {
  if (process.env.SSH_MCP_GUARD === "off") {
    return { allowed: true };
  }

  const risk = classifyCommand(command);
  if (risk === "read") {
    return { allowed: true };
  }
  if (isSessionApproved(command)) {
    return { allowed: true };
  }
  if (
    confirmationId !== undefined &&
    consumePendingConfirmation(confirmationId, command)
  ) {
    if (rememberApproval) {
      approveCommandForSession(command);
    }
    return { allowed: true };
  }

  const message = buildApprovalMessage(command, risk);

  // Clients that do not advertise elicitation get the confirmation-id
  // fallback immediately instead of a hanging request.
  const clientCapabilities = server.server.getClientCapabilities?.();
  if (!clientCapabilities?.elicitation) {
    return confirmationRequiredPayload(message, command);
  }

  try {
    const result = await server.server.elicitInput({
      message,
      requestedSchema: APPROVAL_CHOICE_SCHEMA,
    });

    if (result.action === "accept") {
      const choice = String(result.content?.choice ?? "once");
      if (choice === "session_command") {
        approveCommandForSession(command);
        return { allowed: true };
      }
      if (choice === "session_all") {
        approveAllForSession();
        return { allowed: true };
      }
      if (choice === "once") {
        return { allowed: true };
      }
    }

    return {
      allowed: false,
      payload: {
        code: "COMMAND_BLOCKED_BY_USER",
        message: `Command rejected by user: ${command}`,
        retriable: false,
      },
    };
  } catch (error) {
    // Client advertised elicitation but the request failed (unsupported
    // method, timeout, transport error) — fall back to a two-step
    // confirmation: ask the user via the calling agent, then retry with
    // the confirmation id.
    Logger.log(
      `Elicitation failed (${(error as Error).message}), falling back to confirmation id`,
      "debug",
    );
    return confirmationRequiredPayload(message, command);
  }
}

function confirmationRequiredPayload(
  message: string,
  command: string,
): Decision {
  const confirmationId = createPendingConfirmation(command);
  return {
    allowed: false,
    payload: {
      code: "COMMAND_CONFIRMATION_REQUIRED",
      message: [
        message,
        "",
        "Interactive approval is not available for this MCP client.",
        "Ask the user to approve this command, then retry the same call with the `confirmationId` parameter set to the value below (add `rememberApproval: true` to allow this exact command for the whole session).",
      ].join("\n"),
      retriable: true,
      confirmationId,
      command,
    },
  };
}

/**
 * Register execute command tool
 */
export function registerExecuteCommandTool(server: McpServer): void {
  const sshManager = SSHConnectionManager.getInstance();

  server.registerTool(
    "execute-command",
    {
      description:
        "Execute a command or a script on a connected server and return its output. " +
        "cmdString is passed VERBATIM to the remote login shell (like `ssh host '<cmdString>'`): " +
        "apply exactly ONE level of shell quoting as you would locally — never add extra escaping layers for SSH or JSON. " +
        "For multi-line commands or commands with nested quotes (e.g. quoting inside docker exec or python -c), " +
        "prefer the `script` parameter: its content is sent verbatim to remote bash and needs no escaping at all. " +
        "Read-only commands run immediately; commands that modify the server require user approval (allow once / for session / all for session / deny).",
      inputSchema: {
        cmdString: z
          .string()
          .optional()
          .describe(
            "Command to execute. Passed verbatim to the remote login shell — use a single level of shell quoting, do not pre-escape quotes for SSH",
          ),
        script: z
          .string()
          .optional()
          .describe(
            "Multi-line shell script executed verbatim by remote bash — quotes need NO escaping. Use instead of cmdString for nested quotes or long commands. Mutually exclusive with cmdString",
          ),
        directory: z.string().optional().describe("Working directory for command execution"),
        connectionName: z
          .string()
          .optional()
          .describe("SSH connection name (optional, default is 'default')"),
        timeout: z
          .number()
          .optional()
          .describe(
            "Command execution timeout in milliseconds (optional, default is 30000ms)",
          ),
        confirmationId: z
          .string()
          .optional()
          .describe(
            "Echo back the confirmationId from a COMMAND_CONFIRMATION_REQUIRED error after the user approved this command",
          ),
        rememberApproval: z
          .boolean()
          .optional()
          .describe(
            "Together with confirmationId: allow this exact command for the whole session without asking again",
          ),
      },
    },
    async ({
      cmdString,
      script,
      directory,
      connectionName,
      timeout,
      confirmationId,
      rememberApproval,
    }) => {
      try {
        if (cmdString !== undefined && script !== undefined) {
          throw new ToolError(
            "COMMAND_VALIDATION_FAILED",
            "Pass either cmdString or script, not both.",
            false,
          );
        }
        if (cmdString === undefined && script === undefined) {
          throw new ToolError(
            "COMMAND_VALIDATION_FAILED",
            "Provide cmdString (single shell command) or script (verbatim multi-line script).",
            false,
          );
        }

        const command = normalizeEol(script ?? cmdString!);
        if (command.trim().length === 0) {
          throw new ToolError(
            "COMMAND_VALIDATION_FAILED",
            "Command must be a non-empty string.",
            false,
          );
        }

        const decision = await approveCommand(
          server,
          command,
          confirmationId,
          rememberApproval,
        );
        if (!decision.allowed) {
          Logger.log(
            `Command not executed: ${decision.payload.code}`,
            "info",
          );
          return {
            content: [{
              type: "text",
              text: JSON.stringify(decision.payload, null, 2),
            }],
            isError: true,
          };
        }

        const result = await sshManager.executeCommand(
          script !== undefined ? undefined : command,
          directory,
          connectionName,
          {
            timeout,
            script: script !== undefined ? command : undefined,
          },
        );
        return {
          content: [{ type: "text", text: result }],
        };
      } catch (error: unknown) {
        const toolError = toToolError(error, "UNKNOWN_ERROR");

        // The command ran and ended with a non-zero status: its output ending in
        // "[exit code] N" is the result, so return it as is instead of wrapping
        // it in an escaped JSON error object. `grep` with no match or `diff` with
        // differences are normal outcomes, not failures of this tool. Parse-failure
        // hints appended by the manager (see appendParseFailureHint) travel in the
        // same message.
        if (toolError.commandRan) {
          return {
            content: [{ type: "text", text: toolError.message }],
          };
        }

        Logger.handleError(toolError, "Failed to execute command");
        return {
          content: [{
            type: "text",
            text: JSON.stringify(
              {
                code: toolError.code,
                message: toolError.message,
                retriable: toolError.retriable,
              },
              null,
              2,
            ),
          }],
          isError: true,
        };
      }
    },
  );
}
