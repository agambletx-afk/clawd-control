import fs from "node:fs";
import https from "node:https";
import path from "node:path";

type ConfirmPathRule = {
  pattern: string;
  timeoutSeconds?: number;
};

type TelegramConfig = {
  botTokenEnvVar: string;
  chatIdEnvVar: string;
};

type SecurityHookConfig = {
  version: string;
  changelog: Array<{ version: string; date: string; note: string }>;
  blocklist: string[];
  protectedPaths: string[];
  allowlist: string[];
  confirmPaths: ConfirmPathRule[];
  telegram: TelegramConfig;
  rateLimits: Record<string, unknown>;
};

type RuleMatch = { matched: boolean; rule?: string };

const DEFAULT_CONFIG: SecurityHookConfig = {
  version: "1.1",
  changelog: [
    {
      version: "1.1",
      date: "2026-02-28",
      note: "Added Telegram confirmation gates for sensitive write paths with timeout controls.",
    },
    {
      version: "1.0",
      date: "2026-02-28",
      note: "Initial security-hook config with blocklist, protected paths, and allowlist.",
    },
  ],
  blocklist: [
    "rm\\s+-rf\\s+/",
    "rm\\s+-rf\\s+~",
    "rm\\s+-rf\\s+\\.\\s",
    "curl\\s.*\\|\\s*(sh|bash)",
    "wget\\s.*\\|\\s*(sh|bash)",
    "chmod\\s+777",
    "chmod\\s+a\\+rwx",
    "mkfs\\.",
    "dd\\s+if=.*of=/dev/",
    ":\\(\\)\\{\\s*:\\|:\\s*&\\s*\\};:",
    "python.*-c.*import\\s+os.*system",
    "eval\\s*\\(",
  ],
  protectedPaths: [
    ".env",
    "SOUL.md",
    "AGENTS.md",
    "HEARTBEAT.md",
    "openclaw.json",
    "openclaw.plugin.json",
    "docker-compose.yml",
    "/etc/systemd/",
    "/etc/sudoers",
    "~/.ssh/",
    "~/.openclaw/credentials",
  ],
  allowlist: [
    "rm /tmp/codex-task-*",
    "rm /tmp/openclaw-*",
    "cat *",
    "grep *",
    "ls *",
    "head *",
    "tail *",
    "find *",
    "wc *",
    "du *",
    "df *",
    "free *",
    "journalctl *",
  ],
  confirmPaths: [
    { pattern: "docker-compose.yml", timeoutSeconds: 300 },
    { pattern: "*.service", timeoutSeconds: 300 },
    { pattern: "SOUL.md", timeoutSeconds: 300 },
    { pattern: ".env", timeoutSeconds: 180 },
  ],
  telegram: {
    botTokenEnvVar: "TELEGRAM_BOT_TOKEN",
    chatIdEnvVar: "TELEGRAM_CHAT_ID",
  },
  rateLimits: {},
};

function ensureDir(dirPath: string): void {
  fs.mkdirSync(dirPath, { recursive: true });
}

function ensureFile(filePath: string): void {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, "", { encoding: "utf8" });
  }
}

function wildcardPatternToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i");
}

function toAbsolutePath(inputPath: string, homeDir: string): string {
  if (inputPath.startsWith("~/")) {
    return path.join(homeDir, inputPath.slice(2));
  }
  return path.resolve(inputPath);
}

function isExecCapableTool(toolName: string): boolean {
  const execTools = ["shell", "bash", "exec", "terminal", "command", "run_command"];
  const lower = toolName.toLowerCase();
  return execTools.some((t) => lower === t || lower.endsWith(`_${t}`) || lower.startsWith(`${t}_`));
}

function isWriteTool(toolName: string): boolean {
  const writeTools = ["write", "edit", "create_file", "save", "append", "apply_patch", "write_file"];
  const lower = toolName.toLowerCase();
  return writeTools.some((t) => lower === t || lower.endsWith(`_${t}`) || lower.startsWith(`${t}_`));
}

function matchAllowlist(command: string, allowlist: string[]): RuleMatch {
  for (const pattern of allowlist) {
    if (wildcardPatternToRegex(pattern).test(command)) {
      return { matched: true, rule: pattern };
    }
  }
  return { matched: false };
}

function matchBlocklist(command: string, blocklist: string[]): RuleMatch {
  for (const pattern of blocklist) {
    if (new RegExp(pattern, "i").test(command)) {
      return { matched: true, rule: pattern };
    }
  }
  return { matched: false };
}

function matchesConfirmPath(targetPath: string, confirmPaths: ConfirmPathRule[], homeDir: string): ConfirmPathRule | null {
  const normalized = toAbsolutePath(targetPath, homeDir);
  for (const rule of confirmPaths) {
    if (!rule || typeof rule.pattern !== "string" || rule.pattern.trim().length === 0) {
      continue;
    }
    const pattern = rule.pattern;
    if (pattern.includes("*")) {
      const matcher = wildcardPatternToRegex(pattern);
      if (matcher.test(targetPath) || matcher.test(normalized)) {
        return rule;
      }
      continue;
    }
    const expandedRule = pattern.startsWith("~/") ? path.join(homeDir, pattern.slice(2)) : pattern;
    const ruleNormalized = path.isAbsolute(expandedRule) ? path.normalize(expandedRule) : expandedRule;
    if (!path.isAbsolute(ruleNormalized)) {
      if (targetPath === ruleNormalized || targetPath.endsWith(`/${ruleNormalized}`)) {
        return rule;
      }
      continue;
    }
    if (normalized === ruleNormalized || normalized.startsWith(`${ruleNormalized}${path.sep}`)) {
      return rule;
    }
  }
  return null;
}

function getOperationSummary(event: any): string {
  const summarySource =
    event?.params?.command ??
    event?.params?.cmd ??
    event?.params?.content ??
    event?.params?.text ??
    event?.params?.patch ??
    "";
  const summary = String(summarySource).replace(/\s+/g, " ").trim();
  return summary.slice(0, 200);
}

function telegramRequest(
  botToken: string,
  method: string,
  body: Record<string, unknown>,
): Promise<Record<string, any>> {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body);
    const req = https.request(
      {
        hostname: "api.telegram.org",
        path: `/bot${botToken}/${method}`,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          if (res.statusCode && (res.statusCode < 200 || res.statusCode >= 300)) {
            reject(new Error(`telegram ${method} failed with status ${res.statusCode}: ${raw}`));
            return;
          }
          try {
            resolve(JSON.parse(raw));
          } catch (error) {
            reject(new Error(`telegram ${method} returned non-JSON response: ${String(error)}`));
          }
        });
      },
    );
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForTelegramDecision(
  botToken: string,
  chatId: string,
  timeoutSeconds: number,
  offset: number,
): Promise<"approve" | "deny" | "timeout"> {
  let nextOffset = offset;
  const deadline = Date.now() + timeoutSeconds * 1000;

  while (Date.now() < deadline) {
    const response = await telegramRequest(botToken, "getUpdates", {
      timeout: 2,
      offset: nextOffset,
      allowed_updates: ["message"],
    });
    const updates = Array.isArray(response?.result) ? response.result : [];
    for (const update of updates) {
      const updateId = Number(update?.update_id ?? 0);
      if (updateId >= nextOffset) {
        nextOffset = updateId + 1;
      }
      const message = update?.message;
      if (!message || String(message?.chat?.id) !== chatId) {
        continue;
      }
      const text = String(message?.text ?? "").trim().toLowerCase();
      const normalized = text.startsWith("/") ? text.slice(1) : text;
      if (normalized === "approve") {
        return "approve";
      }
      if (normalized === "deny") {
        return "deny";
      }
    }
    await delay(2000);
  }
  return "timeout";
}

function matchesProtectedPath(targetPath: string, protectedPaths: string[], homeDir: string): RuleMatch {
  const normalized = toAbsolutePath(targetPath, homeDir);
  for (const rule of protectedPaths) {
    if (rule.includes("*")) {
      if (wildcardPatternToRegex(rule).test(targetPath) || wildcardPatternToRegex(rule).test(normalized)) {
        return { matched: true, rule };
      }
      continue;
    }
    const expandedRule = rule.startsWith("~/") ? path.join(homeDir, rule.slice(2)) : rule;
    const ruleNormalized = path.isAbsolute(expandedRule) ? path.normalize(expandedRule) : expandedRule;
    if (!path.isAbsolute(ruleNormalized)) {
      if (targetPath === ruleNormalized || targetPath.endsWith(`/${ruleNormalized}`)) {
        return { matched: true, rule };
      }
      continue;
    }
    if (normalized === ruleNormalized || normalized.startsWith(`${ruleNormalized}${path.sep}`)) {
      return { matched: true, rule };
    }
  }
  return { matched: false };
}

function validateConfig(config: any): string[] {
  const errors: string[] = [];
  if (!config || typeof config !== "object") {
    errors.push("config is not an object");
    return errors;
  }
  if (typeof config.version !== "string" || config.version.trim().length === 0) {
    errors.push("missing required field: version");
  }
  if (!Array.isArray(config.blocklist)) {
    errors.push("missing required field: blocklist[]");
  }
  if (!Array.isArray(config.protectedPaths)) {
    errors.push("missing required field: protectedPaths[]");
  }
  if (!Array.isArray(config.allowlist)) {
    errors.push("missing required field: allowlist[]");
  }
  if (!Array.isArray(config.changelog)) {
    errors.push("missing required field: changelog[]");
  }
  if (!Array.isArray(config.confirmPaths)) {
    errors.push("missing required field: confirmPaths[]");
  }
  if (!config.telegram || typeof config.telegram !== "object") {
    errors.push("missing required field: telegram");
  } else {
    if (typeof config.telegram.botTokenEnvVar !== "string" || config.telegram.botTokenEnvVar.trim().length === 0) {
      errors.push("missing required field: telegram.botTokenEnvVar");
    }
    if (typeof config.telegram.chatIdEnvVar !== "string" || config.telegram.chatIdEnvVar.trim().length === 0) {
      errors.push("missing required field: telegram.chatIdEnvVar");
    }
  }
  return errors;
}

async function appendBlockedLog(logPath: string, payload: Record<string, unknown>): Promise<void> {
  await fs.promises.appendFile(logPath, `${JSON.stringify(payload)}\n`, { encoding: "utf8" });
}

function blockCall(reason: string): { block: true; blockReason: string } {
  return { block: true, blockReason: reason };
}

export default function securityHook(api: any) {
  const homeDir = process.env.HOME ?? "/home/openclaw";
  const openclawDir = path.join(homeDir, ".openclaw");
  const logsDir = path.join(openclawDir, "logs");
  const configPath = path.join(openclawDir, "security-hook.json");
  const logPath = path.join(logsDir, "security-hook.log");

  ensureDir(logsDir);
  ensureFile(logPath);

  let config: SecurityHookConfig | null = null;
  let failClosed = false;

  try {
    if (!fs.existsSync(configPath)) {
      fs.writeFileSync(configPath, `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`, { encoding: "utf8" });
      api.logger.info(`security-hook: seeded config at ${configPath}`);
    }
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(raw);
    const errors = validateConfig(parsed);
    if (errors.length > 0) {
      failClosed = true;
      api.logger.error(`security-hook: config validation failed (${errors.join("; ")})`);
    } else {
      config = parsed as SecurityHookConfig;
    }
  } catch (error) {
    failClosed = true;
    api.logger.error(`security-hook: failed to load config (${String(error)})`);
  }

  api.registerService({
    id: "security-hook",
    start: () => {
      api.logger.info("security-hook: service started");
    },
    stop: () => {
      api.logger.info("security-hook: service stopped");
    },
  });

  api.logger.info("[plugins] security-hook: registered — pre-execution command filtering active");

  api.on("before_tool_call", async (event: any, ctx: any) => {
    const toolName = String(event?.toolName ?? "unknown");
    const command: string | null = event?.params?.command ?? event?.params?.cmd ?? null;
    const targetPath: string | null = event?.params?.path ?? event?.params?.file_path ?? event?.params?.target ?? null;
    const agentId = String(ctx?.agentId ?? "unknown");

    // Fail-closed: block all exec-capable calls when config is invalid
    if (failClosed && isExecCapableTool(toolName)) {
      const reason = "invalid config: fail-closed mode";
      await appendBlockedLog(logPath, {
        timestamp: new Date().toISOString(),
        agentId,
        tool: toolName,
        command,
        path: targetPath,
        matchedRule: reason,
        action: "blocked",
      });
      return blockCall("security-hook blocked this call: configuration is invalid (fail-closed)");
    }

    if (!config) {
      return;
    }

    // Check exec-capable tool calls against blocklist (with allowlist override)
    if (command && isExecCapableTool(toolName)) {
      const allow = matchAllowlist(command, config.allowlist);
      if (!allow.matched) {
        const blocked = matchBlocklist(command, config.blocklist);
        if (blocked.matched) {
          const reason = `blocklist match: ${blocked.rule}`;
          await appendBlockedLog(logPath, {
            timestamp: new Date().toISOString(),
            agentId,
            tool: toolName,
            command,
            path: targetPath,
            matchedRule: reason,
            action: "blocked",
          });
          api.logger.warn(`security-hook: blocked tool=${toolName} agent=${agentId} reason="${reason}"`);
          return blockCall(`Blocked by security-hook (${reason})`);
        }
      }
    }

    // Check write tools against protected paths
    if (targetPath && isWriteTool(toolName)) {
      const protectedMatch = matchesProtectedPath(targetPath, config.protectedPaths, homeDir);
      if (protectedMatch.matched) {
        const reason = `protected path: ${protectedMatch.rule}`;
        await appendBlockedLog(logPath, {
          timestamp: new Date().toISOString(),
          agentId,
          tool: toolName,
          command,
          path: targetPath,
          matchedRule: reason,
          action: "blocked",
        });
        api.logger.warn(`security-hook: blocked tool=${toolName} agent=${agentId} reason="${reason}"`);
        return blockCall(`Blocked by security-hook (${reason})`);
      }

      const confirmMatch = matchesConfirmPath(targetPath, config.confirmPaths, homeDir);
      if (confirmMatch) {
        const timeoutSeconds = confirmMatch.timeoutSeconds ?? 300;
        const botToken = process.env[config.telegram.botTokenEnvVar] ?? "";
        const chatId = process.env[config.telegram.chatIdEnvVar] ?? "";
        const operationSummary = getOperationSummary(event);
        const matchedRule = `confirm path: ${confirmMatch.pattern}`;

        if (!botToken || !chatId) {
          const reason = `${matchedRule}; missing telegram credentials in env`;
          await appendBlockedLog(logPath, {
            timestamp: new Date().toISOString(),
            agentId,
            tool: toolName,
            command,
            path: targetPath,
            matchedRule: reason,
            action: "gate-denied",
          });
          return blockCall(`Blocked by security-hook (${reason})`);
        }

        try {
          const updates = await telegramRequest(botToken, "getUpdates", {
            timeout: 0,
            allowed_updates: ["message"],
          });
          const existingUpdates = Array.isArray(updates?.result) ? updates.result : [];
          const initialOffset = existingUpdates.reduce((maxOffset: number, update: any) => {
            const updateId = Number(update?.update_id ?? 0);
            return updateId >= maxOffset ? updateId + 1 : maxOffset;
          }, 0);

          const requestMessage =
            `Security confirmation requested\n` +
            `Agent ID: ${agentId}\n` +
            `Tool: ${toolName}\n` +
            `Target Path: ${targetPath}\n` +
            `Operation Summary: ${operationSummary || "(none)"}\n\n` +
            `Reply /approve or /deny`;

          await telegramRequest(botToken, "sendMessage", {
            chat_id: chatId,
            text: requestMessage,
          });

          await appendBlockedLog(logPath, {
            timestamp: new Date().toISOString(),
            agentId,
            tool: toolName,
            command,
            path: targetPath,
            matchedRule,
            action: "gate-requested",
            timeoutSeconds,
          });

          const decision = await waitForTelegramDecision(botToken, chatId, timeoutSeconds, initialOffset);
          if (decision === "approve") {
            await appendBlockedLog(logPath, {
              timestamp: new Date().toISOString(),
              agentId,
              tool: toolName,
              command,
              path: targetPath,
              matchedRule,
              action: "gate-approved",
            });
            return;
          }

          if (decision === "deny") {
            await appendBlockedLog(logPath, {
              timestamp: new Date().toISOString(),
              agentId,
              tool: toolName,
              command,
              path: targetPath,
              matchedRule,
              action: "gate-denied",
            });
            return blockCall(`Blocked by security-hook (${matchedRule}; denied via Telegram)`);
          }

          await appendBlockedLog(logPath, {
            timestamp: new Date().toISOString(),
            agentId,
            tool: toolName,
            command,
            path: targetPath,
            matchedRule,
            action: "gate-timeout",
            timeoutSeconds,
          });
          return blockCall(`Blocked by security-hook (${matchedRule}; approval timeout)`);
        } catch (error) {
          const reason = `${matchedRule}; telegram error: ${String(error)}`;
          await appendBlockedLog(logPath, {
            timestamp: new Date().toISOString(),
            agentId,
            tool: toolName,
            command,
            path: targetPath,
            matchedRule: reason,
            action: "gate-denied",
          });
          return blockCall(`Blocked by security-hook (${reason})`);
        }
      }
    }

    // Allow: return undefined
    return;
  });
}
