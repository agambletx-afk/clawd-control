import fs from "node:fs";
import path from "node:path";

type SecurityHookConfig = {
  version: string;
  changelog: Array<{ version: string; date: string; note: string }>;
  blocklist: string[];
  protectedPaths: string[];
  allowlist: string[];
  confirmPaths: string[];
  rateLimits: Record<string, unknown>;
};

type RuleMatch = { matched: boolean; rule?: string };

const DEFAULT_CONFIG: SecurityHookConfig = {
  version: "1.0",
  changelog: [
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
  confirmPaths: [],
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
    }

    // Allow: return undefined
    return;
  });
}
