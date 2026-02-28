import fs from "node:fs";
import https from "node:https";

import { redactValue, scanForCredentials } from "./credential-patterns.ts";

type TelegramConfig = {
  botToken: string;
  chatId: string;
};

function extractTextContent(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }

  if (Array.isArray(content)) {
    return content
      .map((item) => {
        if (typeof item === "string") {
          return item;
        }

        if (item && typeof item === "object") {
          const typed = item as { type?: string; text?: string };
          if (typed.type === "text" && typeof typed.text === "string") {
            return typed.text;
          }
        }

        return "";
      })
      .join(" ")
      .trim();
  }

  return "";
}

function extractAssistantResponse(event: any): string {
  const candidateArrays = [event?.messages, event?.response?.messages, event?.output?.messages];

  for (const candidate of candidateArrays) {
    if (!Array.isArray(candidate)) {
      continue;
    }

    for (let idx = candidate.length - 1; idx >= 0; idx -= 1) {
      const message = candidate[idx];
      if (message?.role === "assistant") {
        const text = extractTextContent(message.content);
        if (text.length > 0) {
          return text;
        }
      }
    }
  }

  const direct = extractTextContent(event?.assistantResponse ?? event?.response?.output_text ?? event?.text);
  return direct;
}

function loadTelegramConfig(configPath = process.env.OPENCLAW_CONFIG_PATH ?? "/home/openclaw/.openclaw/openclaw.json"): TelegramConfig | null {
  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(raw);
    const botToken = parsed?.channels?.telegram?.botToken;
    const chatId = parsed?.channels?.telegram?.allowFrom?.[0];

    if (typeof botToken !== "string" || typeof chatId !== "string") {
      return null;
    }

    return { botToken, chatId };
  } catch {
    return null;
  }
}

function sendTelegramAlert(message: string, config: TelegramConfig, dryRun = process.env.CREDENTIAL_SCANNER_TELEGRAM_DRY_RUN === "1"): Promise<void> {
  if (dryRun) {
    return Promise.resolve();
  }

  return new Promise((resolve, reject) => {
    const body = new URLSearchParams({
      chat_id: config.chatId,
      text: message,
      parse_mode: "Markdown",
    }).toString();

    const request = https.request(
      {
        method: "POST",
        hostname: "api.telegram.org",
        path: `/bot${config.botToken}/sendMessage`,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Content-Length": Buffer.byteLength(body),
        },
      },
      (response) => {
        response.on("data", () => {});
        response.on("end", () => {
          if (response.statusCode && response.statusCode >= 200 && response.statusCode < 300) {
            resolve();
            return;
          }

          reject(new Error(`telegram status ${response.statusCode ?? "unknown"}`));
        });
      },
    );

    request.on("error", (error) => reject(error));
    request.write(body);
    request.end();
  });
}

export default function credentialScanner(api: any) {
  api.logger.info("[plugins] credential-scanner: registered — output credential scanning active");

  api.on("agent_end", async (event: any) => {
    const responseText = extractAssistantResponse(event);
    if (!responseText) {
      return {};
    }

    const detections = scanForCredentials(responseText);
    if (detections.length === 0) {
      return {};
    }

    const telegramConfig = loadTelegramConfig();

    for (const detection of detections) {
      const preview = redactValue(detection.value);

      if (detection.method === "regex") {
        api.logger.error(
          `credential-scanner: [CRITICAL] type="${detection.type}" method="regex" preview="${preview}"`,
        );

        const timestamp = new Date().toISOString();
        const alertMessage = [
          `🚨 Credential Scanner Alert`,
          `Timestamp: ${timestamp}`,
          `Credential type: ${detection.type}`,
          `Preview: ${preview}`,
          `Agent output may contain exposed credentials. Review the dashboard.`,
        ].join("\n");

        if (!telegramConfig) {
          api.logger.warn("credential-scanner: telegram config unavailable; alert not sent");
          continue;
        }

        try {
          await sendTelegramAlert(alertMessage, telegramConfig);
        } catch (error) {
          api.logger.warn(`credential-scanner: telegram alert failed (${String(error)})`);
        }
      } else {
        api.logger.warn(
          `credential-scanner: [WARNING] type="${detection.type}" method="entropy" preview="${preview}"`,
        );
      }
    }

    return {};
  });
}
