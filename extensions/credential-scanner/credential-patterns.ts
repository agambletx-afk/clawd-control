export type DetectionMethod = "regex" | "entropy";

export type DetectionResult = {
  type: string;
  value: string;
  method: DetectionMethod;
};

const HEX_32 = /^[a-f0-9]{32}$/i;
const HEX_64 = /^[a-f0-9]{64}$/i;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const URL = /^https?:\/\//i;
const PATH = /^(\/|~\/|\.\/)/;

export const CREDENTIAL_PATTERNS: Array<{ type: string; regex: RegExp }> = [
  { type: "AWS access key", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { type: "OpenAI API key", regex: /\bsk-[A-Za-z0-9-]{48,}\b/g },
  { type: "GitHub personal access token", regex: /\bghp_[A-Za-z0-9]{36}\b/g },
  { type: "GitHub fine-grained token", regex: /\bgithub_pat_[A-Za-z0-9_\-]+\b/g },
  { type: "Bearer token", regex: /\bBearer\s+[A-Za-z0-9._~+\-/=]{20,}\b/g },
  { type: "OpenRouter key", regex: /\bsk-or-[A-Za-z0-9-]+\b/g },
  { type: "Anthropic API key", regex: /\bsk-ant-[A-Za-z0-9-]+\b/g },
  {
    type: "Environment variable credential leak",
    regex: /\b(?:export\s+)?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD)\s*=\s*["']?[A-Za-z0-9._\-/+=]{12,}["']?/g,
  },
  { type: "Telegram bot token", regex: /\b\d{6,}:[A-Za-z0-9_-]{20,}\b/g },
];

function stripCodeFences(text: string): string {
  return text.replace(/```[\s\S]*?```/g, " ");
}

export function redactValue(secret: string): string {
  if (secret.length <= 6) {
    return "[redacted]";
  }

  return `${secret.slice(0, 4)}...${secret.slice(-2)}`;
}

export function shannonEntropy(input: string): number {
  if (!input) {
    return 0;
  }

  const counts = new Map<string, number>();
  for (const char of input) {
    counts.set(char, (counts.get(char) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / input.length;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

export function isKnownSafeToken(token: string): boolean {
  return HEX_32.test(token) || HEX_64.test(token) || UUID.test(token) || URL.test(token) || PATH.test(token);
}

export function scanForCredentials(text: string): DetectionResult[] {
  const results: DetectionResult[] = [];
  const normalized = stripCodeFences(text);

  for (const { type, regex } of CREDENTIAL_PATTERNS) {
    regex.lastIndex = 0;
    let match: RegExpExecArray | null = regex.exec(normalized);

    while (match) {
      results.push({
        type,
        value: match[0],
        method: "regex",
      });
      match = regex.exec(normalized);
    }
  }

  const tokens = normalized.split(/\s+/).filter((token) => token.length >= 20);
  for (const token of tokens) {
    const trimmed = token.replace(/^["'`([{]+|["'`.,;:!?)}\]]+$/g, "");
    if (trimmed.length < 20 || isKnownSafeToken(trimmed)) {
      continue;
    }

    if (results.some((result) => result.method === "regex" && result.value.includes(trimmed))) {
      continue;
    }

    const entropy = shannonEntropy(trimmed);
    if (entropy > 4.5) {
      results.push({
        type: "High-entropy secret-like token",
        value: trimmed,
        method: "entropy",
      });
    }
  }

  return results;
}
