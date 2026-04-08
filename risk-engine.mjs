import { readFileSync } from 'fs';
import { basename } from 'path';

const TIER_ORDER = {
  routine: 0,
  elevated: 1,
  critical: 2,
};

const CONFIG_PATH = new URL('./risk-patterns.json', import.meta.url);

function loadRiskPatterns() {
  const raw = readFileSync(CONFIG_PATH, 'utf8');
  return JSON.parse(raw);
}

function normalizePath(filePath) {
  return String(filePath || '').replace(/\\/g, '/').toLowerCase();
}

function includesAny(text, patterns) {
  return patterns.some((pattern) => pattern.test(text));
}

function maxTier(...tiers) {
  return tiers.reduce((highest, current) => (TIER_ORDER[current] > TIER_ORDER[highest] ? current : highest), 'routine');
}

export function classifyTaskRisk(task, changedFiles = []) {
  const patterns = loadRiskPatterns();
  const files = Array.isArray(changedFiles) ? changedFiles.map((value) => String(value || '')) : [];
  const filePaths = files.map(normalizePath);
  const fileNames = files.map((file) => basename(file).toLowerCase());
  const reasons = [];
  let tier = 'routine';

  const taskText = [task?.title, task?.description, task?.acceptance_criteria, task?.task_type]
    .filter((value) => typeof value === 'string' && value.trim())
    .join(' ')
    .toLowerCase();

  const criticalChecks = [
    {
      hit: () => patterns.protectedPaths.some((protectedPath) => {
        const target = String(protectedPath).toLowerCase();
        return filePaths.some((filePath) => filePath.includes(target));
      }),
      reason: 'changed file matches protected path',
    },
    {
      hit: () => {
        const authPattern = /\b(secret|auth|credential|api[_\- ]?key|token|oauth)\b/i;
        return authPattern.test(taskText) || filePaths.some((filePath) => authPattern.test(filePath));
      },
      reason: 'auth/secrets keywords detected',
    },
    {
      hit: () => filePaths.some((filePath) => /soul\.md|agents\.md|security-hook|delegation-rules/i.test(filePath)),
      reason: 'sensitive governance file touched',
    },
    {
      hit: () => filePaths.some((filePath) => /migrations?|schema|alter\s*table|create\s*table/i.test(filePath)),
      reason: 'database migration/schema path detected',
    },
    {
      hit: () => filePaths.some((filePath) => /systemd|nginx|cloudflare|firewall|iptables|ufw|\.service/i.test(filePath)),
      reason: 'infrastructure control file touched',
    },
    {
      hit: () => filePaths.some((filePath) => /telegram|email|webhook|agentmail|sendgrid|twilio/i.test(filePath)),
      reason: 'external messaging integration touched',
    },
    {
      hit: () => /\b(data deletion|drop|truncate|destructive operations?)\b/i.test(taskText),
      reason: 'destructive operation described',
    },
    {
      hit: () => {
        const shared = (patterns.sharedLibraries || []).map((file) => String(file).toLowerCase());
        const touchedShared = fileNames.filter((name) => shared.includes(name));
        return touchedShared.length > 0 && files.length >= 3;
      },
      reason: 'cross-service shared library touched in multi-file change',
    },
  ];

  for (const check of criticalChecks) {
    if (check.hit()) {
      reasons.push(check.reason);
      tier = 'critical';
    }
  }

  const elevatedChecks = [
    {
      hit: () => files.length >= 3,
      reason: 'multi-file change (3+ files)',
    },
    {
      hit: () => filePaths.some((filePath) => /\.db\b|\.sql\b|database|query|sqlite/i.test(filePath)),
      reason: 'database read/write surface touched',
    },
    {
      hit: () => filePaths.some((filePath) => /cron|schedule/i.test(filePath)),
      reason: 'scheduled job surface touched',
    },
    {
      hit: () => fileNames.some((name) => name === 'package.json' || name === 'package-lock.json'),
      reason: 'dependency manifest changed',
    },
    {
      hit: () => filePaths.some((filePath) => /(^|\/)\.env(\.|$)|process\.env/i.test(filePath)),
      reason: 'environment variable surface touched',
    },
  ];

  let elevatedTriggered = false;
  for (const check of elevatedChecks) {
    if (check.hit()) {
      reasons.push(check.reason);
      elevatedTriggered = true;
    }
  }

  const routineAdmission =
    files.length <= 1
    && !filePaths.some((filePath) => /systemd|nginx|cloudflare|firewall|iptables|ufw|\.service/i.test(filePath))
    && !filePaths.some((filePath) => /\.db\b|\.sql\b|database|schema|migration/i.test(filePath))
    && !includesAny(taskText, [/\bauth\b/i, /\bsecret\b/i, /\bcredential\b/i, /\btoken\b/i, /oauth/i])
    && !filePaths.some((filePath) => /telegram|email|webhook|agentmail|sendgrid|twilio/i.test(filePath))
    && !filePaths.some((filePath) => patterns.protectedPaths.some((protectedPath) => filePath.includes(String(protectedPath).toLowerCase())))
    && !filePaths.some((filePath) => /\.ya?ml$|\.toml$|\.ini$|\.json$/i.test(filePath));

  if (tier !== 'critical' && (elevatedTriggered || !routineAdmission)) {
    tier = 'elevated';
  }

  if (tier === 'routine') {
    return { tier, reasons: [] };
  }

  return { tier, reasons: [...new Set(reasons)] };
}

export function scanDiffContent(diffText) {
  const patterns = loadRiskPatterns();
  const lines = String(diffText || '')
    .split('\n')
    .filter((line) => line.startsWith('+') && !line.startsWith('+++'));

  const matches = [];
  let tier = 'routine';

  for (const level of ['critical', 'elevated']) {
    for (const patternDef of patterns.contentPatterns?.[level] || []) {
      const regex = new RegExp(patternDef.pattern, patternDef.flags || '');
      for (const line of lines) {
        if (regex.test(line)) {
          matches.push({ pattern: patternDef.name, tier: level, line });
          tier = maxTier(tier, level);
        }
      }
    }
  }

  return { tier, matches };
}

export function reclassifyPostExecution(task, initialTier, changedFiles, diffText) {
  const fileClassification = classifyTaskRisk(task, changedFiles);
  const contentScan = scanDiffContent(diffText);
  const realizedTier = maxTier(fileClassification.tier, contentScan.tier);
  const promoted = TIER_ORDER[realizedTier] > TIER_ORDER[initialTier] ;

  const scopeDrift = promoted
    ? {
      initial_tier: initialTier,
      realized_tier: realizedTier,
      reason: [
        ...fileClassification.reasons,
        ...contentScan.matches.map((match) => `content pattern: ${match.pattern}`),
      ].join('; ') || 'realized scope exceeded planned scope',
      reclassified_at: new Date().toISOString(),
    }
    : null;

  return {
    initialTier,
    realizedTier,
    promoted,
    scopeDrift,
    fileClassification,
    contentScan,
  };
}
