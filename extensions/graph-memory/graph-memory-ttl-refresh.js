// ===========================================================================
// graph-memory-ttl-refresh.js
// ===========================================================================
// Snippet to add to the graph-memory plugin's activation bump section.
// This updates last_confirmed_at and recalculates expires_at when facts
// are retrieved during context injection.
//
// WHERE TO ADD: Inside the graph-memory plugin's activation bump logic,
// after the existing Hebbian score bump, before returning results.
//
// DEPENDS ON: better-sqlite3 (already installed in the plugin)
// ===========================================================================

// TTL values in seconds (must match graph-migrate-decay.py)
const TTL_SECONDS = {
  permanent:  null,
  stable:     90 * 24 * 3600,   // 7,776,000
  active:     14 * 24 * 3600,   // 1,209,600
  session:    24 * 3600,        // 86,400
  checkpoint: 4  * 3600,        // 14,400
};

/**
 * Refresh TTL for accessed facts.
 *
 * Called after the activation bump when facts are retrieved for injection.
 * Only extends TTL for 'stable' and 'active' facts.
 * Permanent facts need no expiry update.
 * Session and checkpoint facts do NOT extend on access.
 *
 * @param {import('better-sqlite3').Database} db - The facts database
 * @param {string[]} factIds - IDs of facts being injected into context
 */
function refreshAccessedFacts(db, factIds) {
  if (!factIds || factIds.length === 0) return;

  const nowSec = Math.floor(Date.now() / 1000);

  // Check if decay columns exist before attempting refresh
  const cols = db.prepare("PRAGMA table_info(facts)").all();
  const colNames = new Set(cols.map(c => c.name));
  if (!colNames.has("decay_class")) return; // Not migrated yet, skip silently

  const stmt = db.prepare(`
    UPDATE facts
    SET last_confirmed_at = @now,
        confidence = 1.0,
        expires_at = CASE decay_class
          WHEN 'stable' THEN @now + @stableTtl
          WHEN 'active' THEN @now + @activeTtl
          ELSE expires_at
        END
    WHERE id = @id
      AND decay_class IN ('stable', 'active')
  `);

  const tx = db.transaction(() => {
    for (const id of factIds) {
      stmt.run({
        now: nowSec,
        stableTtl: TTL_SECONDS.stable,
        activeTtl: TTL_SECONDS.active,
        id,
      });
    }
  });
  tx();
}

// ===========================================================================
// INTEGRATION POINT
// ===========================================================================
// In the graph-memory plugin's main file (index.js or similar), find the
// section that bumps activation scores after retrieving facts. It looks
// something like:
//
//   // Bump activation scores (Hebbian learning)
//   for (const fact of results) {
//     db.prepare('UPDATE facts SET activation = activation + 1 WHERE rowid = ?')
//       .run(fact.rowid);
//   }
//
// After that block, add:
//
//   // TTL refresh: extend expiry for accessed stable/active facts
//   const factIds = results
//     .map(r => r.id)
//     .filter(Boolean);
//   refreshAccessedFacts(db, factIds);
//
// ===========================================================================

module.exports = { refreshAccessedFacts, TTL_SECONDS };
