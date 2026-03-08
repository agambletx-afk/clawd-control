#!/usr/bin/env node
/**
 * Backfill Knowledge.db → Continuity.db
 *
 * One-time migration of Clint's formational memories (knowledge.db, 5,751 entries)
 * into the continuity system so old and new memories participate in the same
 * RRF search, context injection, and temporal ranking.
 *
 * What it does:
 *   1. Reads all entries from knowledge.db
 *   2. Filters out ARC-AGI failures (193 entries)
 *   3. Deduplicates by exact full-document text
 *   4. Chunks long documents (>2000 chars) at paragraph boundaries
 *   5. Groups by date, writes daily archive JSONs
 *   6. Indexes each date into continuity.db via the Indexer
 *
 * Metadata tagging:
 *   - source: "formational" — enables weight modifiers in searcher
 *   - originalType: preserved from knowledge.db
 *   - knowledgeDbId: original document ID
 *
 * Usage:
 *   node scripts/backfill-knowledge.js --dry-run    # Preview without writing
 *   node scripts/backfill-knowledge.js              # Execute backfill
 *
 * Requires: The gateway to NOT be running (exclusive DB access).
 */

const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');

// ---------------------------------------------------------------
// Config
// ---------------------------------------------------------------

const KNOWLEDGE_DB = '/Users/clint/.openclaw/workspace-clint/knowledge.db';
const CONTINUITY_DIR = path.join(__dirname, '..', 'data', 'agents', 'clint');
const ARCHIVE_DIR = path.join(CONTINUITY_DIR, 'archive');
const INDEX_LOG = path.join(CONTINUITY_DIR, 'index-log.json');

const DRY_RUN = process.argv.includes('--dry-run');
const CHUNK_THRESHOLD = 4000;  // chars — documents longer than this get chunked
const CHUNK_TARGET = 1500;     // chars — target chunk size

// memoryType values to skip entirely (ARC-AGI failures — puzzle noise)
const SKIP_MEMORY_TYPES = new Set(['arc-agi-failure']);

// memoryType values for ARC-AGI successes (kept but weighted lower in searcher)
const ARC_AGI_TYPES = new Set(['arc_agi_attempt']);

// ---------------------------------------------------------------
// Main
// ---------------------------------------------------------------

async function main() {
    console.log(`\n=== Knowledge.db → Continuity Backfill ===`);
    console.log(`Mode: ${DRY_RUN ? 'DRY RUN (no writes)' : 'LIVE'}\n`);

    // 1. Read all entries from knowledge.db
    const sourceDb = new Database(KNOWLEDGE_DB, { readonly: true });
    const allEntries = sourceDb.prepare('SELECT id, document, metadata, created_at FROM documents').all();
    console.log(`Source: ${allEntries.length} total entries in knowledge.db`);

    // 2. Parse metadata and extract types
    // knowledge.db uses two type fields:
    //   meta.type — broad category (e.g., "personal-memory")
    //   meta.memoryType — specific type (e.g., "arc_agi_attempt", "philosophical_foundation")
    // memoryType is the more granular and useful one for filtering/weighting
    const parsed = allEntries.map(e => {
        let meta = {};
        try { meta = JSON.parse(e.metadata || '{}'); } catch {}
        const memoryType = meta.memoryType || null;
        const type = meta.type || 'unknown';
        // For display/metadata: prefer memoryType, fall back to type
        const displayType = memoryType || type;
        return { ...e, meta, type, memoryType, displayType };
    });

    // 3. Filter out skipped memoryTypes (ARC-AGI failures)
    const filtered = parsed.filter(e => !SKIP_MEMORY_TYPES.has(e.memoryType));
    const skippedCount = parsed.length - filtered.length;
    console.log(`Filtered: ${skippedCount} entries skipped (memoryTypes: ${[...SKIP_MEMORY_TYPES].join(', ')})`);

    const arcCount = filtered.filter(e => ARC_AGI_TYPES.has(e.memoryType)).length;
    console.log(`ARC-AGI successes included: ${arcCount} (will be weighted 0.5x in searcher)`);
    console.log(`Remaining: ${filtered.length} entries`);

    // 4. Deduplicate by exact full document text
    const seen = new Map(); // document text → first entry
    const deduped = [];
    let dupCount = 0;

    for (const entry of filtered) {
        const text = (entry.document || '').trim();
        if (!text) continue; // skip empty

        if (seen.has(text)) {
            dupCount++;
            continue;
        }
        seen.set(text, entry);
        deduped.push(entry);
    }
    console.log(`Deduped: ${dupCount} exact duplicates removed`);
    console.log(`Final: ${deduped.length} entries to backfill\n`);

    // 5. Type breakdown (by memoryType for granularity)
    const typeCounts = {};
    for (const e of deduped) {
        typeCounts[e.displayType] = (typeCounts[e.displayType] || 0) + 1;
    }
    console.log('Type breakdown (memoryType):');
    Object.entries(typeCounts)
        .sort((a, b) => b[1] - a[1])
        .forEach(([type, count]) => {
            const marker = ARC_AGI_TYPES.has(type) ? ' [0.5x weight]' : '';
            console.log(`  ${type}: ${count}${marker}`);
        });
    console.log('');

    // 6. Extract date and group entries by date
    const byDate = new Map();
    for (const entry of deduped) {
        const timestamp = entry.meta.timestamp || entry.created_at;
        const date = extractDate(timestamp);
        if (!byDate.has(date)) byDate.set(date, []);
        byDate.get(date).push(entry);
    }

    const sortedDates = [...byDate.keys()].sort();
    console.log(`Date range: ${sortedDates[0]} → ${sortedDates[sortedDates.length - 1]}`);
    console.log(`Unique dates: ${sortedDates.length}\n`);

    // 7. Build archive messages for each date (with chunking)
    let totalMessages = 0;
    let chunkedDocs = 0;
    let totalChunks = 0;
    const archiveData = new Map(); // date → messages[]

    for (const [date, entries] of byDate) {
        const messages = [];

        for (const entry of entries) {
            const text = (entry.document || '').trim();
            const timestamp = entry.meta.timestamp || entry.created_at || `${date}T12:00:00.000Z`;
            const normalizedTs = normalizeTimestamp(timestamp, date);

            // Determine if this is an ARC-AGI entry (tagged for lower weight)
            const isArcAgi = ARC_AGI_TYPES.has(entry.memoryType);
            const originalType = entry.displayType;

            if (text.length > CHUNK_THRESHOLD) {
                // Chunk long documents
                const chunks = chunkText(text, CHUNK_TARGET);
                chunkedDocs++;
                totalChunks += chunks.length;

                for (let ci = 0; ci < chunks.length; ci++) {
                    messages.push({
                        timestamp: normalizedTs,
                        sender: 'agent',
                        text: chunks[ci],
                        _meta: {
                            source: 'formational',
                            originalType,
                            knowledgeDbId: entry.id,
                            chunked: true,
                            chunkIndex: ci,
                            totalChunks: chunks.length,
                            ...(isArcAgi && { arcAgi: true })
                        }
                    });
                }
            } else {
                messages.push({
                    timestamp: normalizedTs,
                    sender: 'agent',
                    text: text,
                    _meta: {
                        source: 'formational',
                        originalType,
                        knowledgeDbId: entry.id,
                        ...(isArcAgi && { arcAgi: true })
                    }
                });
            }
        }

        archiveData.set(date, messages);
        totalMessages += messages.length;
    }

    console.log(`Chunking: ${chunkedDocs} long documents split into ${totalChunks} chunks`);
    console.log(`Total archive messages: ${totalMessages}\n`);

    if (DRY_RUN) {
        console.log('=== DRY RUN COMPLETE — No files written ===');
        console.log(`Would write ${sortedDates.length} archive files`);
        console.log(`Would index ${totalMessages} exchanges into continuity.db`);
        sourceDb.close();
        return;
    }

    // 8. Write archive files (merge with existing if present)
    console.log('Writing archive files...');
    let archiveFilesWritten = 0;
    let archiveFilesUpdated = 0;

    for (const [date, messages] of archiveData) {
        const filePath = path.join(ARCHIVE_DIR, `${date}.json`);
        let archive = { date, messageCount: 0, messages: [] };

        // Load existing archive for this date
        if (fs.existsSync(filePath)) {
            try {
                archive = JSON.parse(fs.readFileSync(filePath, 'utf8'));
                archiveFilesUpdated++;
            } catch {
                // Start fresh if corrupt
            }
        } else {
            archiveFilesWritten++;
        }

        // Build dedup set from existing messages
        const dedupKeys = new Set(
            archive.messages.map(m => `${m.timestamp}_${m.sender}_${(m.text || '').substring(0, 100)}`)
        );

        // Add new messages
        let added = 0;
        for (const msg of messages) {
            const key = `${msg.timestamp}_${msg.sender}_${(msg.text || '').substring(0, 100)}`;
            if (!dedupKeys.has(key)) {
                // Store metadata in the message for the indexer to pick up
                const archiveMsg = {
                    timestamp: msg.timestamp,
                    sender: msg.sender,
                    text: msg.text
                };
                // Attach formational metadata so indexer can include it
                if (msg._meta) {
                    archiveMsg._formational = msg._meta;
                }
                archive.messages.push(archiveMsg);
                dedupKeys.add(key);
                added++;
            }
        }

        if (added > 0) {
            archive.messages.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            archive.messageCount = archive.messages.length;
            fs.writeFileSync(filePath, JSON.stringify(archive, null, 2), 'utf8');
        }
    }
    console.log(`  New archive files: ${archiveFilesWritten}`);
    console.log(`  Updated archive files: ${archiveFilesUpdated}`);

    // 9. Index into continuity.db directly
    //
    // We can't use the Indexer's indexDay() because it generates IDs like
    // exchange_{date}_{index} which would collide with existing continuity
    // exchanges on the same dates. Instead, we initialize the Indexer for
    // its DB connection and embedding function, then insert directly with
    // formational-prefixed IDs.
    console.log('\nIndexing into continuity.db...');

    const Indexer = require('../storage/indexer');
    const config = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'config.default.json'), 'utf8'));
    const indexer = new Indexer(config, CONTINUITY_DIR);
    await indexer.initialize();

    const db = indexer.db;

    const insertExchange = db.prepare(`
        INSERT OR IGNORE INTO exchanges
        (id, date, exchange_index, user_text, agent_text, combined, metadata, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const deleteVec = db.prepare('DELETE FROM vec_exchanges WHERE id = ?');
    const insertVec = db.prepare('INSERT INTO vec_exchanges (id, embedding) VALUES (?, ?)');

    // Check FTS5 availability
    let fts5Available = false;
    try {
        db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='fts_exchanges'").get();
        fts5Available = true;
    } catch {}
    const deleteFts = fts5Available ? db.prepare('DELETE FROM fts_exchanges WHERE id = ?') : null;
    const insertFts = fts5Available ? db.prepare('INSERT INTO fts_exchanges (id, user_text, agent_text) VALUES (?, ?, ?)') : null;

    let totalIndexed = 0;
    let indexErrors = 0;
    let globalIdx = 0; // Global unique counter across all dates

    for (const date of sortedDates) {
        const messages = archiveData.get(date);
        if (!messages || messages.length === 0) continue;

        let dateIndexed = 0;

        for (let i = 0; i < messages.length; i++) {
            const msg = messages[i];
            const meta = msg._meta || {};

            // Create unique ID with formational prefix to avoid collisions
            const chunkSuffix = meta.chunked ? `_c${meta.chunkIndex}` : '';
            const id = `formational_${date}_${i}${chunkSuffix}`;

            // Format for embedding (matches indexer's _formatExchange pattern)
            const time = msg.timestamp?.substring(11, 16) || '12:00';
            const combined = `[${date} ${time}]\nAgent: ${msg.text}`;

            try {
                // Generate embedding
                const embedding = await indexer._embed(combined);
                if (!embedding) {
                    indexErrors++;
                    continue;
                }

                // Build metadata JSON with formational tags
                const metadata = JSON.stringify({
                    timestamp: msg.timestamp,
                    hasUser: false,
                    hasAgent: true,
                    source: meta.source || 'formational',
                    originalType: meta.originalType,
                    knowledgeDbId: meta.knowledgeDbId,
                    ...(meta.chunked && {
                        chunked: true,
                        chunkIndex: meta.chunkIndex,
                        totalChunks: meta.totalChunks
                    }),
                    ...(meta.arcAgi && { arcAgi: true })
                });

                // Insert in transaction
                const transaction = db.transaction(() => {
                    insertExchange.run(
                        id, date, 10000 + i, // high exchange_index to sort after regular exchanges
                        '',                   // user_text (empty — agent-only)
                        msg.text,             // agent_text
                        combined,             // combined
                        metadata,             // metadata
                        msg.timestamp || new Date().toISOString() // created_at
                    );
                    deleteVec.run(id);
                    insertVec.run(id, new Float32Array(embedding));

                    if (deleteFts && insertFts) {
                        deleteFts.run(id);
                        insertFts.run(id, '', msg.text);
                    }
                });
                transaction();

                totalIndexed++;
                dateIndexed++;
                globalIdx++;
            } catch (err) {
                if (!err.message.includes('UNIQUE constraint')) {
                    console.error(`  ${id}: ERROR — ${err.message}`);
                    indexErrors++;
                }
            }
        }

        if (dateIndexed > 0) {
            process.stdout.write(`  ${date}: ${dateIndexed} exchanges indexed\n`);
        }

        // Small delay between dates
        await sleep(50);
    }

    console.log(`\nIndexing complete: ${totalIndexed} exchanges, ${indexErrors} errors`);

    // 11. Summary
    const finalCount = indexer.getExchangeCount();
    console.log(`\n=== BACKFILL COMPLETE ===`);
    console.log(`Total exchanges in continuity.db: ${finalCount}`);
    console.log(`Formational entries added: ${totalIndexed}`);

    indexer.close();
    sourceDb.close();
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

/**
 * Extract YYYY-MM-DD from various timestamp formats.
 */
function extractDate(timestamp) {
    if (!timestamp) return '2025-11-01'; // fallback

    const str = String(timestamp);

    // ISO format: 2025-09-28T00:17:47.323Z
    if (str.includes('T')) {
        return str.substring(0, 10);
    }

    // SQLite format: 2025-09-24 23:08:53
    if (str.includes(' ') && str.includes('-')) {
        return str.substring(0, 10);
    }

    // Unix timestamp (seconds or milliseconds)
    const num = Number(str);
    if (!isNaN(num)) {
        const ms = num > 1e12 ? num : num * 1000;
        return new Date(ms).toISOString().substring(0, 10);
    }

    return '2025-11-01'; // fallback
}

/**
 * Normalize timestamp to ISO format.
 */
function normalizeTimestamp(timestamp, fallbackDate) {
    if (!timestamp) return `${fallbackDate}T12:00:00.000Z`;

    const str = String(timestamp);

    // Already ISO
    if (str.includes('T') && str.includes('-')) return str;

    // SQLite format: 2025-09-24 23:08:53
    if (str.includes(' ') && str.includes('-')) {
        return str.replace(' ', 'T') + '.000Z';
    }

    return `${fallbackDate}T12:00:00.000Z`;
}

/**
 * Chunk text at paragraph boundaries, targeting ~targetLen chars per chunk.
 */
function chunkText(text, targetLen) {
    const paragraphs = text.split(/\n\n+/);
    const chunks = [];
    let current = '';

    for (const para of paragraphs) {
        if (current.length + para.length > targetLen && current.length > 0) {
            chunks.push(current.trim());
            current = para;
        } else {
            current += (current ? '\n\n' : '') + para;
        }
    }

    if (current.trim()) {
        chunks.push(current.trim());
    }

    // If we only got one chunk (no paragraph breaks), force-split
    if (chunks.length === 1 && chunks[0].length > targetLen * 2) {
        return forceSplit(chunks[0], targetLen);
    }

    return chunks.length > 0 ? chunks : [text];
}

/**
 * Force-split text at sentence boundaries when no paragraphs exist.
 */
function forceSplit(text, targetLen) {
    const sentences = text.split(/(?<=[.!?])\s+/);
    const chunks = [];
    let current = '';

    for (const sentence of sentences) {
        if (current.length + sentence.length > targetLen && current.length > 0) {
            chunks.push(current.trim());
            current = sentence;
        } else {
            current += (current ? ' ' : '') + sentence;
        }
    }

    if (current.trim()) {
        chunks.push(current.trim());
    }

    return chunks.length > 0 ? chunks : [text];
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------
// Run
// ---------------------------------------------------------------

main().catch(err => {
    console.error('\nFATAL:', err.message);
    console.error(err.stack);
    process.exit(1);
});
