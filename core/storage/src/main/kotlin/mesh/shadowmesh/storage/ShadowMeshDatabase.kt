package mesh.shadowmesh.storage

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters
import net.zetetic.database.sqlcipher.SQLiteDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import net.zetetic.database.sqlcipher.SQLiteDatabaseHook
import net.zetetic.database.sqlcipher.SQLiteConnection

/**
 * SQLCipher-encrypted Room database — design doc Phase 3.
 *
 * All persistent storage is AES-256 encrypted via SQLCipher. The encryption
 * key is derived from the Android Keystore (hardware-backed) — it is never
 * stored in plaintext on disk or in SharedPreferences.
 *
 * Key derivation: the caller supplies the 32-byte database key, which has
 * already been unwrapped by BiometricKeyManager (for COMPARTMENTED channels)
 * or derived via IntegrityBoundedKeyDerivation (for OPEN/CLOSED channels).
 * This class does not touch key material directly — it receives the key and
 * passes it to SQLCipher's SupportFactory.
 *
 * Database version: 1.
 * Migration strategy: addMigrations() for schema changes — never destructive.
 *
 * Thread-safety: Room handles all threading. Do not call from main thread
 * (allowMainThreadQueries is only enabled in tests).
 */


@Database(
    entities = [
        ChannelEntity::class,
        PostEntity::class,
        FragmentEntity::class,
        BlocklistEntry::class,
        ReputationEntry::class,
        RatchetCheckpointEntity::class,
        PollEntity::class,
        ReactionEntity::class,
        TransferCheckpointEntity::class,
        EntryNodePreference::class,
        NodeSettingEntity::class,
        UsedBootstrapNonce::class,
        PeerModelEntity::class,
        PollVoteEntity::class,
        MemberRemovalEntry::class,
        DiscoveredPeerEntity::class
    ],
    version = 15,   // v15: discovered_peers table for bootstrap warm-start
    exportSchema = true
)
@TypeConverters(ShadowMeshTypeConverters::class)
abstract class ShadowMeshDatabase : RoomDatabase() {
    abstract fun dao(): ShadowMeshDao
    abstract fun ratchetDao(): RatchetDao
    abstract fun peerDao(): PeerModelDao
    abstract fun memberRemovalDao(): MemberRemovalDao

    companion object {
        // v9→v10: create peer_models table. New table only — no data transform — so the
        // migration is a pure CREATE; existing rows in other tables are untouched.
        val MIGRATION_9_10 = object : androidx.room.migration.Migration(9, 10) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS peer_models (" +
                        "nodeId TEXT NOT NULL PRIMARY KEY, " +
                        "deliveryWeight REAL NOT NULL DEFAULT 0.0, " +
                        "deliverySamples INTEGER NOT NULL DEFAULT 0, " +
                        "todNightCount INTEGER NOT NULL DEFAULT 0, " +
                        "todMorningCount INTEGER NOT NULL DEFAULT 0, " +
                        "todAfternoonCount INTEGER NOT NULL DEFAULT 0, " +
                        "todEveningCount INTEGER NOT NULL DEFAULT 0, " +
                        "encounterCount INTEGER NOT NULL DEFAULT 0, " +
                        "globalSeqFirstSeen INTEGER NOT NULL DEFAULT 0, " +
                        "globalSeqLastSeen INTEGER NOT NULL DEFAULT 0, " +
                        "observedChannelsMask INTEGER NOT NULL DEFAULT 0, " +
                        "modelVersion INTEGER NOT NULL DEFAULT 1)"
                )
            }
        }

        // v10→v11: replace cumulative observedChannelsMask with a sliding-window pair.
        //
        // WHY: observedChannelsMask was a lifetime OR-accumulation of channel co-membership
        // bitsets across all encounters. An adversary seizing the DB could read the full
        // history of channel slots shared with each peer — a durable intersection-attack
        // surface not covered by the six-hour-bucket caveat in THREAT_MODEL.md §2.
        //
        // The fix replaces it with:
        //   channelsMaskRecentWindow        — the OR-accumulation for the CURRENT window
        //   channelsMaskEpochEncounterCount — encounterCount at window-open time
        //
        // When (encounterCount − channelsMaskEpochEncounterCount) exceeds
        // PeerModelEntity.CHANNEL_MASK_WINDOW_ENCOUNTERS on the next fold, the mask resets.
        //
        // Migration defaults:
        //   channelsMaskRecentWindow = 0        (no channels observed in new window)
        //   channelsMaskEpochEncounterCount = 0 (epoch at zero)
        //
        // For existing rows where encounterCount > CHANNEL_MASK_WINDOW_ENCOUNTERS, the gap
        // (encounterCount − 0) immediately exceeds the window on the next encounter fold,
        // clearing the old cumulative mask. This is the correct behavior: do not carry the
        // old lifetime-accumulation forward under the new windowed semantics.
        //
        // observedChannelsMask is dropped. SQLite < 3.35 (Android API < 34) requires the
        // recreate-copy-drop strategy; API 34+ supports DROP COLUMN directly. We use
        // recreate-copy-drop for maximum compatibility.
        val MIGRATION_10_11 = object : androidx.room.migration.Migration(10, 11) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                // 1. Create the new table with the correct schema.
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS peer_models_new (" +
                        "nodeId TEXT NOT NULL PRIMARY KEY, " +
                        "deliveryWeight REAL NOT NULL DEFAULT 0.0, " +
                        "deliverySamples INTEGER NOT NULL DEFAULT 0, " +
                        "todNightCount INTEGER NOT NULL DEFAULT 0, " +
                        "todMorningCount INTEGER NOT NULL DEFAULT 0, " +
                        "todAfternoonCount INTEGER NOT NULL DEFAULT 0, " +
                        "todEveningCount INTEGER NOT NULL DEFAULT 0, " +
                        "encounterCount INTEGER NOT NULL DEFAULT 0, " +
                        "globalSeqFirstSeen INTEGER NOT NULL DEFAULT 0, " +
                        "globalSeqLastSeen INTEGER NOT NULL DEFAULT 0, " +
                        "channelsMaskRecentWindow INTEGER NOT NULL DEFAULT 0, " +
                        "channelsMaskEpochEncounterCount INTEGER NOT NULL DEFAULT 0, " +
                        "modelVersion INTEGER NOT NULL DEFAULT 1)"
                )
                // 2. Copy all columns that survive. observedChannelsMask is intentionally
                //    NOT copied — existing accumulated data is discarded. New window columns
                //    default to 0, which is correct per the migration rationale above.
                db.execSQL(
                    "INSERT INTO peer_models_new " +
                        "(nodeId, deliveryWeight, deliverySamples, " +
                        "todNightCount, todMorningCount, todAfternoonCount, todEveningCount, " +
                        "encounterCount, globalSeqFirstSeen, globalSeqLastSeen, modelVersion) " +
                        "SELECT nodeId, deliveryWeight, deliverySamples, " +
                        "todNightCount, todMorningCount, todAfternoonCount, todEveningCount, " +
                        "encounterCount, globalSeqFirstSeen, globalSeqLastSeen, modelVersion " +
                        "FROM peer_models"
                )
                // 3. Swap tables.
                db.execSQL("DROP TABLE peer_models")
                db.execSQL("ALTER TABLE peer_models_new RENAME TO peer_models")
            }
        }

        // FIX (B1): v3→v4 adds tier1Unlocked column to posts table.
        val MIGRATION_8_9 = object : androidx.room.migration.Migration(8, 9) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                // v8→v9: add totalData column to fragments table.
                // totalData is the number of data shards needed for FEC reconstruction
                // (may differ from total = totalData + totalParity in FEC configurations).
                // Default 0, then backfilled to total (conservative — treat all as data shards
                // for existing rows until they are re-received with correct FEC metadata).
                db.execSQL("ALTER TABLE fragments ADD COLUMN totalData INTEGER NOT NULL DEFAULT 0")
                db.execSQL("UPDATE fragments SET totalData = total WHERE totalData = 0")
            }
        }

        val MIGRATION_3_4 = object : androidx.room.migration.Migration(3, 4) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "ALTER TABLE posts ADD COLUMN tier1Unlocked INTEGER NOT NULL DEFAULT 0"
                )
            }
        }

        // v4→v5: dedicated SHADOWFILES resume-checkpoint table (replaces the
        // synthetic-fragment-row workaround).
        val MIGRATION_4_5 = object : androidx.room.migration.Migration(4, 5) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS transfer_checkpoints (" +
                        "transferId TEXT NOT NULL PRIMARY KEY, " +
                        "lastChunkIndex INTEGER NOT NULL, " +
                        "totalChunks INTEGER NOT NULL, " +
                        "updatedAtMs INTEGER NOT NULL)"
                )
            }
        }

        // v5→v6: Entry Node preference table and key-value settings table.
        //   entry_node_preferences: persists the user's ranked Entry Node list
        //     (global and per-channel overrides).
        //   node_settings: generic key-value store for scalar settings such as
        //     the Entry Node mode (AUTOMATIC / ASK_EACH_TIME).
        val MIGRATION_5_6 = object : androidx.room.migration.Migration(5, 6) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS entry_node_preferences (" +
                        "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, " +
                        "nodeId TEXT NOT NULL, " +
                        "displayName TEXT NOT NULL, " +
                        "rank INTEGER NOT NULL, " +
                        "channelOverrideId TEXT, " +
                        "addedAtMs INTEGER NOT NULL)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_entry_node_preferences_rank " +
                        "ON entry_node_preferences (rank)"
                )
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS index_entry_node_preferences_channelOverrideId " +
                        "ON entry_node_preferences (channelOverrideId)"
                )
                db.execSQL(
                    "CREATE UNIQUE INDEX IF NOT EXISTS " +
                        "index_entry_node_preferences_nodeId_channelOverrideId " +
                        "ON entry_node_preferences (nodeId, channelOverrideId)"
                )
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS node_settings (" +
                        "key TEXT NOT NULL PRIMARY KEY, " +
                        "value TEXT NOT NULL)"
                )
            }
        }

        // v6→v7: used_bootstrap_nonces — persisted set of accepted QR/NFC nonces,
        // preventing replay of a captured code after a process restart within the
        // 5-minute validity window. Nonces are retained for 10 minutes (2× window)
        // and swept by TtlSweepWorker.
        val MIGRATION_6_7 = object : androidx.room.migration.Migration(6, 7) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS used_bootstrap_nonces (" +
                        "nonceHex TEXT NOT NULL PRIMARY KEY, " +
                        "seenAtMs INTEGER NOT NULL)"
                )
            }
        }

        // v7→v8: composite index on posts(channelId, postState, openedAtMs).
        // observeUnreadCount and unreadCountForChannel filter by all three columns;
        // the previous per-column indices forced a full channelId scan with post-filter.
        // This covering index lets SQLite resolve the query in O(log n + k).
        val MIGRATION_7_8 = object : androidx.room.migration.Migration(7, 8) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE INDEX IF NOT EXISTS " +
                        "index_posts_channelId_postState_openedAtMs " +
                        "ON posts (channelId, postState, openedAtMs)"
                )
            }
        }

        // v11→v12: two schema changes.
        //
        // 1. ratchet_checkpoints: shared single-sender PK (channelId) → per-sender composite
        //    PK (channelId, senderNodeId). The previous design derived a single shared chain
        //    key for the whole channel; the new design gives each sender their own independent
        //    chain key derived from HKDF(channelKey, salt=senderNodeId). This eliminates ratchet
        //    divergence when isolated network partitions both post to the same channel offline:
        //    each cluster advances only its own members' chains, which are disjoint, so merge is
        //    trivially correct.
        //
        //    Migration: drop old table, create new table with composite PK. Old checkpoints cannot
        //    be migrated because they belong to the shared chain model and the per-sender chains
        //    start fresh from (channelKey, senderNodeId) on next use. This is safe: the channel
        //    key is preserved; the per-sender ratchet is re-derived and advanced on demand. Users
        //    may need to re-fetch recent messages (within 7-day TTL) if the ratchet position
        //    was past a checkpoint boundary, but the DHT still holds all fragments.
        //
        // 2. posts: add receivedOffline INTEGER column (0 = normal, 1 = arrived during a
        //    reconnect sync window). Used by the UI to show a "While you were offline" separator
        //    grouping catch-up messages for users who rejoin after a partition or network absence.
        //    Default 0 for existing rows (they were received in normal online operation).
        val MIGRATION_11_12 = object : androidx.room.migration.Migration(11, 12) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                // 1. ratchet_checkpoints: recreate with composite PK.
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS ratchet_checkpoints_new (" +
                        "channelId TEXT NOT NULL, " +
                        "senderNodeId TEXT NOT NULL DEFAULT '', " +
                        "encryptedChainKey BLOB NOT NULL, " +
                        "postIndex INTEGER NOT NULL, " +
                        "updatedAtMs INTEGER NOT NULL, " +
                        "PRIMARY KEY(channelId, senderNodeId))"
                )
                // Old rows belong to the shared-chain model and cannot be meaningfully migrated
                // to per-sender chains. Drop and start fresh.
                db.execSQL("DROP TABLE ratchet_checkpoints")
                db.execSQL("ALTER TABLE ratchet_checkpoints_new RENAME TO ratchet_checkpoints")

                // 2. posts: add receivedOffline column.
                db.execSQL("ALTER TABLE posts ADD COLUMN receivedOffline INTEGER NOT NULL DEFAULT 0")
            }
        }

        // v12→v13: endorsedPostId — nullable TEXT column on posts.
        // Links an endorsement post back to the original OFFLINE_LOCAL post on the author's device.
        // Existing rows get NULL (no endorsement), which is the correct default.
        val MIGRATION_12_13 = object : androidx.room.migration.Migration(12, 13) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE posts ADD COLUMN endorsedPostId TEXT")
            }
        }

        // v13→v14: distributed-systems correctness fixes.
        //   channels: keyVersionNumber (rotation counter) + keyVersionTimestampMs (rotation wall-clock).
        //   posts:    sequenceNumber — monotonic per (channelId, authorNodeId) for clock-independent ordering.
        //   member_removals: new table for explicit membership removal events.
        val MIGRATION_13_14 = object : androidx.room.migration.Migration(13, 14) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE channels ADD COLUMN keyVersionNumber INTEGER NOT NULL DEFAULT 1")
                db.execSQL("ALTER TABLE channels ADD COLUMN keyVersionTimestampMs INTEGER NOT NULL DEFAULT 0")
                db.execSQL("ALTER TABLE posts ADD COLUMN sequenceNumber INTEGER NOT NULL DEFAULT 0")
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS member_removals (" +
                        "channelId TEXT NOT NULL, " +
                        "removedNodeId TEXT NOT NULL, " +
                        "removedAtMs INTEGER NOT NULL, " +
                        "initiatorNodeId TEXT NOT NULL, " +
                        "receivedAtMs INTEGER NOT NULL, " +
                        "PRIMARY KEY(channelId, removedNodeId))"
                )
            }
        }

        // v14→v15: discovered_peers table for bootstrap warm-start.
        //   Stores the best-known address and trust level of each peer seen in the
        //   last session so DhtEngine.bootstrap() can skip the cold-start latency.
        val MIGRATION_14_15 = object : androidx.room.migration.Migration(14, 15) {
            override fun migrate(db: androidx.sqlite.db.SupportSQLiteDatabase) {
                db.execSQL(
                    "CREATE TABLE IF NOT EXISTS discovered_peers (" +
                        "nodeIdHex TEXT NOT NULL PRIMARY KEY, " +
                        "lastSeenMs INTEGER NOT NULL, " +
                        "transport TEXT NOT NULL, " +
                        "addressHint TEXT, " +
                        "trustLevel TEXT NOT NULL)"
                )
            }
        }

        @Volatile private var INSTANCE: ShadowMeshDatabase? = null

        /**
         * Get or create the encrypted database instance.
         *
         * @param ctx        Android context (application scope recommended).
         * @param dbKey      32-byte key from Android Keystore. Caller owns the
         *                   lifecycle — wipe with fill(0) after this call returns.
         * @param allowMainThread  True only in tests. Never set in production.
         */
        fun getInstance(
            ctx:             Context,
            dbKey:           ByteArray,
            allowMainThread: Boolean = false
        ): ShadowMeshDatabase = INSTANCE ?: synchronized(this) {
            INSTANCE ?: build(ctx, dbKey, allowMainThread).also { INSTANCE = it }
        }

        private fun build(
            ctx:             Context,
            dbKey:           ByteArray,
            allowMainThread: Boolean
        ): ShadowMeshDatabase {
            require(dbKey.size == 32) { "Database key must be 32 bytes" }
            // Load the SQLCipher native library before any JNI method on SQLiteConnection
            // is invoked. SupportOpenHelperFactory does NOT trigger loading on its own —
            // Room's SupportSQLiteOpenHelper calls into SQLiteConnection (which has native
            // methods) before SQLiteDatabase's static initializer has a chance to run.
            // System.loadLibrary is idempotent; safe to call on every build().
            System.loadLibrary("sqlcipher")
            // Pass PRAGMA secure_delete=ON alongside the encryption key.
            // secure_delete causes SQLCipher to overwrite deleted page content with zeros
            // before returning freed pages to the free-list. Without it, deleted rows
            // (messages, fragments, channel keys) remain as plaintext-ish content in free
            // pages until overwritten by new data — a forensic examiner with the DB key
            // can extract recently-deleted content. With it, the overwrite happens
            // synchronously on each DELETE, making recovery from free pages infeasible.
            //
            // Performance cost: ~5–15% on delete-heavy operations (TtlSweepWorker, panic wipe
            // steps). This is acceptable given the threat model (device seizure by adversaries
            // with forensic tools). The cost is negligible compared to the encryption overhead.
            //
            // SupportFactory(key, hook, clearPassphrase):
            //   - key:             encryption key bytes
            //   - hook:            SQLiteDatabaseHook for pre/post-key pragmas
            //   - clearPassphrase: zero the key array after use (true = secure)
            val hook = object : SQLiteDatabaseHook {
                override fun preKey(connection: SQLiteConnection) {}
                override fun postKey(connection: SQLiteConnection) {
                    // SQLCipher 4.x: PRAGMA secure_delete returns a result row (current value),
                    // so execute() throws "use query/rawQuery". Use executeForLong() for it.
                    // PRAGMA cipher_memory_security returns no rows, so execute() is correct.
                    connection.executeForLong("PRAGMA secure_delete = ON", null, null)
                    connection.execute("PRAGMA cipher_memory_security = ON", null, null)
                }
            }
            val factory = SupportOpenHelperFactory(dbKey, hook, true)
            return Room.databaseBuilder(ctx, ShadowMeshDatabase::class.java, DB_NAME)
                .openHelperFactory(factory)
                // Room 2.6.x defaults to AUTOMATIC (WAL) which calls PRAGMA journal_mode=WAL
                // via SQLiteDatabase.setWriteAheadLoggingEnabled(). SQLCipher 4.5.x wraps the
                // resulting SQLITE_ROW from that PRAGMA as code-0 "use query/rawQuery" error.
                // TRUNCATE avoids the WAL enablement call and is compatible with SQLCipher.
                .setJournalMode(androidx.room.RoomDatabase.JournalMode.TRUNCATE)
                .addMigrations(MIGRATION_3_4, MIGRATION_4_5, MIGRATION_5_6, MIGRATION_6_7, MIGRATION_7_8, MIGRATION_8_9, MIGRATION_9_10, MIGRATION_10_11, MIGRATION_11_12, MIGRATION_12_13, MIGRATION_13_14, MIGRATION_14_15)
                .apply { if (allowMainThread) allowMainThreadQueries() }
                .build()
        }

        /**
         * Close and clear the singleton — call on app destruction or panic wipe.
         * The database file remains encrypted on disk; it becomes inaccessible
         * without the key.
         */
        fun close() {
            INSTANCE?.close()
            INSTANCE = null
        }

        private const val DB_NAME = "shadowmesh.db"
    }
}

// ── Type converters ───────────────────────────────────────────────────────────

class ShadowMeshTypeConverters {

    @TypeConverter fun channelTypeToString(v: ChannelType): String = v.name
    @TypeConverter fun stringToChannelType(v: String): ChannelType = ChannelType.valueOf(v)

    @TypeConverter fun postStateToString(v: PostState): String = v.name
    @TypeConverter fun stringToPostState(v: String): PostState = PostState.valueOf(v)

    @TypeConverter fun repTierToString(v: ReputationTier): String = v.name
    @TypeConverter fun stringToRepTier(v: String): ReputationTier = ReputationTier.valueOf(v)

    @TypeConverter fun blockSourceToString(v: BlockSource): String = v.name
    @TypeConverter fun stringToBlockSource(v: String): BlockSource = BlockSource.valueOf(v)

    @TypeConverter fun bytesToBlob(v: ByteArray?): ByteArray? = v
}
