package mesh.shadowmesh.storage

import androidx.room.*

@Dao
interface MemberRemovalDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertRemoval(entry: MemberRemovalEntry)

    @Query("SELECT * FROM member_removals WHERE channelId = :channelId")
    suspend fun getRemovalsForChannel(channelId: String): List<MemberRemovalEntry>

    @Query("SELECT * FROM member_removals WHERE channelId = :channelId AND removedNodeId = :nodeId LIMIT 1")
    suspend fun getRemoval(channelId: String, nodeId: String): MemberRemovalEntry?

    @Query("SELECT COUNT(*) FROM member_removals WHERE channelId = :channelId AND removedNodeId = :nodeId")
    suspend fun isRemoved(channelId: String, nodeId: String): Int

    @Query("DELETE FROM member_removals WHERE channelId = :channelId AND removedAtMs < :cutoffMs")
    suspend fun deleteOldRemovals(channelId: String, cutoffMs: Long)
}
