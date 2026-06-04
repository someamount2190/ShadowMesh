package mesh.shadowmesh.storage

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

@Dao
interface PeerModelDao {

    @Query("SELECT * FROM peer_models WHERE nodeId = :nodeId LIMIT 1")
    suspend fun getPeer(nodeId: String): PeerModelEntity?

    /** Whole-row upsert — the abstractor produces a complete new model, so replace is correct. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(model: PeerModelEntity)

    @Query("SELECT * FROM peer_models")
    suspend fun allPeers(): List<PeerModelEntity>

    /**
     * Candidate relays: enough samples behind the weight AND weight above threshold.
     * Confidence (deliverySamples) is enforced in SQL so callers can't accidentally trust a
     * high weight built from a single encounter.
     */
    @Query(
        "SELECT * FROM peer_models WHERE deliverySamples >= :minSamples " +
        "AND deliveryWeight >= :minWeight ORDER BY deliveryWeight DESC"
    )
    suspend fun reliableRelays(minSamples: Int, minWeight: Double): List<PeerModelEntity>

    @Query("DELETE FROM peer_models WHERE nodeId = :nodeId")
    suspend fun deletePeer(nodeId: String)
}
