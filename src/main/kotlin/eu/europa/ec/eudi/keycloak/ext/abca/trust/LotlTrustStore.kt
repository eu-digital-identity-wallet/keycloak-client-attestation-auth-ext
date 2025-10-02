package eu.europa.ec.eudi.keycloak.ext.abca.trust

import java.security.cert.X509Certificate
import java.util.concurrent.atomic.AtomicReference

/**
 * Simple per-node in-memory storage for LOTL-provided trusted certificates.
 *
 * Nodes refresh their stores periodically via LotlRefreshTask scheduled in the factory.
 */
object LotlTrustStore {
    private val ref = AtomicReference<List<X509Certificate>>(emptyList())

    @Volatile
    var lastUpdatedEpochSeconds: Long = 0
        private set

    fun get(): List<X509Certificate> = ref.get()

    fun update(list: List<X509Certificate>, nowEpochSeconds: Long = System.currentTimeMillis() / 1000) {
        ref.set(list)
        lastUpdatedEpochSeconds = nowEpochSeconds
    }
}
