package eu.europa.ec.eudi.keycloak.ext.abca.trust

import org.jboss.logging.Logger
import org.keycloak.cluster.ClusterProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.timer.ScheduledTask
import java.net.URI

/**
 * Periodic refresher that retrieves a LOTL and loads X.509 certificates into memory.
 *
 * This example expects either:
 *  - a PEM bundle with one or more certificates, or
 *  - a base64 DER bundle (single cert) in the HTTP response body.
 * Adjust parsing to your actual LOTL format as needed.
 */
class LotlRefreshTask(
    private val lotlUri: URI,
    private val serviceTypeFilter: String? = null,
    private val readTimeoutMs: Long = 15_000,
    private val clusterGuardKey: String = "abca.lotl.refresh",
) : ScheduledTask {

    override fun run(session: KeycloakSession) {
        // Ensure only one node performs the actual HTTP fetch per interval across the cluster.
        val cluster = session.getProvider(ClusterProvider::class.java)
        cluster.executeIfNotExecuted(clusterGuardKey, readTimeoutMs.toInt()) {
            doRefresh()
        }
    }

    fun doRefresh() {
        try {
            val fetcher = FetchLOTLCertificatesDSS()
            val config = TrustedListConfig(
                location = lotlUri.toURL(),
                serviceTypeFilter = serviceTypeFilter,
                keystoreConfig = null,
            )
            val result = fetcher.invoke(config)
            result.onSuccess { certs ->
                if (certs.isEmpty()) {
                    LOG.warn("LOTL refresh: DSS returned no certificates from $lotlUri")
                    return@onSuccess
                }
                LotlTrustStore.update(certs)
                LOG.info("LOTL refresh: Updated ${certs.size} certificates from $lotlUri")
            }.onFailure { t ->
                LOG.warn("LOTL refresh failed via DSS fetcher: ${t.message}", t)
            }
        } catch (t: Throwable) {
            LOG.warn("LOTL refresh failed (unexpected): ${t.message}", t)
        }
    }

    companion object {
        private val LOG: Logger = Logger.getLogger(LotlRefreshTask::class.java)
    }
}
