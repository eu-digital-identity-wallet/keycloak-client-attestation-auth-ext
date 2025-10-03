package eu.europa.ec.eudi.keycloak.ext.abca.auth

import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import eu.europa.ec.eudi.keycloak.ext.abca.trust.LotlRefreshTask
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.authentication.ClientAuthenticator
import org.keycloak.authentication.ClientAuthenticatorFactory
import org.keycloak.authentication.ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import org.keycloak.services.ServicesLogger
import org.keycloak.timer.TimerProvider
import java.net.URI

class AttestationClientAuthenticatorFactory : ClientAuthenticatorFactory {
    override fun getId(): String = PROVIDER_ID

    override fun create(session: KeycloakSession): ClientAuthenticator = AttestationClientAuthenticator()

    override fun create(): ClientAuthenticator = AttestationClientAuthenticator()

    private var lotlUrl: String? = null
    private var serviceTypeFilter: String? = null
    private var lotlRefreshIntervalSeconds: Int = 300
    private var lotlHttpTimeoutMs: Int = 15000

    override fun init(config: Config.Scope?) {
        lotlUrl = config?.get("lotl-url") ?: "https://trustedlist.serviceproviders.eudiw.dev/LOTL/01.xml"
        serviceTypeFilter = config?.get("service-type-filter")
        lotlRefreshIntervalSeconds = config?.getInt("lotl-refresh-interval-seconds") ?: 300
        lotlHttpTimeoutMs = config?.getInt("lotl-http-timeout-ms") ?: 15000
        ServicesLogger.LOGGER.info("LOTL refresher initialized: url=$lotlUrl intervalSeconds=$lotlRefreshIntervalSeconds")
    }

    override fun postInit(factory: KeycloakSessionFactory?) {
        try {
            if (lotlUrl.isNullOrBlank()) {
                LOG.info("LOTL refresher not scheduled: no lotl-url configured")
                return
            }
            val intervalMs = lotlRefreshIntervalSeconds.coerceAtLeast(30) * 1000L
            val session = factory?.create()
            if (session == null) {
                LOG.warn("Could not create KeycloakSession to schedule LOTL refresher")
                return
            }
            try {
                val timer = session.getProvider(TimerProvider::class.java)
                val task = LotlRefreshTask(
                    URI(lotlUrl!!),
                    readTimeoutMs = lotlHttpTimeoutMs.toLong(),
                )

                // run now
                task.doRefresh()

                // Schedule repeated task
                timer.scheduleTask(task, intervalMs, "LOTL certificate refresh")
                LOG.info("Scheduled LOTL refresher: url=$lotlUrl intervalSeconds=$lotlRefreshIntervalSeconds")
            } finally {
                session.close()
            }
        } catch (t: Throwable) {
            LOG.warn("Failed to schedule LOTL refresher: ${t.message}", t)
        }
    }

    override fun close() { /* no-op */ }

    override fun getDisplayType(): String = "Attestation-Based Client Authentication"

    override fun getHelpText(): String =
        "Authenticates OAuth clients using attestation results and a proof bound to a server-issued challenge."

    override fun isConfigurable(): Boolean = true

    override fun isUserSetupAllowed(): Boolean = false

    override fun getReferenceCategory(): String = "attestation"

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> = REQUIREMENT_CHOICES

    val clientConfigProperties: MutableList<ProviderConfigProperty> = ProviderConfigurationBuilder.create()
        .property().name("lotl-url")
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("LOTL URL")
        .defaultValue(null)
        .helpText("URL of the List of Trusted Lists (LOTL) to fetch trusted certificates from.")
        .add()
        .property().name("service-type-filter")
        .type(ProviderConfigProperty.STRING_TYPE)
        .label("Service Type Identifier filter")
        .defaultValue(null)
        .helpText("The Service Type Identifiers with which to filter the Services in the LOTL.")
        .add()
        .property().name("lotl-refresh-interval-seconds")
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .label("LOTL Refresh Interval (seconds)")
        .defaultValue(300)
        .helpText("How often the LOTL refresher should run for this client.")
        .add()
        .property().name("lotl-http-timeout-ms")
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .label("LOTL HTTP Timeout (ms)")
        .defaultValue(15000)
        .helpText("HTTP connect/read timeout in milliseconds for LOTL fetching.")
        .add()
        .build()

    override fun getConfigProperties(): MutableList<ProviderConfigProperty> = clientConfigProperties

    override fun getConfigPropertiesPerClient(): MutableList<ProviderConfigProperty> = clientConfigProperties

    override fun getAdapterConfiguration(client: ClientModel): MutableMap<String, Any> = mutableMapOf()

    override fun getProtocolAuthenticatorMethods(loginProtocol: String): MutableSet<String?> =
        when (loginProtocol) {
            OIDCLoginProtocol.LOGIN_PROTOCOL -> mutableSetOf(Spec.AUTHENTICATION_METHOD)
            else -> mutableSetOf()
        }

    companion object {
        const val PROVIDER_ID: String = "attestation-based-client-auth"
        private val LOG: Logger = Logger.getLogger(AttestationClientAuthenticatorFactory::class.java)
    }
}
