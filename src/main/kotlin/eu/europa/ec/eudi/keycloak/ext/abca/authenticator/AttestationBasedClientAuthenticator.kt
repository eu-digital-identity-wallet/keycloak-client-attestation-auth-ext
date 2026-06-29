/*
 * Copyright (c) 2023-2026 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.keycloak.ext.abca.authenticator

import arrow.core.getOrElse
import arrow.core.raise.catch
import arrow.core.raise.context.*
import arrow.core.raise.effect
import arrow.core.raise.getOrElse
import arrow.core.toNonEmptyListOrNull
import com.eygraber.uri.Url
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.util.X509CertUtils
import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeHandler
import eu.europa.ec.eudi.keycloak.ext.abca.toNonBlankString
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.TrustValidator
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.VerificationContext
import eu.europa.ec.eudi.keycloak.ext.abca.util.clientStatus
import eu.europa.ec.eudi.keycloak.ext.abca.util.context.ensure
import eu.europa.ec.eudi.keycloak.ext.abca.util.context.ensureNotNull
import eu.europa.ec.eudi.keycloak.ext.abca.util.dropNanos
import eu.europa.ec.eudi.keycloak.ext.abca.util.isEnabled
import eu.europa.ec.eudi.keycloak.ext.abca.util.provider
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientAttestation
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientAttestationPoP
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientStatusValidator
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.MultivaluedMap
import jakarta.ws.rs.core.Response
import kotlinx.coroutines.runBlocking
import org.keycloak.Config
import org.keycloak.OAuth2Constants
import org.keycloak.authentication.*
import org.keycloak.authentication.authenticators.client.ClientAuthUtil
import org.keycloak.events.Errors
import org.keycloak.models.*
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import org.keycloak.services.Urls
import org.slf4j.LoggerFactory
import java.security.interfaces.ECPublicKey
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.hours
import kotlin.time.Duration.Companion.seconds

class AttestationBasedClientAuthenticator(
    private val httpClient: HttpClient,
    private val clock: Clock,
) : ClientAuthenticator {
    override fun authenticateClient(context: ClientAuthenticationFlowContext) {
        runBlocking {
            with(context) {
                effect {
                    val context = ensureValidClientAttestation()

                    if (hasFormParameters) {
                        val clientId = formParameters.getFirst(OAuth2Constants.CLIENT_ID)
                        if (context.client.isPublicClient) {
                            ensureNotNull(clientId) {
                                ClientAuthenticationError.MissingClientId
                            }
                        }
                        if (null != clientId) {
                            ensure(context.clientAttestation.claims.subject.value == clientId) {
                                ClientAuthenticationError.ClientIdMismatch
                            }
                        }
                    }

                    context(context) {
                        ensureValidClientAttestationPoP()
                    }

                    log.info("Successfully authenticated Client: {}", context.client.clientId)
                    this@with.client = context.client
                    event.client(context.client)
                    session.clientStatus = context.clientAttestation.claims.clientStatus
                    success()
                }.getOrElse { failure(it) }
            }
        }
    }

    context(_: Raise<ClientAuthenticationError>)
    private suspend fun ClientAuthenticationFlowContext.ensureValidClientAttestation(): ClientAttestationContext {
        val header = ensureNotNull(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)) {
            ClientAuthenticationError.MissingClientAttestation
        }
        val clientAttestation = ensureNotNull(ClientAttestation.ofOrNull(header)) {
            ClientAuthenticationError.InvalidClientAttestation
        }
        ensure(session.isEnabled(clientAttestation.signatureAlgorithm)) {
            ClientAuthenticationError.InvalidClientAttestationSignatureAlgorithm
        }

        val client = ensureNotNull(session.clients().getClientByClientId(realm, clientAttestation.claims.subject.value)) {
            ClientAuthenticationError.ClientNotFound
        }
        ensure(client.isEnabled) {
            ClientAuthenticationError.InactiveClient
        }
        val config = ClientAuthenticatorConfig(client, authenticatorConfig)

        val now = clock.now().dropNanos()
        ensure(now < (clientAttestation.claims.expiresAt + config.clockSkew)) {
            ClientAuthenticationError.ExpiredClientAttestation
        }

        if (null != clientAttestation.claims.issuedAt) {
            val clientAttestationIssuedAfter = now - config.clientAttestationMaxAge
            ensure(clientAttestation.claims.issuedAt >= (clientAttestationIssuedAfter - config.clockSkew)) {
                ClientAuthenticationError.StaleClientAttestation
            }
        }

        if (null != clientAttestation.claims.notBefore) {
            ensure(now >= (clientAttestation.claims.notBefore - config.clockSkew)) {
                ClientAuthenticationError.InactiveClientAttestation
            }
        }

        ensure(config.trustValidator.isTrusted(clientAttestation.x5c, VerificationContext.WALLET_INSTANCE_ATTESTATION)) {
            ClientAuthenticationError.ClientAttestationIssuerNotTrusted
        }
        val clientStatusValid = catch({
            config.clientStatusValidator.isValid(clientAttestation.claims.clientStatus)
        }) {
            if ("Invalid JWT signature" == it.message) {
                raise(ClientAuthenticationError.ClientStatusIssuerNotTrusted)
            } else {
                throw it
            }
        }
        ensure(clientStatusValid) {
            ClientAuthenticationError.InvalidClientStatus
        }

        return ClientAttestationContext(clientAttestation, client, config)
    }

    private data class ClientAttestationContext(
        val clientAttestation: ClientAttestation,
        val client: ClientModel,
        val config: ClientAuthenticatorConfig,
    )

    private val ClientAuthenticatorConfig.trustValidator: TrustValidator
        get() {
            val trustValidatorServiceUrl = trustValidatorServiceUrl
            return if (null != trustValidatorServiceUrl) TrustValidator(httpClient, trustValidatorServiceUrl) else TrustValidator.Ignored
        }

    private val ClientAuthenticatorConfig.clientStatusValidator: ClientStatusValidator
        get() = ClientStatusValidator(httpClient, clock, clockSkew) { statusListToken ->
            option {
                ensure(statusListToken.header.algorithm in TS3.ALLOWED_ALGORITHMS)
                val x5c = ensureNotNull(statusListToken.header.x509CertChain?.toNonEmptyListOrNull())
                    .map { X509CertUtils.parseWithException(it.decode()) }
                val signingKey = x5c.first().publicKey
                ensure(signingKey is ECPublicKey)
                ensure(statusListToken.verify(ECDSAVerifier(signingKey)))
                trustValidator.isTrusted(x5c, VerificationContext.WALLET_OR_KEY_STORAGE_STATUS)
            }.getOrElse { false }
        }

    context(_: Raise<ClientAuthenticationError>, context: ClientAttestationContext)
    private suspend fun ClientAuthenticationFlowContext.ensureValidClientAttestationPoP(): ClientAttestationPoP {
        val header = ensureNotNull(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)) {
            ClientAuthenticationError.MissingClientAttestationPoP
        }
        val clientAttestationPoP = ensureNotNull(ClientAttestationPoP.ofOrNull(header)) {
            ClientAuthenticationError.InvalidClientAttestationPoP
        }
        ensure(session.isEnabled(clientAttestationPoP.signatureAlgorithm)) {
            ClientAuthenticationError.InvalidClientAttestationPoPSignatureAlgorithm
        }

        val signatureValid = catch({
            clientAttestationPoP.jwt.verify(ECDSAVerifier(context.clientAttestation.confirmationKey))
        }) { false }
        ensure(signatureValid) {
            ClientAuthenticationError.InvalidClientAttestationPoPSignature
        }

        ensure(context.clientAttestation.claims.subject == clientAttestationPoP.claims.issuer) {
            ClientAuthenticationError.InvalidClientAttestationPoPIssuer
        }

        ensure(issuer.toString().toNonBlankString() in clientAttestationPoP.claims.audience) {
            ClientAuthenticationError.InvalidClientAttestationPoPAudience
        }

        val now = clock.now().dropNanos()
        val clientAttestationPoPIssuedAfter = now - context.config.clientAttestationPoPMaxAge
        ensure(clientAttestationPoP.claims.issuedAt >= (clientAttestationPoPIssuedAfter - context.config.clockSkew)) {
            ClientAuthenticationError.StaleClientAttestationPoP
        }

        val challengeHandler = session.provider<ChallengeHandler>()
        val challenge = ensureNotNull(clientAttestationPoP.claims.challenge) {
            ClientAuthenticationError.InvalidClientAttestationPoPChallenge(challengeHandler.generateNew())
        }
        withError({ ClientAuthenticationError.InvalidClientAttestationPoPChallenge(it.challenge) }) {
            challengeHandler.validate(challenge.value)
        }

        if (null != clientAttestationPoP.claims.notBefore) {
            ensure(now >= (clientAttestationPoP.claims.notBefore - context.config.clockSkew)) {
                ClientAuthenticationError.InactiveClientAttestationPoP
            }
        }

        return clientAttestationPoP
    }

    private fun ClientAuthenticationFlowContext.failure(clientAuthenticationError: ClientAuthenticationError) {
        val (error, errorDescription) = when (clientAuthenticationError) {
            ClientAuthenticationError.MissingClientAttestation -> Errors.INVALID_REQUEST to "Missing ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER} header"
            ClientAuthenticationError.InvalidClientAttestation -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Not a valid Wallet Instance Attestation"
            ClientAuthenticationError.InvalidClientAttestationSignatureAlgorithm -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Wallet Instance Attestation must signed with one of the JWS Algorithms advertised in ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_SUPPORTED_SIGNING_ALGORITHMS}"
            ClientAuthenticationError.ExpiredClientAttestation -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Wallet Instance Attestation is expired"
            ClientAuthenticationError.StaleClientAttestation -> AttestationBasedClientAuthentication.USE_FRESH_ATTESTATION_ERROR to "Stale Wallet Instance Attestation"
            ClientAuthenticationError.InactiveClientAttestation -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Wallet Instance Attestation is not active"
            ClientAuthenticationError.ClientNotFound -> Errors.INVALID_CLIENT to "Client not found"
            ClientAuthenticationError.InactiveClient -> Errors.INVALID_CLIENT to "Client is not active"
            ClientAuthenticationError.ClientAttestationIssuerNotTrusted -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The issuer of the Wallet Instance Attestation is not trusted"
            ClientAuthenticationError.ClientStatusIssuerNotTrusted -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The issuer of the Client Status of the Wallet Instance Attestation is not trusted"
            ClientAuthenticationError.InvalidClientStatus -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The Client Status of the Wallet Instance Attestation is not Valid"
            ClientAuthenticationError.MissingClientId -> Errors.INVALID_REQUEST to "${OAuth2Constants.CLIENT_ID} form parameter is required for public clients"
            ClientAuthenticationError.ClientIdMismatch -> Errors.INVALID_REQUEST to "${OAuth2Constants.CLIENT_ID} form parameter does not match the subject of Wallet Instance Attestation"
            ClientAuthenticationError.MissingClientAttestationPoP -> Errors.INVALID_REQUEST to "Missing ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER} header"
            ClientAuthenticationError.InvalidClientAttestationPoP -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Not a valid Client Attestation PoP"
            ClientAuthenticationError.InvalidClientAttestationPoPSignatureAlgorithm -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Client Attestation PoP must be signed with one of the JWS Algorithms advertised in ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_SUPPORTED_SIGNING_ALGORITHMS}"
            ClientAuthenticationError.InvalidClientAttestationPoPSignature -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The signature of the Client Attestation PoP is not valid"
            ClientAuthenticationError.InvalidClientAttestationPoPIssuer -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The issuer of the Client Attestation PoP is not valid"
            ClientAuthenticationError.InvalidClientAttestationPoPAudience -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The audience of the Client Attestation PoP is not valid"
            ClientAuthenticationError.StaleClientAttestationPoP -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Stale Client Attestation PoP"
            is ClientAuthenticationError.InvalidClientAttestationPoPChallenge -> AttestationBasedClientAuthentication.USE_ATTESTATION_CHALLENGE_ERROR to "The Client Attestation PoP does not contain a valid Challenge"
            ClientAuthenticationError.InactiveClientAttestationPoP -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The Client Attestation PoP is not active"
        }
        val headers = when (clientAuthenticationError) {
            is ClientAuthenticationError.InvalidClientAttestationPoPChallenge -> mapOf(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER to clientAuthenticationError.useAttestationChallenge.value)
            else -> emptyMap()
        }
        val flowError = when (clientAuthenticationError) {
            ClientAuthenticationError.ClientNotFound -> AuthenticationFlowError.CLIENT_NOT_FOUND
            ClientAuthenticationError.InactiveClient -> AuthenticationFlowError.CLIENT_DISABLED
            else -> AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS
        }

        val response = Response.fromResponse(
            ClientAuthUtil.errorResponse(Response.Status.BAD_REQUEST.statusCode, error, errorDescription),
        ).apply {
            headers.forEach { (name, value) -> header(name, value) }
        }.build()

        log.warn("Failed to authenticate Client: {}", clientAuthenticationError)
        client = null
        event.client(null as ClientModel?)
        session.clientStatus = null
        failure(flowError, response)
    }

    override fun close() {
        // no-op
    }

    companion object {
        private val log = LoggerFactory.getLogger(AttestationBasedClientAuthenticator::class.java)
    }
}

private sealed interface ClientAuthenticationError {
    data object MissingClientAttestation : ClientAuthenticationError
    data object InvalidClientAttestation : ClientAuthenticationError
    data object InvalidClientAttestationSignatureAlgorithm : ClientAuthenticationError
    data object ExpiredClientAttestation : ClientAuthenticationError
    data object StaleClientAttestation : ClientAuthenticationError
    data object InactiveClientAttestation : ClientAuthenticationError
    data object ClientNotFound : ClientAuthenticationError
    data object InactiveClient : ClientAuthenticationError
    data object ClientAttestationIssuerNotTrusted : ClientAuthenticationError
    data object ClientStatusIssuerNotTrusted : ClientAuthenticationError
    data object InvalidClientStatus : ClientAuthenticationError
    data object MissingClientId : ClientAuthenticationError
    data object ClientIdMismatch : ClientAuthenticationError
    data object MissingClientAttestationPoP : ClientAuthenticationError
    data object InvalidClientAttestationPoP : ClientAuthenticationError
    data object InvalidClientAttestationPoPSignatureAlgorithm : ClientAuthenticationError
    data object InvalidClientAttestationPoPSignature : ClientAuthenticationError
    data object InvalidClientAttestationPoPIssuer : ClientAuthenticationError
    data object InvalidClientAttestationPoPAudience : ClientAuthenticationError
    data object StaleClientAttestationPoP : ClientAuthenticationError
    data class InvalidClientAttestationPoPChallenge(val useAttestationChallenge: Challenge) : ClientAuthenticationError
    data object InactiveClientAttestationPoP : ClientAuthenticationError
}

class ClientAuthenticatorConfig(private val client: ClientModel, private val authenticator: AuthenticatorConfigModel?) {

    val trustValidatorServiceUrl: Url?
        get() = get(TRUST_VALIDATOR_SERVICE_URL)
            ?.takeIf { it.isNotBlank() }
            ?.let { Url.parse(it) }

    val clockSkew: Duration
        get() = get(CLOCK_SKEW)
            ?.toIntOrNull()
            ?.seconds
            ?.takeIf { it >= Duration.ZERO }
            ?: DEFAULT_CLOCK_SKEW

    val clientAttestationMaxAge: Duration
        get() = get(CLIENT_ATTESTATION_MAX_AGE)
            ?.toIntOrNull()
            ?.seconds
            ?.takeIf { it >= Duration.ZERO }
            ?: DEFAULT_CLIENT_ATTESTATION_MAX_AGE

    val clientAttestationPoPMaxAge: Duration
        get() = get(CLIENT_ATTESTATION_POP_MAX_AGE)
            ?.toIntOrNull()
            ?.seconds
            ?.takeIf { it.isPositive() }
            ?: DEFAULT_CLIENT_ATTESTATION_POP_MAX_AGE

    operator fun get(name: String): String? = (client.getAttribute(name) ?: authenticator?.config[name])

    companion object {
        const val TRUST_VALIDATOR_SERVICE_URL = "trustValidator.serviceUrl"

        const val CLOCK_SKEW = "clock.skew"
        val DEFAULT_CLOCK_SKEW = Duration.ZERO

        const val CLIENT_ATTESTATION_MAX_AGE = "clientAttestation.maxAge"
        val DEFAULT_CLIENT_ATTESTATION_MAX_AGE = 24.hours

        const val CLIENT_ATTESTATION_POP_MAX_AGE = "clientAttestationPoP.maxAge"
        val DEFAULT_CLIENT_ATTESTATION_POP_MAX_AGE = 15.seconds
    }
}

private val ClientAuthenticationFlowContext.httpHeaders: HttpHeaders
    get() = httpRequest.httpHeaders

private val ClientAuthenticationFlowContext.issuer: Url
    get() = Url.parse(Urls.realmIssuer(session.context.uri.baseUri, realm.name))

private val ClientAuthenticationFlowContext.hasFormParameters: Boolean
    get() = httpRequest.httpHeaders.mediaType?.isCompatible(MediaType.APPLICATION_FORM_URLENCODED_TYPE) ?: false

private val ClientAuthenticationFlowContext.formParameters: MultivaluedMap<String, String>
    get() = httpRequest.decodedFormParameters

class AttestationBasedClientAuthenticatorFactory : ClientAuthenticatorFactory {
    override fun create(): ClientAuthenticator = AttestationBasedClientAuthenticator(createHttpClient(), Clock.System)

    override fun create(session: KeycloakSession): ClientAuthenticator = AttestationBasedClientAuthenticator(createHttpClient(), Clock.System)

    override fun isConfigurable(): Boolean = true

    override fun getAdapterConfiguration(session: KeycloakSession, client: ClientModel): Map<String, Any?> = emptyMap()

    override fun getProtocolAuthenticatorMethods(loginProtocol: String): Set<String> = when (loginProtocol) {
        OIDCLoginProtocol.LOGIN_PROTOCOL -> setOf(AttestationBasedClientAuthentication.AUTHENTICATION_METHOD)
        else -> emptySet()
    }

    override fun init(config: Config.Scope) {
        // no-op
    }

    override fun postInit(factory: KeycloakSessionFactory) {
        // no-op
    }

    override fun close() {
        // no-op
    }

    override fun getId(): String = ID

    override fun getDisplayType(): String = "Attestation-Based Client Authentication"

    override fun getReferenceCategory(): String = "client-attestation"

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> = ConfigurableAuthenticatorFactory.REQUIREMENT_CHOICES

    override fun isUserSetupAllowed(): Boolean = false

    override fun getHelpText(): String = "Authenticates OAuth Clients using a Client Attestation JWT, and a Client Attestation PoP JWT bound to a server-issued challenge."

    override fun getConfigProperties(): List<ProviderConfigProperty> = ProviderConfigurationBuilder.create()
        .property()
        .name(ClientAuthenticatorConfig.TRUST_VALIDATOR_SERVICE_URL)
        .type(ProviderConfigProperty.STRING_TYPE)
        .defaultValue(null)
        .label("Trust Validator Service URL")
        .helpText("URL of the Trust Validator Service. When blank, no trust verification is performed.")
        .add()
        .property()
        .name(ClientAuthenticatorConfig.CLOCK_SKEW)
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(0)
        .label("Clock Skew")
        .helpText("Allowed clock skew in seconds. When negative, clock skew is 0.")
        .add()
        .property()
        .name(ClientAuthenticatorConfig.CLIENT_ATTESTATION_MAX_AGE)
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(86400)
        .label("Client Attestation Max Age")
        .helpText("Maximum age of the Client Attestation in seconds. When 0, or negative, defaults to 24 hours.")
        .add()
        .property()
        .name(ClientAuthenticatorConfig.CLIENT_ATTESTATION_POP_MAX_AGE)
        .type(ProviderConfigProperty.INTEGER_TYPE)
        .defaultValue(15)
        .label("Client Attestation PoP Max Age")
        .helpText("Maximum age of the Client Attestation PoP in seconds. When 0, or negative, defaults to 15 seconds.")
        .add()
        .build()

    override fun getConfigPropertiesPerClient(): List<ProviderConfigProperty> = configProperties

    override fun dependsOn(): Set<Class<out Provider>> = setOf(ChallengeHandler::class.java)

    private fun createHttpClient(): HttpClient = HttpClient(Java) {
        install(ContentNegotiation) {
            json()
        }
    }

    companion object {
        const val ID = "abca-draft07"
    }
}
