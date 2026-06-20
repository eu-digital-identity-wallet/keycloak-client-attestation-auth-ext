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
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

class AttestationBasedClientAuthenticator(
    private val httpClient: HttpClient = createHttpClient(),
    private val clock: Clock = Clock.System,
) : ClientAuthenticator {
    override fun authenticateClient(context: ClientAuthenticationFlowContext) {
        runBlocking {
            with(context) {
                effect {
                    val (clientAttestation, client) = ensureValidClientAttestationAndActiveClient()

                    if (hasFormParameters) {
                        val clientId = formParameters.getFirst(OAuth2Constants.CLIENT_ID)
                        if (client.isPublicClient) {
                            ensureNotNull(clientId) {
                                ClientAuthenticationError.MissingClientId
                            }
                        }
                        if (null != clientId) {
                            ensure(clientAttestation.claims.subject.value == clientId) {
                                ClientAuthenticationError.ClientIdMismatch
                            }
                        }
                    }

                    ensureValidClientAttestationPoP(clientAttestation)

                    log.info("Successfully authenticated Client: {}", client.clientId)
                    this@with.client = client
                    event.client(client)
                    session.clientStatus = clientAttestation.claims.clientStatus
                    success()
                }.getOrElse { failure(it) }
            }
        }
    }

    context(_: Raise<ClientAuthenticationError>)
    private suspend fun ClientAuthenticationFlowContext.ensureValidClientAttestationAndActiveClient(): Pair<ClientAttestation, ClientModel> {
        val header = ensureNotNull(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)) {
            ClientAuthenticationError.MissingClientAttestation
        }
        val clientAttestation = ensureNotNull(ClientAttestation.ofOrNull(header)) {
            ClientAuthenticationError.InvalidClientAttestation
        }

        val now = clock.now().dropNanos()
        ensure(now < clientAttestation.claims.expiresAt) {
            ClientAuthenticationError.ExpiredClientAttestation
        }

        if (null != clientAttestation.claims.notBefore) {
            ensure(now >= clientAttestation.claims.notBefore) {
                ClientAuthenticationError.InactiveClientAttestation
            }
        }

        val client = ensureNotNull(session.clients().getClientByClientId(realm, clientAttestation.claims.subject.value)) {
            ClientAuthenticationError.ClientNotFound
        }
        ensure(client.isEnabled) {
            ClientAuthenticationError.InactiveClient
        }

        val config = ClientAuthenticatorConfig(client, authenticatorConfig)
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

        return clientAttestation to client
    }

    private val ClientAuthenticatorConfig.trustValidator: TrustValidator
        get() {
            val trustValidatorServiceUrl = trustValidatorServiceUrl
            return if (null != trustValidatorServiceUrl) TrustValidator(httpClient, trustValidatorServiceUrl) else TrustValidator.Ignored
        }

    private val ClientAuthenticatorConfig.clientStatusValidator: ClientStatusValidator
        get() = ClientStatusValidator(httpClient, clock, 15.seconds) { statusListToken ->
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

    context(_: Raise<ClientAuthenticationError>)
    private suspend fun ClientAuthenticationFlowContext.ensureValidClientAttestationPoP(
        clientAttestation: ClientAttestation,
    ): ClientAttestationPoP {
        val header = ensureNotNull(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)) {
            ClientAuthenticationError.MissingClientAttestationPoP
        }
        val clientAttestationPoP = ensureNotNull(ClientAttestationPoP.ofOrNull(header)) {
            ClientAuthenticationError.InvalidClientAttestationPoP
        }

        val signatureValid = catch({
            clientAttestationPoP.jwt.verify(ECDSAVerifier(clientAttestation.confirmationKey))
        }) { false }
        ensure(signatureValid) {
            ClientAuthenticationError.InvalidClientAttestationPoPSignature
        }

        ensure(clientAttestation.claims.subject == clientAttestationPoP.claims.issuer) {
            ClientAuthenticationError.InvalidClientAttestationPoPIssuer
        }

        ensure(issuer.toString().toNonBlankString() in clientAttestationPoP.claims.audience) {
            ClientAuthenticationError.InvalidClientAttestationPoPAudience
        }

        val now = clock.now().dropNanos()
        ensure(clientAttestationPoP.claims.issuedAt >= now - (2.minutes)) {
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
            ensure(now >= clientAttestationPoP.claims.notBefore) {
                ClientAuthenticationError.InactiveClientAttestationPoP
            }
        }

        return clientAttestationPoP
    }

    private fun ClientAuthenticationFlowContext.failure(clientAuthenticationError: ClientAuthenticationError) {
        val (error, errorDescription) = when (clientAuthenticationError) {
            ClientAuthenticationError.MissingClientAttestation -> Errors.INVALID_REQUEST to "Missing ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER} header"
            ClientAuthenticationError.InvalidClientAttestation -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Not a valid Wallet Instance Attestation"
            ClientAuthenticationError.ExpiredClientAttestation -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Wallet Instance Attestation is expired"
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
            ClientAuthenticationError.InvalidClientAttestationPoPSignature -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The signature of the Client Attestation PoP is not valid"
            ClientAuthenticationError.InvalidClientAttestationPoPIssuer -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The issuer of the Client Attestation PoP is not valid"
            ClientAuthenticationError.InvalidClientAttestationPoPAudience -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "The audience of the Client Attestation PoP is not valid"
            ClientAuthenticationError.StaleClientAttestationPoP -> AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR to "Client Attestation PoP is too old"
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

private fun createHttpClient(): HttpClient = HttpClient(Java) {
    install(ContentNegotiation) {
        json()
    }
}

private sealed interface ClientAuthenticationError {
    data object MissingClientAttestation : ClientAuthenticationError
    data object InvalidClientAttestation : ClientAuthenticationError
    data object ExpiredClientAttestation : ClientAuthenticationError
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
    data object InvalidClientAttestationPoPSignature : ClientAuthenticationError
    data object InvalidClientAttestationPoPIssuer : ClientAuthenticationError
    data object InvalidClientAttestationPoPAudience : ClientAuthenticationError
    data object StaleClientAttestationPoP : ClientAuthenticationError
    data class InvalidClientAttestationPoPChallenge(val useAttestationChallenge: Challenge) : ClientAuthenticationError
    data object InactiveClientAttestationPoP : ClientAuthenticationError
}

private class ClientAuthenticatorConfig(private val client: ClientModel, private val authenticator: AuthenticatorConfigModel?) {

    val trustValidatorServiceUrl: Url?
        get() = get(TRUST_VALIDATOR_SERVICE_URL)?.let { Url.parse(it) }

    operator fun get(name: String): String? = (client.getAttribute(name) ?: authenticator?.config[name])

    companion object {
        const val TRUST_VALIDATOR_SERVICE_URL = "trustValidator.serviceUrl"
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
    override fun create(): ClientAuthenticator = AttestationBasedClientAuthenticator()

    override fun create(session: KeycloakSession): ClientAuthenticator = AttestationBasedClientAuthenticator()

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
        .helpText("URL of the Trust Validator Service to use for checking whether the Client Attestation JWT Issuer is trusted or not.")
        .add()
        .build()

    override fun getConfigPropertiesPerClient(): List<ProviderConfigProperty> = configProperties

    override fun dependsOn(): Set<Class<out Provider>> = setOf(ChallengeHandler::class.java)

    companion object {
        const val ID = "abca-draft07"
    }
}
