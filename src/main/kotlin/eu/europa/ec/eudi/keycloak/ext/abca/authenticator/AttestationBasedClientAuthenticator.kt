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

import arrow.core.raise.*
import com.eygraber.uri.Url
import com.nimbusds.jose.crypto.ECDSAVerifier
import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeHandler
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeValidationError
import eu.europa.ec.eudi.keycloak.ext.abca.toNonBlankString
import eu.europa.ec.eudi.keycloak.ext.abca.tokenstatuslist.verifyStatus
import eu.europa.ec.eudi.keycloak.ext.abca.trust.*
import eu.europa.ec.eudi.keycloak.ext.abca.util.clientStatus
import eu.europa.ec.eudi.keycloak.ext.abca.util.provider
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientAttestation
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientAttestationPoP
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientStatus
import eu.europa.ec.eudi.statium.Status
import io.ktor.client.*
import io.ktor.client.engine.java.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.Response
import kotlinx.coroutines.runBlocking
import org.keycloak.Config
import org.keycloak.authentication.*
import org.keycloak.authentication.authenticators.client.ClientAuthUtil
import org.keycloak.models.*
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import org.keycloak.services.Urls
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

private const val TRUST_VALIDATOR_SERVICE_URL = "serviceUrl"

class AttestationBasedClientAuthenticator(
    private val httpClient: HttpClient = createHttpClient(),
    private val clock: Clock = Clock.System,
) : ClientAuthenticator {
    override fun authenticateClient(context: ClientAuthenticationFlowContext) {
        either {
            val clientAttestationJWT = ensureClientAttestationJWTPresent(context, clock)
            val clientAttestationPoPJWT = ensureClientAttestationPoPJWTPresent(context)

            // If the request form contains client_id, ensure it matches the client attestation jwt subject
            val clientId = ensureClientIdMatch(context, clientAttestationJWT)
            context.event.client(clientId)

            val client = ensureActiveClient(context, clientId)
            context.client = client

            ensureClientAttestationJWTIssuerTrusted(log, context, httpClient, clientAttestationJWT)
            ensureClientAttestationJWTStatusActive(httpClient, clientAttestationJWT)

            val clientStatus = clientAttestationJWT.claims.clientStatus
            ensureClientStatusIsValid(log, httpClient, clientStatus, context)
            context.session.clientStatus = clientStatus

            ensureValidClientAttestationPoPJWT(context, clock, clientAttestationJWT, clientAttestationPoPJWT)
        }.fold(
            ifLeft = {
                log.warn("Failed to authenticate Client using Attestation Based Client Authentication; Reason: ${it.eventError}")
                context.failure(it)
            },
            ifRight = {
                log.info("Successfully authenticated Client ${context.client.clientId} using Attestation Based Client Authentication")
                context.success()
            },
        )
    }

    override fun close() {
        // no-op
    }

    companion object {
        private val log by lazy { LoggerFactory.getLogger(AttestationBasedClientAuthenticator::class.java) }
    }
}

private class ClientAuthenticatorConfiguration(private val client: ClientModel, private val authenticator: AuthenticatorConfigModel?) {

    val trustValidatorServiceUrl: Url?
        get() = get(TRUST_VALIDATOR_SERVICE_URL)
            ?.let { Url.parse(it) }

    operator fun get(name: String): String? = (client.getAttribute(name) ?: authenticator?.config[name])
        ?.takeIf { it.isNotBlank() }
        ?.trim()

    companion object {
        fun fromContext(context: ClientAuthenticationFlowContext): ClientAuthenticatorConfiguration = ClientAuthenticatorConfiguration(context.client, context.authenticatorConfig)
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationJWTPresent(
    context: ClientAuthenticationFlowContext,
    clock: Clock,
): ClientAttestation {
    val header = ensureNotNull(context.httpRequest.httpHeaders[AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER]) {
        ClientAuthenticationFailure.missingClientAttestationJWT()
    }
    val clientAttestation = ensureNotNull(ClientAttestation.ofOrNull(header)) {
        ClientAuthenticationFailure.invalidClientAttestationJWT()
    }

    val now = Instant.fromEpochSeconds(clock.now().epochSeconds, 0L)
    ensure(now < clientAttestation.claims.expiresAt) {
        ClientAuthenticationFailure.invalidClientAttestationJWT()
    }
    if (null != clientAttestation.claims.notBefore) {
        ensure(now >= clientAttestation.claims.notBefore) {
            ClientAuthenticationFailure.invalidClientAttestationJWT()
        }
    }

    return clientAttestation
}

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationPoPJWTPresent(context: ClientAuthenticationFlowContext): ClientAttestationPoP {
    val header = ensureNotNull(context.httpRequest.httpHeaders[AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER]) {
        ClientAuthenticationFailure.missingClientAttestationPoPJWT()
    }
    return ensureNotNull(ClientAttestationPoP.ofOrNull(header)) {
        ClientAuthenticationFailure.invalidClientAttestationPoPJWT()
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientIdMatch(
    context: ClientAuthenticationFlowContext,
    clientAttestation: ClientAttestation,
): String {
    val clientId = context.httpRequest.decodedFormParameters?.getFirst("client_id") ?: clientAttestation.claims.subject.value
    ensure(clientAttestation.claims.subject.value == clientId) {
        ClientAuthenticationFailure.clientIdMismatch()
    }
    return clientId
}

private fun Raise<ClientAuthenticationFailure>.ensureActiveClient(
    context: ClientAuthenticationFlowContext,
    clientId: String,
): ClientModel {
    val client = ensureNotNull(context.session.clients().getClientByClientId(context.realm, clientId)) {
        ClientAuthenticationFailure.clientNotFound()
    }
    ensure(client.isEnabled) {
        ClientAuthenticationFailure.clientDisabled()
    }
    return client
}

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationJWTIssuerTrusted(
    log: Logger,
    context: ClientAuthenticationFlowContext,
    httpClient: HttpClient,
    clientAttestation: ClientAttestation,
) {
    val config = ClientAuthenticatorConfiguration.fromContext(context)
    val isClientAttestationJWTIssuerTrusted =
        config.trustValidatorServiceUrl?.let {
            log.info("Validating Client Attestation JWT Issuer using Trust Validator Service; Service Url: $it")
            IsClientAttestationIssuerTrusted.usingTrustValidatorService(httpClient, it)
        } ?: run {
            log.warn("Trust Validator Service Url not configured; Trusting all Client Attestation JWT Issuers")
            IsClientAttestationIssuerTrusted.Ignored
        }

    val trustResult = runBlocking { isClientAttestationJWTIssuerTrusted(clientAttestation.x5c) }
    ensure(TrustResult.IsTrusted == trustResult) {
        ClientAuthenticationFailure.clientAttestationJWTIssuerNotTrusted()
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationJWTStatusActive(
    httpClient: HttpClient,
    clientAttestation: ClientAttestation,
) {
    val statusListReference = clientAttestation.claims.status
    if (null != statusListReference) {
        val status = runBlocking { statusListReference.verifyStatus(httpClient, IsClientStatusIssuerTrusted.Ignored) }
        ensure(Status.Valid == status) {
            ClientAuthenticationFailure.clientAttestationJWTStatusNotValid()
        }
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientStatusIsValid(
    log: Logger,
    httpClient: HttpClient,
    clientStatus: ClientStatus,
    context: ClientAuthenticationFlowContext,
) {
    val statusListReference = clientStatus.status

    val config = ClientAuthenticatorConfiguration.fromContext(context)
    val trustValidationServiceUrl = config.trustValidatorServiceUrl

    val isClientStatusIssuerTrusted = if (null != trustValidationServiceUrl) {
        log.info("Validating Client Status JWT using Trust Validator Service; Service Url: $trustValidationServiceUrl")
        IsClientStatusIssuerTrusted.usingTrustValidatorService(httpClient, trustValidationServiceUrl)
    } else {
        log.warn("Trust Validator Service Url not configured; Trusting all Client Status JWT")
        IsClientStatusIssuerTrusted.Ignored
    }

    val status = runBlocking { statusListReference.verifyStatus(httpClient, isClientStatusIssuerTrusted) }
    ensure(Status.Valid == status) {
        ClientAuthenticationFailure.clientAttestationJWTInvalidClientStatus()
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureValidClientAttestationPoPJWT(
    context: ClientAuthenticationFlowContext,
    clock: Clock,
    clientAttestation: ClientAttestation,
    clientAttestationPoP: ClientAttestationPoP,
) {
    catch({
        require(clientAttestationPoP.jwt.verify(ECDSAVerifier(clientAttestation.confirmationKey)))
    }) {
        raise(ClientAuthenticationFailure.invalidClientAttestationPoPJWTSignature())
    }

    ensure(context.issuer.toString().toNonBlankString() in clientAttestationPoP.claims.audience) {
        ClientAuthenticationFailure.invalidClientAttestationPoPJWTAudience()
    }

    ensure(clientAttestation.claims.subject == clientAttestationPoP.claims.issuer) {
        ClientAuthenticationFailure.invalidClientAttestationPoPJWTIssuer()
    }

    val now = Instant.fromEpochSeconds(clock.now().epochSeconds, 0L)
    val issuedAtRange = (now - 60.seconds)..(now + 60.seconds)
    ensure(clientAttestationPoP.claims.issuedAt in issuedAtRange) {
        ClientAuthenticationFailure.clientAttestationPoPNotIssuedWithinAcceptableWindow()
    }

    runBlocking {
        val challengeHandler = context.session.provider<ChallengeHandler>()
        val challenge = ensureNotNull(clientAttestationPoP.claims.challenge) {
            ClientAuthenticationFailure.missingClientAttestationPoPJWTChallenge(challengeHandler.generateNew())
        }

        challengeHandler.validate(challenge.value)
            .mapLeft {
                when (it) {
                    is ChallengeValidationError.UseAttestationChallenge -> ClientAuthenticationFailure.invalidClientAttestationPoPJWTChallenge(it)
                }
            }
            .bind()
    }
}

private data class ClientAuthenticationFailure(
    val flowError: AuthenticationFlowError,
    val httpStatus: Response.Status,
    val oauthError: String,
    val message: String,
    val eventError: String,
    val headers: Map<String, String>,
) {
    companion object {
        fun missingClientAttestationJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Missing Client Attestation JWT",
            "missing_client_attestation_jwt",
            emptyMap(),
        )

        fun invalidClientAttestationJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT is not valid",
            "client_attestation_jwt_not_valid",
            emptyMap(),
        )

        fun missingClientAttestationPoPJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Missing Client Attestation PoP JWT",
            "missing_client_attestation_pop_jwt",
            emptyMap(),
        )

        fun invalidClientAttestationPoPJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT is not valid",
            "client_attestation_pop_jwt_not_valid",
            emptyMap(),
        )

        fun clientIdMismatch() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Request client_id does not match Client Attestation JWT subject",
            "client_id_mismatch",
            emptyMap(),
        )

        fun clientNotFound() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client not found",
            "client_not_found",
            emptyMap(),
        )

        fun clientDisabled() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client is disabled",
            "client_disabled",
            emptyMap(),
        )

        fun clientAttestationJWTIssuerNotTrusted() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT Issuer is not trusted",
            "client_attestation_jwt_issuer_not_trusted",
            emptyMap(),
        )

        fun clientAttestationJWTInvalidClientStatus() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT Client Status is invalid",
            "client_attestation_jwt_client_status_invalid",
            emptyMap(),
        )

        fun clientAttestationJWTStatusNotValid() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT Status is not Valid",
            "client_attestation_jwt_status_not_valid",
            emptyMap(),
        )

        fun invalidClientAttestationPoPJWTSignature() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT signature is not valid",
            "client_attestation_pop_jwt_signature_not_valid",
            emptyMap(),
        )

        fun invalidClientAttestationPoPJWTAudience() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT audience is not valid",
            "client_attestation_pop_jwt_audience_not_valid",
            emptyMap(),
        )

        fun invalidClientAttestationPoPJWTIssuer() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT Issuer is not valid",
            "client_attestation_pop_jwt_issuer_not_valid",
            emptyMap(),
        )

        fun clientAttestationPoPNotIssuedWithinAcceptableWindow() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT not issued within an acceptable window",
            "client_attestation_pop_jwt_not_issued_within_acceptable_window",
            emptyMap(),
        )

        fun missingClientAttestationPoPJWTChallenge(challenge: Challenge) = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.USE_ATTESTATION_CHALLENGE_ERROR,
            "Client Attestation PoP JWT is missing Challenge",
            "client_attestation_pop_jwt_missing_challenge",
            mapOf(
                AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER to challenge.value,
            ),
        )

        fun invalidClientAttestationPoPJWTChallenge(error: ChallengeValidationError.UseAttestationChallenge) = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.USE_ATTESTATION_CHALLENGE_ERROR,
            "Client Attestation PoP JWT Challenge is not valid",
            "client_attestation_pop_jwt_challenge_not_valid",
            mapOf(
                AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER to error.challenge.value,
            ),
        )
    }
}

private fun ClientAuthenticationFlowContext.failure(authenticationFailure: ClientAuthenticationFailure) {
    val response = Response.fromResponse(
        ClientAuthUtil.errorResponse(
            authenticationFailure.httpStatus.statusCode,
            authenticationFailure.oauthError,
            authenticationFailure.message,
        ),
    ).apply {
        authenticationFailure.headers.forEach { (name, value) -> header(name, value) }
    }
        .build()

    event.error(authenticationFailure.eventError)
    failure(authenticationFailure.flowError, response)
}

private operator fun HttpHeaders.get(name: String): String? = getHeaderString(name)?.takeIf { it.isNotBlank() }?.trim()

private fun createHttpClient(): HttpClient = HttpClient(Java) {
    install(ContentNegotiation) {
        json()
    }
}

private val ClientAuthenticationFlowContext.issuer: Url
    get() = Url.parse(Urls.realmIssuer(session.context.uri.baseUri, session.context.realm.name))

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
        .name(TRUST_VALIDATOR_SERVICE_URL)
        .type(ProviderConfigProperty.URL_TYPE)
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
