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
package eu.europa.ec.eudi.keycloak.ext.abca.auth

import arrow.autoCloseScope
import arrow.core.raise.*
import arrow.core.toNonEmptyListOrNull
import com.nimbusds.jose.util.X509CertUtils
import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import eu.europa.ec.eudi.keycloak.ext.abca.RFC9449
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.trust.Ignored
import eu.europa.ec.eudi.keycloak.ext.abca.trust.IsClientAttestationIssuerTrusted
import eu.europa.ec.eudi.keycloak.ext.abca.trust.IsClientStatusIssuerTrusted
import eu.europa.ec.eudi.keycloak.ext.abca.trust.TrustResult
import eu.europa.ec.eudi.keycloak.ext.abca.trust.usingTrustValidatorService
import eu.europa.ec.eudi.statium.Status
import io.ktor.client.*
import io.ktor.client.engine.okhttp.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.Response
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.ClientAuthenticationFlowContext
import org.keycloak.authentication.authenticators.client.AbstractClientAuthenticator
import org.keycloak.authentication.authenticators.client.ClientAuthUtil
import org.keycloak.models.AuthenticationExecutionModel
import org.keycloak.models.AuthenticatorConfigModel
import org.keycloak.models.ClientModel
import org.keycloak.protocol.oauth2.OAuth2WellKnownProviderFactory
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigProperty.STRING_TYPE
import org.keycloak.provider.ProviderConfigurationBuilder
import org.keycloak.wellknown.WellKnownProvider
import org.slf4j.LoggerFactory

private const val TrustValidatorServiceUrl = "serviceUrl"

private val ConfigurationProperties =
    ProviderConfigurationBuilder.create()
        .property()
        .name(TrustValidatorServiceUrl)
        .type(STRING_TYPE)
        .defaultValue(null)
        .label("Trust Validator Service URL")
        .helpText("URL of the Trust Validator Service to use for checking whether the Client Attestation JWT Issuer is trusted or not.")
        .add()
        .build()

private const val Id = "abca-draft07"

private val log = LoggerFactory.getLogger(AttestationBasedClientAuthenticatorFactory::class.java)

class AttestationBasedClientAuthenticatorFactory(private val httpClient: HttpClient) : AbstractClientAuthenticator() {

    constructor() : this(createHttpClient())

    init {
        log.info("Initializing AttestationBasedClientAuthenticatorFactory...")
    }

    override fun getId(): String = Id

    override fun getDisplayType(): String = "Attestation-Based Client Authentication"

    override fun getHelpText(): String =
        "Authenticates OAuth Clients using a Client Attestation JWT, and a Client Attestation PoP JWT bound to a server-issued challenge."

    override fun isConfigurable(): Boolean = true

    override fun getConfigPropertiesPerClient(): List<ProviderConfigProperty> = ConfigurationProperties

    override fun getConfigProperties(): List<ProviderConfigProperty> = ConfigurationProperties

    override fun getAdapterConfiguration(client: ClientModel): Map<String, Any> = mapOf()

    override fun getProtocolAuthenticatorMethods(loginProtocol: String): Set<String> =
        when (loginProtocol) {
            OIDCLoginProtocol.LOGIN_PROTOCOL -> setOf(AttestationBasedClientAuthentication.AUTHENTICATION_METHOD)
            else -> emptySet()
        }

    override fun getRequirementChoices(): Array<AuthenticationExecutionModel.Requirement> = REQUIREMENT_CHOICES

    override fun authenticateClient(context: ClientAuthenticationFlowContext) = doAuthenticate(context, httpClient)
}

private class Config(private val client: ClientModel, private val authenticator: AuthenticatorConfigModel?) {

    val trustValidatorServiceUrl: Url?
        get() = get(TrustValidatorServiceUrl)
            ?.let { Url(it) }

    operator fun get(name: String): String? =
        (client.getAttribute(name) ?: authenticator?.config[name])
            ?.takeIf { it.isNotBlank() }
            ?.trim()

    companion object {
        fun fromContext(context: ClientAuthenticationFlowContext): Config = Config(context.client, context.authenticatorConfig)
    }
}

private fun doAuthenticate(context: ClientAuthenticationFlowContext, httpClient: HttpClient) {
    either {
        val clientAttestationJWT = ensureClientAttestationJWTPresent(context)

        val clientAttestationPoPJWT = ensureClientAttestationPoPJWTPresent(context)
        val dPoPProofJWT = ensureDPoPProofJWTPresent(context)

        // If the request form contains client_id, ensure it matches the client attestation jwt subject
        val clientId = ensureClientIdMatch(context, clientAttestationJWT)
        context.event.client(clientId)

        val client = ensureActiveClient(context, clientId)
        context.client = client

        ensureClientAttestationJWTIssuerTrusted(context, httpClient, clientAttestationJWT)
        ensureClientAttestationJWTStatusActive(httpClient, clientAttestationJWT)

        val clientStatus = clientAttestationJWT.clientStatus
        ensureClientStatusIsValid(httpClient, clientStatus, context)
        context.clientAuthAttributes[TS3.EUDI_CLIENT_STATUS_CLAIM] = Json.encodeToString(clientStatus)

        ensureValidClientAttestationPoPJWT(context, clientAttestationJWT, clientAttestationPoPJWT)
        ensureValidDPoPProofJWT(clientAttestationJWT, dPoPProofJWT)
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

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationJWTPresent(context: ClientAuthenticationFlowContext): ClientAttestationJWT {
    val header = ensureNotNull(context.httpRequest.httpHeaders[AttestationBasedClientAuthentication.HEADER_CLIENT_ATTESTATION]) {
        ClientAuthenticationFailure.missingClientAttestationJWT()
    }
    return ensureNotNull(ClientAttestationJWT(header).getOrNull()) {
        ClientAuthenticationFailure.invalidClientAttestationJWT()
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationPoPJWTPresent(context: ClientAuthenticationFlowContext): ClientAttestationPoPJWT {
    val header = ensureNotNull(context.httpRequest.httpHeaders[AttestationBasedClientAuthentication.HEADER_CLIENT_ATTESTATION_POP]) {
        ClientAuthenticationFailure.missingClientAttestationPoPJWT()
    }
    return ensureNotNull(ClientAttestationPoPJWT(header).getOrNull()) {
        ClientAuthenticationFailure.invalidClientAttestationPoPJWT()
    }
}
private fun Raise<ClientAuthenticationFailure>.ensureDPoPProofJWTPresent(context: ClientAuthenticationFlowContext): DPoPProofJWT {
    val header = ensureNotNull(context.httpRequest.httpHeaders[RFC9449.HEADER_DPOP]) {
        ClientAuthenticationFailure.missingDPoPProofJWT()
    }
    return ensureNotNull(DPoPProofJWT(header).getOrNull()) {
        ClientAuthenticationFailure.invalidDPoPProofJWT()
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientIdMatch(
    context: ClientAuthenticationFlowContext,
    clientAttestationJWT: ClientAttestationJWT,
): String {
    val clientId = context.httpRequest.decodedFormParameters?.getFirst("client_id") ?: clientAttestationJWT.subject
    ensure(clientAttestationJWT.subject == clientId) {
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
    context: ClientAuthenticationFlowContext,
    httpClient: HttpClient,
    clientAttestationJWT: ClientAttestationJWT,
) {
    val x5c = run {
        val decoded = clientAttestationJWT.jwt
            .header
            .x509CertChain
            .orEmpty()
            .map { requireNotNull(X509CertUtils.parse(it.decode())) }
        ensureNotNull(decoded.toNonEmptyListOrNull()) {
            ClientAuthenticationFailure.clientAttestationJWTMissingX5C()
        }
    }

    val config = Config.fromContext(context)
    val isClientAttestationJWTIssuerTrusted =
        config.trustValidatorServiceUrl?.let {
            log.info("Validating Client Attestation JWT Issuer using Trust Validator Service; Service Url: $it")
            IsClientAttestationIssuerTrusted.usingTrustValidatorService(httpClient, it)
        } ?: run {
            log.warn("Trust Validator Service Url not configured; Trusting all Client Attestation JWT Issuers")
            IsClientAttestationIssuerTrusted.Ignored
        }

    val trustResult = runBlocking { isClientAttestationJWTIssuerTrusted(x5c) }
    ensure(TrustResult.IsTrusted == trustResult) {
        ClientAuthenticationFailure.clientAttestationJWTIssuerNotTrusted()
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientAttestationJWTStatusActive(
    httpClient: HttpClient,
    clientAttestationJWT: ClientAttestationJWT,
) {
    val statusListReference = clientAttestationJWT.status
    if (null != statusListReference) {
        val status = runBlocking { statusListReference.verifyStatus(httpClient, IsClientStatusIssuerTrusted.Ignored) }
        ensure(Status.Valid == status) {
            ClientAuthenticationFailure.clientAttestationJWTStatusNotValid()
        }
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureClientStatusIsValid(
    httpClient: HttpClient,
    clientStatus: ClientStatus,
    context: ClientAuthenticationFlowContext,
) {
    val statusListReference = clientStatus.status

    val config = Config.fromContext(context)
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
    clientAttestationJWT: ClientAttestationJWT,
    clientAttestationPoPJWT: ClientAttestationPoPJWT,
) {
    catch({
        clientAttestationPoPJWT.verifyPop(clientAttestationJWT)
    }) {
        raise(ClientAuthenticationFailure.invalidClientAttestationPoPJWTSignature())
    }

    ensure(context.issuer in clientAttestationPoPJWT.audience) {
        ClientAuthenticationFailure.invalidClientAttestationPoPJWTAudience()
    }

    ensure(clientAttestationJWT.subject == clientAttestationPoPJWT.issuer) {
        ClientAuthenticationFailure.invalidClientAttestationPoPJWTIssuer()
    }

    val challenge = ensureNotNull(clientAttestationPoPJWT.challenge) {
        ClientAuthenticationFailure.missingClientAttestationPoPJWTChallenge()
    }
    catch({ challenge.verify(context.session) }) {
        raise(ClientAuthenticationFailure.invalidClientAttestationPoPJWTChallenge())
    }
}

private fun Raise<ClientAuthenticationFailure>.ensureValidDPoPProofJWT(
    clientAttestationJWT: ClientAttestationJWT,
    dPoPProofJWT: DPoPProofJWT,
) = ensure(clientAttestationJWT.jwk == dPoPProofJWT.jwk) {
    raise(ClientAuthenticationFailure.invalidDPoPProofJWTSignature())
}

private data class ClientAuthenticationFailure(
    val flowError: AuthenticationFlowError,
    val httpStatus: Response.Status,
    val oauthError: String,
    val message: String,
    val eventError: String,
) {
    companion object {
        fun missingClientAttestationJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Missing Client Attestation JWT",
            "missing_client_attestation_jwt",
        )

        fun invalidClientAttestationJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT is not valid",
            "client_attestation_jwt_not_valid",
        )

        fun missingClientAttestationPoPJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Missing Client Attestation PoP JWT",
            "missing_client_attestation_pop_jwt",
        )

        fun invalidClientAttestationPoPJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT is not valid",
            "client_attestation_pop_jwt_not_valid",
        )

        fun clientIdMismatch() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Request client_id does not match Client Attestation JWT subject",
            "client_id_mismatch",
        )

        fun clientNotFound() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client not found",
            "client_not_found",
        )

        fun clientDisabled() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client is disabled",
            "client_disabled",
        )

        fun clientAttestationJWTMissingX5C() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT is missing 'x5c'",
            "client_attestation_jwt_missing_x5c",
        )

        fun clientAttestationJWTIssuerNotTrusted() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT Issuer is not trusted",
            "client_attestation_jwt_issuer_not_trusted",
        )

        fun clientAttestationJWTInvalidClientStatus() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT Client Status is invalid",
            "client_attestation_jwt_client_status_invalid",
        )

        fun clientAttestationJWTStatusNotValid() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation JWT Status is not Valid",
            "client_attestation_jwt_status_not_valid",
        )

        fun invalidClientAttestationPoPJWTSignature() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT signature is not valid",
            "client_attestation_pop_jwt_signature_not_valid",
        )

        fun invalidClientAttestationPoPJWTAudience() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT audience is not valid",
            "client_attestation_pop_jwt_audience_not_valid",
        )

        fun invalidClientAttestationPoPJWTIssuer() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT Issuer is not valid",
            "client_attestation_pop_jwt_issuer_not_valid",
        )

        fun missingClientAttestationPoPJWTChallenge() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT is missing Challenge",
            "client_attestation_pop_jwt_missing_challenge",
        )

        fun invalidClientAttestationPoPJWTChallenge() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP JWT Challenge is not valid",
            "client_attestation_pop_jwt_challenge_not_valid",
        )

        fun missingDPoPProofJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Missing DPoP Proof JWT",
            "missing_dpop_proof_jwt",
        )

        fun invalidDPoPProofJWT() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "DPoP Proof JWT is not valid",
            "dpop_proof_jwt_not_valid",
        )

        fun invalidDPoPProofJWTSignature() = ClientAuthenticationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "DPoP Proof JWT signature is not valid",
            "dpop_proof_jwt_signature_not_valid",
        )
    }
}

private fun ClientAuthenticationFlowContext.failure(authenticationFailure: ClientAuthenticationFailure) {
    event.error(authenticationFailure.eventError)
    failure(
        authenticationFailure.flowError,
        ClientAuthUtil.errorResponse(
            authenticationFailure.httpStatus.statusCode,
            authenticationFailure.oauthError,
            authenticationFailure.message,
        ),
    )
}

private operator fun HttpHeaders.get(name: String): String? =
    getHeaderString(name)?.takeIf { it.isNotBlank() }?.trim()

private fun createHttpClient(): HttpClient =
    HttpClient(OkHttp) {
        install(ContentNegotiation) {
            json()
        }
    }

private val ClientAuthenticationFlowContext.issuer: String
    get() = autoCloseScope {
        val provider = autoClose({ session.getProvider(WellKnownProvider::class.java, OAuth2WellKnownProviderFactory.PROVIDER_ID) }) { provider, _ -> provider.close() }
        val config = provider.config as Map<*, *>
        config["issuer"] as String
    }
