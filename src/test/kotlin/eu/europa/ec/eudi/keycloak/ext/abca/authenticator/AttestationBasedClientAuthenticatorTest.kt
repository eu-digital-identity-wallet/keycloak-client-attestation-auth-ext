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

import arrow.core.NonEmptyList
import arrow.core.nonEmptyListOf
import arrow.core.raise.context.Raise
import arrow.core.raise.context.raise
import com.eygraber.uri.Uri
import com.eygraber.uri.Url
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.keycloak.ext.abca.*
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeHandler
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.UseAttestationChallenge
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.toChallenge
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.Audience
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.AudienceSerializer
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.InstantEpochSecondsSerializer
import eu.europa.ec.eudi.keycloak.ext.abca.tokenstatuslist.Status
import eu.europa.ec.eudi.keycloak.ext.abca.tokenstatuslist.StatusList
import eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator.VerificationContext
import eu.europa.ec.eudi.keycloak.ext.abca.util.dropNanos
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientStatus
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.Confirmation
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.mockk.*
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.MultivaluedMap
import jakarta.ws.rs.core.Response
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.*
import kotlinx.serialization.json.io.decodeFromSource
import org.junit.jupiter.api.BeforeEach
import org.keycloak.OAuth2Constants
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.ClientAuthenticationFlowContext
import org.keycloak.events.Errors
import org.keycloak.events.EventBuilder
import org.keycloak.http.HttpRequest
import org.keycloak.models.*
import org.keycloak.representations.idm.OAuth2ErrorRepresentation
import java.net.URI
import java.security.cert.X509Certificate
import kotlin.test.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Instant
import kotlin.uuid.Uuid
import io.ktor.http.HttpHeaders as KtorHttpHeaders

class AttestationBasedClientAuthenticatorTest {
    private val clock = Clock.System

    private val walletProviderCertificate = X509CertUtils.parseWithException(loadResource("wallet-provider.pem"))
    private val walletProviderKey = ECKey.parse(loadResource("wallet-provider.jwk"))

    private val context = mockk<ClientAuthenticationFlowContext>()
    private val httpRequest = mockk<HttpRequest>()
    private val httpHeaders = mockk<HttpHeaders>()
    private val session = mockk<KeycloakSession>()
    private val clients = mockk<ClientProvider>()
    private val realm = mockk<RealmModel>()
    private val keycloakContext = mockk<KeycloakContext>()
    private val uriInfo = mockk<KeycloakUriInfo>()
    private val formParameters = mockk<MultivaluedMap<String, String>>()
    private val event = mockk<EventBuilder>()

    @BeforeEach
    fun setup() {
        every { context.httpRequest } returns httpRequest
        every { httpRequest.httpHeaders } returns httpHeaders
        every { httpHeaders.mediaType } returns MediaType.APPLICATION_FORM_URLENCODED_TYPE
        every { context.session } returns session
        every { session.clients() } returns clients
        every { context.realm } returns realm
        every { realm.isEnabled } returns true
        every { realm.name } returns "pid-issuer-realm"
        every { context.authenticatorConfig } returns null
        every { session.context } returns keycloakContext
        every { keycloakContext.uri } returns uriInfo
        every { uriInfo.baseUri } returns URI.create("https://localhost/idp")
        every { httpRequest.decodedFormParameters } returns formParameters
        justRun { context.client = any(ClientModel::class) }
        every { context.event } returns event
        every { event.client(any(ClientModel::class)) } returns event
        justRun { session.setAttribute(TS3.CLIENT_STATUS_CLAIM, any(ClientStatus::class)) }
        justRun { context.success() }
        justRun { context.failure(any(AuthenticationFlowError::class), any(Response::class)) }
    }

    @Test
    fun `verify successful authentication`() = runTest {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val challenge = Uuid.generateV7().toString().toChallenge()
        val clientAttestationPoP = clientAttestationPoP(
            challenge = challenge,
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        every { httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER) } returns clientAttestation.serialize()
        every { httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER) } returns clientAttestationPoP.serialize()

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val challengeHandler = ChallengeHandler(challenge)
        every { session.getProvider(ChallengeHandler::class.java) } returns challengeHandler

        val authenticator = AttestationBasedClientAuthenticator(httpClient, clock)
        authenticator.authenticateClient(context)

        verify(inverse = true) { context.failure(any(AuthenticationFlowError::class), any(Response::class)) }
        verify { context.client = client }
        verify { event.client(client) }
        verify { session.setAttribute(TS3.CLIENT_STATUS_CLAIM, clientStatus) }
        verify { context.success() }
    }

    @Test
    fun `authentication fails when client attestation is missing`() {
        testExpectingFailure(
            null,
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Errors.INVALID_REQUEST,
            "Missing ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER} header",
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    private fun testExpectingFailure(
        clientAttestation: String?,
        clientAttestationPoP: String?,
        authenticationFlowError: AuthenticationFlowError,
        error: String,
        errorDescription: String,
        httpClient: HttpClient = HttpClient(),
        assertions: (Response) -> Unit = {},
    ) = runTest {
        every { httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER) } returns clientAttestation
        every { httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER) } returns clientAttestationPoP

        val authenticator = AttestationBasedClientAuthenticator(httpClient, clock)
        authenticator.authenticateClient(context)

        verify(inverse = true) { context.success() }
        verify { context.client = null }
        verify { event.client(null as ClientModel?) }
        verify { session.setAttribute(TS3.CLIENT_STATUS_CLAIM, null) }

        val response = slot<Response>()
        verify { context.failure(authenticationFlowError, capture(response)) }
        assertTrue { response.isCaptured }
        with(response.captured) {
            assertEquals(Response.Status.BAD_REQUEST.statusCode, status)
            val oauth2Error = assertIs<OAuth2ErrorRepresentation>(entity)
            assertEquals(error, oauth2Error.error)
            assertEquals(errorDescription, oauth2Error.errorDescription)
            assertions(this)
        }
    }

    @Test
    fun `authentication fails when client attestation is invalid`() {
        testExpectingFailure(
            Uuid.generateV7().toString(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Not a valid Wallet Instance Attestation",
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation is expired`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            expiresAt = clock.now().dropNanos() - 31.days,
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Wallet Instance Attestation is expired",
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation is not active`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            notBefore = clock.now().dropNanos() + 5.minutes,
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Wallet Instance Attestation is not active",
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client is not found`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        every { clients.getClientByClientId(realm, "eudiw") } returns null

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.CLIENT_NOT_FOUND,
            Errors.INVALID_CLIENT,
            "Client not found",
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client is not active`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val client = client(enabled = false)
        every { clients.getClientByClientId(realm, "eudiw") } returns client

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.CLIENT_DISABLED,
            Errors.INVALID_CLIENT,
            "Client is not active",
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation issuer is not trusted`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, false),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The issuer of the Wallet Instance Attestation is not trusted",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client status issuer is not trusted`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, false),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The issuer of the Client Status of the Wallet Instance Attestation is not trusted",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client status is not valid`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus(index = 8192u)
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The Client Status of the Wallet Instance Attestation is not Valid",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when a public client is missing client_id`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns null

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Errors.INVALID_REQUEST,
            "${OAuth2Constants.CLIENT_ID} form parameter is required for public clients",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails client_id mismatch`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns Uuid.generateV7().toString()

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Errors.INVALID_REQUEST,
            "${OAuth2Constants.CLIENT_ID} form parameter does not match the subject of Wallet Instance Attestation",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop is missing`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        testExpectingFailure(
            clientAttestation.serialize(),
            null,
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Errors.INVALID_REQUEST,
            "Missing ${AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER} header",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop is invalid`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        testExpectingFailure(
            clientAttestation.serialize(),
            Uuid.generateV7().toString(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Not a valid Client Attestation PoP",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop signature is invalid`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val clientAttestationPoPSigningKey = ECKeyGenerator(Curve.P_256).generate()
        val clientAttestationPoP = clientAttestationPoP(
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(clientAttestationPoPSigningKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The signature of the Client Attestation PoP is not valid",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop issuer is invalid`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val clientAttestationPoP = clientAttestationPoP(
            issuer = Uuid.generateV7().toString().toNonBlankString(),
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The issuer of the Client Attestation PoP is not valid",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop audience is invalid`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val clientAttestationPoP = clientAttestationPoP(
            audience = nonEmptyListOf(Uuid.generateV7().toString().toNonBlankString()),
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The audience of the Client Attestation PoP is not valid",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop is stale`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val clientAttestationPoP = clientAttestationPoP(
            issuedAt = clock.now().dropNanos() - 5.minutes,
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client Attestation PoP is too old",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    @Test
    fun `authentication fails when client attestation pop does not contain challenge`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val clientAttestationPoP = clientAttestationPoP(
            challenge = null,
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        val useAttestationChallenge = Uuid.generateV7().toString().toChallenge()
        val challengeHandler = ChallengeHandler(validChallenge = null, newChallenge = useAttestationChallenge)
        every { session.getProvider(ChallengeHandler::class.java) } returns challengeHandler

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.USE_ATTESTATION_CHALLENGE_ERROR,
            "The Client Attestation PoP does not contain a valid Challenge",
            httpClient,
        ) {
            assertTrue { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
            assertEquals(useAttestationChallenge.value, it.headers.getFirst(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER))
        }
    }

    @Test
    fun `authentication fails when client attestation pop contains an invalid challenge`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val challenge = Uuid.generateV7().toString().toChallenge()
        val clientAttestationPoP = clientAttestationPoP(
            challenge = challenge,
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        val useAttestationChallenge = Uuid.generateV7().toString().toChallenge()
        check(challenge != useAttestationChallenge)
        val challengeHandler = ChallengeHandler(validChallenge = null, newChallenge = useAttestationChallenge)
        every { session.getProvider(ChallengeHandler::class.java) } returns challengeHandler

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.USE_ATTESTATION_CHALLENGE_ERROR,
            "The Client Attestation PoP does not contain a valid Challenge",
            httpClient,
        ) {
            assertTrue { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
            assertEquals(useAttestationChallenge.value, it.headers.getFirst(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER))
        }
    }

    @Test
    fun `authentication fails when client attestation pop is not active`() {
        val walletInstanceKey = ECKeyGenerator(Curve.P_256).generate()
        val clientStatus = clientStatus()
        val clientAttestation = clientAttestation(
            confirmation = Confirmation.of(walletInstanceKey.toPublicJWK()),
            clientStatus = clientStatus,
            algorithm = JWSAlgorithm.ES256,
            x5c = nonEmptyListOf(walletProviderCertificate),
            signer = ECDSASigner(walletProviderKey),
        )
        val challenge = Uuid.generateV7().toString().toChallenge()
        val clientAttestationPoP = clientAttestationPoP(
            challenge = challenge,
            notBefore = clock.now().dropNanos() + 5.minutes,
            algorithm = JWSAlgorithm.ES256,
            signer = ECDSASigner(walletInstanceKey),
        )

        val httpClient = HttpClient(
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_INSTANCE_ATTESTATION, true),
            statusListTokenRequestHandler(),
            trustValidatorServiceRequestHandler(VerificationContext.WALLET_OR_KEY_STORAGE_STATUS, true),
        )

        val client = client()
        every { clients.getClientByClientId(realm, "eudiw") } returns client
        every { formParameters.getFirst(OAuth2Constants.CLIENT_ID) } returns "eudiw"

        val useAttestationChallenge = Uuid.generateV7().toString().toChallenge()
        check(challenge != useAttestationChallenge)
        val challengeHandler = ChallengeHandler(validChallenge = challenge, newChallenge = useAttestationChallenge)
        every { session.getProvider(ChallengeHandler::class.java) } returns challengeHandler

        testExpectingFailure(
            clientAttestation.serialize(),
            clientAttestationPoP.serialize(),
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            AttestationBasedClientAuthentication.INVALID_CLIENT_ATTESTATION_ERROR,
            "The Client Attestation PoP is not active",
            httpClient,
        ) {
            assertFalse { AttestationBasedClientAuthentication.CLIENT_ATTESTATION_CHALLENGE_HEADER in it.headers }
        }
    }

    private fun clientAttestation(
        issuer: NonBlankString? = "Wallet Provider".toNonBlankString(),
        subject: NonBlankString? = "eudiw".toNonBlankString(),
        expiresAt: Instant? = clock.now().dropNanos() + 31.days,
        confirmation: Confirmation? = null,
        issuedAt: Instant? = clock.now().dropNanos(),
        notBefore: Instant? = clock.now().dropNanos(),
        walletName: NonBlankString? = "EUDI Wallet".toNonBlankString(),
        walletLink: Url? = Url.parse("https://eudiw.dev"),
        status: Status? = null,
        walletVersion: NonBlankString? = "1.0.0".toNonBlankString(),
        walletSolutionCertificationInformation: JsonElement? = JsonPrimitive("https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework"),
        clientStatus: ClientStatus? = null,
        algorithm: JWSAlgorithm,
        type: JOSEObjectType? = JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_JWT_TYPE),
        x5c: NonEmptyList<X509Certificate>? = null,
        signer: JWSSigner,
    ): SignedJWT = SignedJWT(
        JWSHeader.Builder(algorithm)
            .apply {
                type?.let { type(it) }
                x5c?.let { x509CertChain(it.map { certificate -> Base64.encode(certificate.encoded) }) }
            }.build(),
        WalletInstanceAttestationClaimsBuilder()
            .apply {
                this.issuer = issuer
                this.subject = subject
                this.expiresAt = expiresAt
                this.confirmation = confirmation
                this.issuedAt = issuedAt
                this.notBefore = notBefore
                this.walletName = walletName
                this.walletLink = walletLink
                this.status = status
                this.walletVersion = walletVersion
                this.walletSolutionCertificationInformation = walletSolutionCertificationInformation
                this.clientStatus = clientStatus
            }.build(),
    ).apply {
        sign(signer)
    }

    private fun clientStatus(
        index: UInt = 0u,
        uri: Uri = Uri.parse("https://issuer.eudiw.dev/token_status_list/FC/key-attestation+jwt/abb5121d-a8bb-440e-bf8f-13bf9de27787"),
    ): ClientStatus = ClientStatus(
        Status(
            StatusList(index, uri),
        ),
        clock.now().dropNanos() + 31.days,
    )

    private fun clientAttestationPoP(
        issuer: NonBlankString? = "eudiw".toNonBlankString(),
        audience: Audience? = nonEmptyListOf("https://localhost/idp/realms/pid-issuer-realm".toNonBlankString()),
        jwtId: NonBlankString? = Uuid.generateV7().toString().toNonBlankString(),
        issuedAt: Instant? = clock.now().dropNanos(),
        challenge: Challenge? = null,
        notBefore: Instant? = clock.now().dropNanos(),
        algorithm: JWSAlgorithm,
        type: JOSEObjectType? = JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_JWT_TYPE),
        signer: JWSSigner,
    ): SignedJWT = SignedJWT(
        JWSHeader.Builder(algorithm)
            .apply {
                type?.let { type(it) }
            }.build(),
        ClientAttestationPoPClaimBuilder()
            .apply {
                this.issuer = issuer
                this.audience = audience
                this.jwtId = jwtId
                this.issuedAt = issuedAt
                this.challenge = challenge
                this.notBefore = notBefore
            }.build(),
    ).apply {
        sign(signer)
    }
}

private fun loadResource(name: String): String = checkNotNull(AttestationBasedClientAuthenticatorTest::class.java.classLoader.getResource(name)).readText()

private class WalletInstanceAttestationClaimsBuilder {
    var issuer: NonBlankString? = null
    var subject: NonBlankString? = null
    var expiresAt: Instant? = null
    var confirmation: Confirmation? = null
    var issuedAt: Instant? = null
    var notBefore: Instant? = null
    var walletName: NonBlankString? = null
    var walletLink: Url? = null
    var status: Status? = null
    var walletVersion: NonBlankString? = null
    var walletSolutionCertificationInformation: JsonElement? = null
    var clientStatus: ClientStatus? = null

    fun build(): JWTClaimsSet {
        val payload = buildJsonObject {
            issuer?.let { put(RFC7519.ISSUER_CLAIM, Json.encodeToJsonElement(it)) }
            subject?.let { put(RFC7519.SUBJECT_CLAIM, Json.encodeToJsonElement(it)) }
            expiresAt?.let { put(RFC7519.EXPIRES_AT_CLAIM, Json.encodeToJsonElement(InstantEpochSecondsSerializer, it)) }
            confirmation?.let { put(RFC7800.CONFIRMATION_CLAIM, Json.encodeToJsonElement(it)) }
            issuedAt?.let { put(RFC7519.ISSUED_AT_CLAIM, Json.encodeToJsonElement(InstantEpochSecondsSerializer, it)) }
            notBefore?.let { put(RFC7519.NOT_BEFORE_CLAIM, Json.encodeToJsonElement(InstantEpochSecondsSerializer, it)) }
            walletName?.let { put(OpenId4VCI.WALLET_NAME_CLAIM, Json.encodeToJsonElement(it)) }
            walletLink?.let { put(OpenId4VCI.WALLET_LINK_CLAIM, Json.encodeToJsonElement(it)) }
            status?.let { put(TokenStatusList.STATUS_CLAIM, Json.encodeToJsonElement(it)) }
            walletVersion?.let { put(TS3.WALLET_VERSION_CLAIM, Json.encodeToJsonElement(it)) }
            walletSolutionCertificationInformation?.let { put(TS3.WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM, it) }
            clientStatus?.let { put(TS3.CLIENT_STATUS_CLAIM, Json.encodeToJsonElement(it)) }
        }
        return JWTClaimsSet.parse(Json.encodeToString(payload))
    }
}

private class ClientAttestationPoPClaimBuilder {
    var issuer: NonBlankString? = null
    var audience: NonEmptyList<NonBlankString>? = null
    var jwtId: NonBlankString? = null
    var issuedAt: Instant? = null
    var challenge: Challenge? = null
    var notBefore: Instant? = null

    fun build(): JWTClaimsSet {
        val payload = buildJsonObject {
            issuer?.let { put(RFC7519.ISSUER_CLAIM, Json.encodeToJsonElement(it)) }
            audience?.let { put(RFC7519.AUDIENCE_CLAIM, Json.encodeToJsonElement(AudienceSerializer, it)) }
            jwtId?.let { put(RFC7519.JWT_ID_CLAIM, Json.encodeToJsonElement(it)) }
            issuedAt?.let { put(RFC7519.ISSUED_AT_CLAIM, Json.encodeToJsonElement(InstantEpochSecondsSerializer, it)) }
            challenge?.let { put(AttestationBasedClientAuthentication.CHALLENGE_CLAIM, Json.encodeToJsonElement(it)) }
            notBefore?.let { put(RFC7519.NOT_BEFORE_CLAIM, Json.encodeToJsonElement(InstantEpochSecondsSerializer, it)) }
        }
        return JWTClaimsSet.parse(Json.encodeToString(payload))
    }
}

private fun client(
    clientId: String = "eudiw",
    enabled: Boolean = true,
    public: Boolean = true,
    trustValidatorServiceUrl: Url? = Url.parse("https://dev.trust-validator.eudiw.dev/trust"),
): ClientModel {
    val client = mockk<ClientModel>()
    every { client.clientId } returns clientId
    every { client.isEnabled } returns enabled
    every { client.isPublicClient } returns public
    every { client.getAttribute("trustValidator.serviceUrl") } returns trustValidatorServiceUrl?.toString()
    return client
}

private fun ChallengeHandler(
    validChallenge: Challenge? = null,
    newChallenge: Challenge = Uuid.generateV7().toString().toChallenge(),
): ChallengeHandler = object : ChallengeHandler {
    override suspend fun generateNew(): Challenge = newChallenge

    context(_: Raise<UseAttestationChallenge>)
    override suspend fun validate(value: String): Challenge = if (validChallenge?.value == value) {
        validChallenge
    } else {
        raise(UseAttestationChallenge(generateNew()))
    }
}

private fun HttpClient(vararg handlers: MockRequestHandler): HttpClient = HttpClient(MockEngine) {
    engine {
        handlers.forEach { addHandler(it) }
        addHandler {
            fail("Unexpected HTTP call: $it")
        }
        reuseHandlers = false
    }

    install(ContentNegotiation) {
        json()
    }
}

private fun trustValidatorServiceRequestHandler(
    verificationContext: VerificationContext,
    trusted: Boolean,
    url: Url = Url.parse("https://dev.trust-validator.eudiw.dev/trust"),
): MockRequestHandler = {
    assertEquals(url.toString(), it.url.toString())
    assertEquals(HttpMethod.Post, it.method)
    assertEquals(ContentType.Application.Json.toString(), it.headers[KtorHttpHeaders.Accept])
    assertEquals(ContentType.Application.Json, it.body.contentType)

    val body = it.body.toByteReadPacket().use { source -> Json.decodeFromSource<JsonObject>(source) }
    assertIs<JsonArray>(body["chain"])
    val context = Json.decodeFromJsonElement<VerificationContext>(assertIs<JsonPrimitive>(body["verificationContext"]))
    assertEquals(verificationContext, context)

    val response = buildJsonObject {
        put("trusted", trusted)
    }
    respond(
        Json.encodeToString(response),
        HttpStatusCode.OK,
        headersOf(KtorHttpHeaders.ContentType, ContentType.Application.Json.toString()),
    )
}

private fun statusListTokenRequestHandler(
    url: Url = Url.parse("https://issuer.eudiw.dev/token_status_list/FC/key-attestation+jwt/abb5121d-a8bb-440e-bf8f-13bf9de27787"),
): MockRequestHandler = {
    assertEquals(url.toString(), it.url.toString())
    assertEquals(HttpMethod.Get, it.method)
    assertEquals("application/statuslist+jwt", it.headers[KtorHttpHeaders.Accept])
    respond(
        loadResource("statuslisttoken.jwt"),
        HttpStatusCode.OK,
        headersOf(KtorHttpHeaders.ContentType, "application/statuslist+jwt"),
    )
}
