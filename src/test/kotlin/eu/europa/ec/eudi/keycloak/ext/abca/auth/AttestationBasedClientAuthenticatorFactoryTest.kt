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

import arrow.core.right
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.oauth2.sdk.id.Issuer
import com.nimbusds.oauth2.sdk.util.X509CertificateUtils
import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import eu.europa.ec.eudi.keycloak.ext.abca.OpenId4VCI
import eu.europa.ec.eudi.keycloak.ext.abca.RFC7800
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.TokenStatusList
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeHandler
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.toChallenge
import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import jakarta.ws.rs.core.HttpHeaders
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.keycloak.authentication.ClientAuthenticationFlowContext
import org.keycloak.events.EventBuilder
import org.keycloak.http.HttpRequest
import org.keycloak.models.*
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.mock
import org.mockito.kotlin.*
import java.net.URI
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant
import kotlin.time.toJavaInstant

class AttestationBasedClientAuthenticatorFactoryTest {

    private lateinit var context: ClientAuthenticationFlowContext
    private lateinit var httpRequest: HttpRequest
    private lateinit var httpHeaders: HttpHeaders
    private lateinit var session: KeycloakSession
    private lateinit var clientProvider: ClientProvider
    private lateinit var keycloakUriInfo: KeycloakUriInfo
    private lateinit var realm: RealmModel
    private lateinit var eventBuilder: EventBuilder
    private lateinit var authenticator: AttestationBasedClientAuthenticatorFactory
    private lateinit var holderKey: ECKey
    private lateinit var mockHttpClient: HttpClient
    private lateinit var challengeHandler: ChallengeHandler

    private val statusListJwt = loadResource("statuslisttoken.jwt")
    private val challengeJwt = loadResource("challenge.txt")

    private fun loadResource(resource: String): String = requireNotNull(
        AttestationBasedClientAuthenticatorFactoryTest::class.java.classLoader.getResource(resource),
    ).readText()

    @BeforeEach
    fun setUp() {
        context = mock()
        httpRequest = mock()
        httpHeaders = mock()
        session = mock()
        clientProvider = mock()
        realm = mock()
        keycloakUriInfo = mock()
        eventBuilder = mock()
        challengeHandler = mock()

        mockHttpClient = HttpClient(createMockEngine())
        authenticator = AttestationBasedClientAuthenticatorFactory(mockHttpClient)

        whenever(context.httpRequest).thenReturn(httpRequest)
        whenever(httpRequest.httpHeaders).thenReturn(httpHeaders)
        whenever(context.session).thenReturn(session)
        whenever(session.clients()).thenReturn(clientProvider)
        whenever(context.realm).thenReturn(realm)
        whenever(context.event).thenReturn(eventBuilder)

        // Mock KeycloakSession context to avoid nulls in challenge helpers
        val kcContext: KeycloakContext = mock()
        whenever(session.context).thenReturn(kcContext)
        whenever(kcContext.getUri(any())).thenReturn(keycloakUriInfo)
        whenever(keycloakUriInfo.baseUri).thenReturn(URI.create("http://localhost:8080"))
        whenever(kcContext.realm).thenReturn(realm)
        whenever(realm.name).thenReturn("master")

        // Provide ChallengeHandler for challenge verification
        whenever(session.getProvider(ChallengeHandler::class.java)).thenReturn(challengeHandler)

        // Mock OAuth2 WellKnown provider to stabilize issuer/audience checks
        val wellKnownProvider: org.keycloak.wellknown.WellKnownProvider = mock()
        whenever(
            session.getProvider(
                org.keycloak.wellknown.WellKnownProvider::class.java,
                org.keycloak.protocol.oauth2.OAuth2WellKnownProviderFactory.PROVIDER_ID,
            ),
        ).thenReturn(wellKnownProvider)
        whenever(wellKnownProvider.config).thenReturn(mapOf("issuer" to "http://localhost:8080/realms/master"))

        // Generate a fresh holder EC key (P-256) for cnf.jwk
        holderKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.ES256)
            .keyID(UUID.randomUUID().toString())
            .generate()
    }

    private fun createMockEngine(): MockEngine = MockEngine {
        respond(
            content = statusListJwt,
            status = HttpStatusCode.OK,
            headers = headersOf(io.ktor.http.HttpHeaders.ContentType, "application/jwt"),

        )
    }

    @Nested
    inner class SuccessPaths {
        @Test
        fun `successful authentication`() = runTest {
            val clientId = "abca_test"

            val challenge = UUID.randomUUID().toString().toChallenge()
            whenever(challengeHandler.validate(eq(challenge.value))).thenReturn(challenge.right())

            val (attestation, pop) = clientAttestation(clientId, challenge = challenge)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)
            whenever(context.client).thenReturn(client)

            authenticator.authenticateClient(context)

            // The authenticator should not report any failure
            verify(context).success()
            verify(context, never()).failure(any(), anyOrNull())
        }

        @Test
        fun `successful authentication with EC holder key`() = runTest {
            val clientId = "abca_test"

            val challenge = UUID.randomUUID().toString().toChallenge()
            whenever(challengeHandler.validate(eq(challenge.value))).thenReturn(challenge.right())

            val (attestation, pop) = clientAttestation(clientId, challenge = challenge)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)
            whenever(context.client).thenReturn(client)

            authenticator.authenticateClient(context)

            // The authenticator should not report any failure
            verify(context, never()).failure(any(), anyOrNull())
            verify(context, never()).challenge(any())
        }
    }

    @Nested
    inner class HeaderValidation {
        @Test
        fun `fails when client attestation header is null`() {
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(null)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn("irrelevant")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when client attestation header is empty`() {
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn("")
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn("irrelevant")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when PoP header is null`() {
            val clientId = "abca_test"
            val (attestation, _) = clientAttestation(clientId)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(null)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when PoP header is empty`() {
            val clientId = "abca_test"
            val (attestation, _) = clientAttestation(clientId)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn("")

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }
    }

    @Nested
    inner class AttestationParsingAndClaims {
        @Test
        fun `fails when attestation is not a JWT`() {
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn("not-a-jwt")
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn("also-not-a-jwt")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when attestation subject is missing`() {
            val attestationJwt = attestationJwt(subject = null)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestationJwt.serialize())
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn("irrelevant")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when cnf is missing`() {
            val clientId = "abca_test"
            val (attestation, pop) = clientAttestation(clientId, cnfJwk = null)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when cnf jwk is missing`() {
            val clientId = "abca_test"
            val (attestation, pop) = clientAttestation(clientId, cnfJwk = null)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when cnf jwk is invalid type`() {
            val clientId = "abca_test"
            val (attestation, pop) = clientAttestation(clientId, cnfJwk = "not-an-object")
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }
    }

    @Nested
    inner class ClientLookup {
        @Test
        fun `fails when client not found`() {
            val clientId = "missing_client"
            val (attestation, pop) = clientAttestation(clientId)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(null)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when client is disabled`() {
            val clientId = "disabled_client"
            val (attestation, pop) = clientAttestation(clientId)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(false)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }
    }

    @Nested
    inner class ExpirationValidation {
        @Test
        fun `fails when client attestation is expired`() {
            val clientId = "abca_test"

            val pastClock = object : Clock {
                override fun now() = Clock.System.now().minus(90.days)
            }
            val (attestation, pop) = clientAttestation(clientId, clock = pastClock)

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }
    }

    @Nested
    inner class PopVerification {
        @Test
        fun `fails when PoP signature does not match cnf jwk`() {
            val clientId = "abca_test"
            val wrongHolderKey = ECKeyGenerator(Curve.P_256)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyID(UUID.randomUUID().toString())
                .generate()

            val (attestation, pop) = clientAttestation(
                clientId = clientId,
                holderForCnf = holderKey, // advertise holderKey in cnf
                popSigner = wrongHolderKey, // sign PoP with a different key
            )

            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)
            whenever(context.client).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }
    }

    @Test
    fun `fails when attestation uses unsupported signing algorithm`() {
        val clientId = "abca_test"
        val attestationJwt = attestationJwtWithUnsupportedAlg(subject = clientId)
        val pop = popJwt(clientId, holderKey)

        whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_HEADER)).thenReturn(attestationJwt.serialize())
        whenever(httpHeaders.getHeaderString(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_HEADER)).thenReturn(pop.serialize())

        val client: ClientModel = mock()
        whenever(client.isEnabled).thenReturn(true)
        whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)
        whenever(context.client).thenReturn(client)

        authenticator.authenticateClient(context)

        verify(context, never()).success()
        verify(context).failure(any(), anyOrNull())
    }

    private fun clientAttestation(
        clientId: String = "abca_test",
        cnfJwk: Any? = holderKey.toPublicJWK().toJSONObject(),
        holderForCnf: ECKey = holderKey,
        popSigner: ECKey = holderForCnf,
        challenge: Challenge? = null,
        clock: Clock = Clock.System,
    ): Pair<String, String> = attestationJwt(clientId, cnfJwk, clock).serialize() to popJwt(clientId, popSigner, clock, challenge).serialize()

    private fun Instant.toJavaDate(): Date = Date.from(toJavaInstant())

    internal fun attestationJwt(
        subject: String?,
        cnfJwk: Any? = holderKey.toPublicJWK().toJSONObject(),
        clock: Clock = Clock.System,
    ): SignedJWT {
        val now = clock.now()

        val attesterKey = ECKeyGenerator(Curve.P_256)
            .algorithm(JWSAlgorithm.ES256)
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val attesterCertificate = X509CertificateUtils.generateSelfSigned(
            Issuer("http://localhost:8080"),
            now.toJavaDate(),
            (now + 365.days).toJavaDate(),
            attesterKey.toECPublicKey(),
            attesterKey.toECPrivateKey(),
        )

        val claims = JWTClaimsSet.Builder().apply {
            issuer("http://localhost:8080")
            subject?.let { subject(it) }
            notBeforeTime((now - 60.days).toJavaDate())
            expirationTime((now + 60.days).toJavaDate())
            cnfJwk?.let {
                claim(RFC7800.CONFIRMATION_CLAIM, mapOf(RFC7800.JWK_METHOD_CLAIM to cnfJwk))
            }
            claim(
                TS3.EUDI_CLIENT_STATUS_CLAIM,
                mapOf(
                    TokenStatusList.STATUS_CLAIM to mapOf(
                        TokenStatusList.STATUS_LIST_CLAIM to mapOf(
                            TokenStatusList.INDEX_CLAIM to 1,
                            TokenStatusList.URI_CLAIM to "https://issuer.eudiw.dev/token_status_list/FC/key-attestation+jwt/3b83d6bd-64f7-4f71-b16f-bb7e66d38557",
                        ),
                    ),
                    "exp" to (now + 60.days).epochSeconds,
                ),
            )
            claim(OpenId4VCI.WALLET_NAME_CLAIM, "Wallet name")
            claim(TS3.EUDI_WALLET_VERSION_CLAIM, "1.0")
            claim(
                TS3.EUDI_WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM,
                mapOf(
                    "test" to "test",
                    "example" to "example",
                    "test2" to mapOf("test3" to "test3"),
                ),
            )
            claim(OpenId4VCI.WALLET_LINK_CLAIM, "https://example")
        }.build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).apply {
            x509CertChain(listOf(Base64.encode(attesterCertificate.encoded)))
            type(JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_JWT_TYPE))
        }.build()

        return SignedJWT(header, claims)
            .also { it.sign(ECDSASigner(attesterKey)) }
    }

    internal fun attestationJwtWithUnsupportedAlg(
        subject: String?,
        cnfJwk: Any? = holderKey.toPublicJWK().toJSONObject(),
        clock: Clock = Clock.System,
    ): SignedJWT {
        val now = clock.now()

        val attesterKey = RSAKeyGenerator(2048)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.RS256)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val claims = JWTClaimsSet.Builder().apply {
            issuer("http://localhost:8080")
            subject?.let { subject(subject) }
            notBeforeTime((now - 60.days).toJavaDate())
            expirationTime((now + 60.days).toJavaDate())
            cnfJwk?.let {
                claim(RFC7800.CONFIRMATION_CLAIM, mapOf(RFC7800.JWK_METHOD_CLAIM to cnfJwk))
            }
            claim(
                TS3.EUDI_CLIENT_STATUS_CLAIM,
                mapOf(
                    TokenStatusList.STATUS_CLAIM to mapOf(
                        TokenStatusList.STATUS_LIST_CLAIM to mapOf(
                            TokenStatusList.INDEX_CLAIM to 1,
                            TokenStatusList.URI_CLAIM to "https://issuer.eudiw.dev/token_status_list/FC/key-attestation+jwt/3b83d6bd-64f7-4f71-b16f-bb7e66d38557",
                        ),
                    ),
                    "exp" to (now + 60.days).epochSeconds,
                ),
            )
            claim(OpenId4VCI.WALLET_NAME_CLAIM, "Wallet name")
            claim(TS3.EUDI_WALLET_VERSION_CLAIM, "1.0")
            claim(TS3.EUDI_WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM, "example")
            claim(OpenId4VCI.WALLET_LINK_CLAIM, "https://example")
        }.build()

        val header = JWSHeader.Builder(JWSAlgorithm.RS256).apply {
            jwk(attesterKey.toPublicJWK())
            x509CertChain(listOf(Base64.encode("dummy-cert".toByteArray())))
            type(JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_JWT_TYPE))
            keyID(attesterKey.keyID)
        }.build()

        return SignedJWT(header, claims)
            .also { it.sign(RSASSASigner(attesterKey)) }
    }

    internal fun popJwt(
        issuer: String,
        popSigner: ECKey,
        clock: Clock = Clock.System,
        challenge: Challenge? = null,
    ): SignedJWT {
        val now = clock.now()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_JWT_TYPE))
            .keyID(popSigner.keyID)
            .build()

        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience("http://localhost:8080/realms/master")
            .jwtID(UUID.randomUUID().toString())
            .issueTime((now - 60.days).toJavaDate())
            .notBeforeTime((now - 60.days).toJavaDate())
            .expirationTime((now + 60.days).toJavaDate())
            .claim(
                AttestationBasedClientAuthentication.CHALLENGE_CLAIM,
                challenge?.value ?: UUID.randomUUID().toString(),
            )
            .build()

        return SignedJWT(header, claims)
            .also { it.sign(ECDSASigner(popSigner)) }
    }

    @Test
    fun test() {
        attestationJwt("eudiw-abca").also { println(it.serialize()) }
        val challenge = Challenge.of(challengeJwt)
        popJwt("abca_test", holderKey, challenge = challenge).also { println(it.serialize()) }
    }
}
