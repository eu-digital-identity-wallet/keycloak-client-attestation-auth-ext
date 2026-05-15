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

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.KeyUse
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import jakarta.ws.rs.core.HttpHeaders
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.keycloak.authentication.ClientAuthenticationFlowContext
import org.keycloak.events.EventBuilder
import org.keycloak.http.HttpRequest
import org.keycloak.models.*
import org.keycloak.protocol.oid4vc.issuance.keybinding.CNonceHandler
import org.mockito.Mockito.mock
import org.mockito.Mockito.mockStatic
import org.mockito.kotlin.*
import java.net.URI
import java.security.cert.X509Certificate
import java.util.*
import kotlin.time.Clock
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

class AttestationBasedClientAuthenticatorFactoryTest {

    private lateinit var context: ClientAuthenticationFlowContext
    private lateinit var httpRequest: HttpRequest
    private lateinit var httpHeaders: HttpHeaders
    private lateinit var session: KeycloakSession
    private lateinit var clientProvider: ClientProvider
    private lateinit var keycloakUriInfo: KeycloakUriInfo
    private lateinit var realm: RealmModel
    private lateinit var eventBuilder: EventBuilder

    private lateinit var cNonceHandler: CNonceHandler

    private lateinit var authenticator: AttestationBasedClientAuthenticatorFactory
    private lateinit var x509CertUtilsMock: org.mockito.MockedStatic<X509CertUtils>

    private lateinit var holderKey: ECKey

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
        cNonceHandler = mock()
        authenticator = AttestationBasedClientAuthenticatorFactory()

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

        x509CertUtilsMock = mockStatic(X509CertUtils::class.java)
        x509CertUtilsMock.`when`<X509Certificate> {
            X509CertUtils.parse(org.mockito.ArgumentMatchers.any(ByteArray::class.java))
        }.thenReturn(mock())

        // Provide CNonceHandler for challenge verification
        whenever(session.getProvider(CNonceHandler::class.java)).thenReturn(cNonceHandler)
        // Let verifyCNonce accept any inputs (no-op)
        doNothing().whenever(cNonceHandler).verifyCNonce(any(), any(), any())

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

    @AfterEach
    fun tearDown() {
        x509CertUtilsMock.close()
    }

    @Nested
    inner class SuccessPaths {
        @Test
        fun `successful authentication`() {
            val clientId = "abca_test"
            val (attestation, pop) = generateAttestationAndPop(clientId)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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
        fun `successful authentication with EC holder key`() {
            val clientId = "abca_test"

            val (attestation, pop) = generateAttestationAndPop(clientId)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(null)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn("irrelevant")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when client attestation header is empty`() {
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn("")
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn("irrelevant")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when PoP header is null`() {
            val clientId = "abca_test"
            val (attestation, _) = generateAttestationAndPop(clientId)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(null)

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
            val (attestation, _) = generateAttestationAndPop(clientId)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn("")

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
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn("not-a-jwt")
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn("also-not-a-jwt")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when attestation subject is missing`() {
            val attestationJwt = attestationJwt(subject = null)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestationJwt.serialize())
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn("irrelevant")

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when cnf is missing`() {
            val clientId = "abca_test"
            val (attestation, pop) = generateAttestationAndPop(clientId, cnfJwk = null)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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
            val (attestation, pop) = generateAttestationAndPop(clientId, cnfJwk = null)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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
            val (attestation, pop) = generateAttestationAndPop(clientId, cnfJwk = "not-an-object")
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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
            val (attestation, pop) = generateAttestationAndPop(clientId)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(null)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }

        @Test
        fun `fails when client is disabled`() {
            val clientId = "disabled_client"
            val (attestation, pop) = generateAttestationAndPop(clientId)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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
            val (attestation, pop) = generateAttestationAndPop(clientId, clock = pastClock)

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

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

            val (attestation, pop) = generateAttestationAndPop(
                clientId = clientId,
                holderForCnf = holderKey, // advertise holderKey in cnf
                popSigner = wrongHolderKey, // sign PoP with a different key
            )

            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)).thenReturn(attestation)
            whenever(httpHeaders.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)).thenReturn(pop)

            val client: ClientModel = mock()
            whenever(client.isEnabled).thenReturn(true)
            whenever(clientProvider.getClientByClientId(realm, clientId)).thenReturn(client)
            whenever(context.client).thenReturn(client)

            authenticator.authenticateClient(context)

            verify(context, never()).success()
            verify(context).failure(any(), anyOrNull())
        }
    }

    private fun generateAttestationAndPop(
        clientId: String = "abca_test",
        cnfJwk: Any? = holderKey.toPublicJWK().toJSONObject(),
        holderForCnf: ECKey = holderKey,
        popSigner: ECKey = holderForCnf,
        clock: Clock = Clock.System,
    ): Pair<String, String> {
        return attestationJwt(clientId, cnfJwk, clock).serialize() to popJwt(clientId, popSigner, clock).serialize()
    }

    internal fun attestationJwt(
        subject: String?,
        cnfJwk: Any? = holderKey.toPublicJWK().toJSONObject(),
        clock: Clock = Clock.System,
    ): SignedJWT {
        val nowMillis = clock.now().toEpochMilliseconds()

        val attesterKey = ECKeyGenerator(Curve.P_256)
            .keyUse(KeyUse.SIGNATURE)
            .algorithm(JWSAlgorithm.ES256)
            .keyID(UUID.randomUUID().toString())
            .generate()

        val claims = JWTClaimsSet.Builder().apply {
            issuer("http://localhost:8080")
            subject?.let {
                subject(subject)
            }
            notBeforeTime(Date(nowMillis - 60.days.inWholeMilliseconds))
            expirationTime(Date(nowMillis + 60.days.inWholeMilliseconds))
            cnfJwk?.let {
                claim(Spec.CNF_CLAIM, mapOf(Spec.CNF_JWK_CLAIM to cnfJwk))
            }
        }.build()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256).apply {
            jwk(attesterKey.toPublicJWK())
            x509CertChain(listOf(Base64.encode("dummy-cert".toByteArray())))
            type(JOSEObjectType(Spec.CLIENT_ATTESTATION_JWT_TYPE))
            keyID(attesterKey.keyID)
        }.build()

        return SignedJWT(header, claims)
            .also { it.sign(ECDSASigner(attesterKey)) }
    }

    internal fun popJwt(
        issuer: String,
        popSigner: ECKey,
        clock: Clock = Clock.System,
        challenge: Challenge? = null,
    ): SignedJWT {
        val nowMillis = clock.now().toEpochMilliseconds()

        val header = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType(Spec.CLIENT_ATTESTATION_POP_JWT_TYPE))
            .keyID(popSigner.keyID)
            .build()

        val claims = JWTClaimsSet.Builder()
            .issuer(issuer)
            .audience("http://localhost:8080/realms/master")
            .jwtID(UUID.randomUUID().toString())
            .issueTime(Date(nowMillis - 60.seconds.inWholeMilliseconds))
            .notBeforeTime(Date(nowMillis - 60.seconds.inWholeMilliseconds))
            .expirationTime(Date(nowMillis + 60.seconds.inWholeMilliseconds))
            .claim(Spec.CHALLENGE_CLAIM, challenge?.value ?: UUID.randomUUID().toString())
            .build()

        return SignedJWT(header, claims)
            .also { it.sign(ECDSASigner(popSigner)) }
    }

    @Test
    fun test() {
        attestationJwt("eudiw-abca").also { println(it.serialize()) }
        val challenge = Challenge("eyJhbGciOiJFUzI1NiIsImtpZCIgOiAiOGZNbGQ1d01OX1duX2J2aGJ1aVRCSWRvWnk1SzR0aTdTLXRNVU16MzJoUSJ9.eyJleHAiOjE3NTkyMjQ0NjQsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9yZWFsbXMvbWFzdGVyIiwiYXVkIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIiLCJzYWx0IjoiRlJKTHovNEpXZ0k3TVVTQ0lpK0Zha0xxUFJFMjA5VW1oWGFzd2NWc0FySk93TGk0TzIyMkJsbFNlZDJkemNDTkFQWHI4OHJEMFhHRXdadTZ4VmxnIiwic291cmNlX2VuZHBvaW50IjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9tYXN0ZXIvY2hhbGxlbmdlIn0.csFKZDOlaxj0N3SZCT_KSoZesmT-0_luF9jVgEKJBSmzBN1r75szj5lSMeEHzKnsf8g86jtYtriAa_pqeuNFzg")
        popJwt("abca_test", holderKey, challenge = challenge).also { println(it.serialize()) }
    }
}
