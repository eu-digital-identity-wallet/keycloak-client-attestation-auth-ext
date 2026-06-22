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
package eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation

import arrow.core.NonEmptyList
import arrow.core.NonEmptySet
import arrow.core.raise.result
import arrow.core.toNonEmptyListOrNull
import arrow.core.toNonEmptyListOrThrow
import com.eygraber.uri.Url
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.keycloak.ext.abca.*
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.Audience
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.EpochSecondsInstant
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.InstantEpochSecondsSerializer
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.JsonObjectJWK
import eu.europa.ec.eudi.keycloak.ext.abca.tokenstatuslist.Status
import eu.europa.ec.eudi.keycloak.ext.abca.util.decodeAs
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import kotlin.time.Instant

data class ClientAttestation private constructor(
    val jwt: SignedJWT,
    val claims: WalletInstanceAttestationClaims,
) {
    val x5c: NonEmptyList<X509Certificate>
        get() = jwt.header.x509CertChain.toNonEmptyListOrThrow().map { X509CertUtils.parseWithException(it.decode()) }

    val signingKey: ECPublicKey
        get() = X509CertUtils.parseWithException(jwt.header.x509CertChain.first().decode()).publicKey as ECPublicKey

    val signatureAlgorithm: JWSAlgorithm
        get() = jwt.header.algorithm

    val confirmationKey: ECPublicKey
        get() = claims.confirmation.jwk.toECKey().toECPublicKey()

    companion object {
        fun ofOrNull(value: String): ClientAttestation? = tryParse(value).getOrNull()
        fun of(value: String): ClientAttestation = tryParse(value).getOrElse { throw IllegalArgumentException("value is not a valid Client Attestation", it) }

        fun tryParse(value: String): Result<ClientAttestation> = result {
            val jwt = SignedJWT.parse(value)

            jwt.header.requireType(JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_JWT_TYPE))
            jwt.header.requireAlgorithmOneOf(TS3.ALLOWED_ALGORITHMS)

            val x5c = requireNotNull(jwt.header.x509CertChain?.toNonEmptyListOrNull()) {
                "Client Attestation is missing the 'x5c' claim in the JWSHeader"
            }.map { X509CertUtils.parseWithException(it.decode()) }

            val signingKey = x5c.first().publicKey
            require(signingKey is ECPublicKey) {
                "The first certificate in the 'x5c' claim in the JWSHeader must contain an EC public key"
            }

            require(jwt.verify(ECDSAVerifier(signingKey))) {
                "Client Attestation signature verification failed"
            }

            val claims = jwt.jwtClaimsSet.decodeAs<WalletInstanceAttestationClaims>()
            require(claims.confirmation.jwk is ECKey) {
                "Confirmation JWK must be an EC public key"
            }

            ClientAttestation(jwt, claims)
        }
    }
}

@Serializable
@JsonIgnoreUnknownKeys
data class WalletInstanceAttestationClaims(
    @Required @SerialName(RFC7519.ISSUER_CLAIM) val issuer: NonBlankString,
    @Required @SerialName(RFC7519.SUBJECT_CLAIM) val subject: NonBlankString,
    @Required @SerialName(RFC7519.EXPIRES_AT_CLAIM) val expiresAt: EpochSecondsInstant,
    @Required @SerialName(RFC7800.CONFIRMATION_CLAIM) val confirmation: Confirmation,
    @SerialName(RFC7519.ISSUED_AT_CLAIM) val issuedAt: EpochSecondsInstant? = null,
    @SerialName(RFC7519.NOT_BEFORE_CLAIM) val notBefore: EpochSecondsInstant? = null,
    @Required @SerialName(OpenId4VCI.WALLET_NAME_CLAIM) val walletName: NonBlankString,
    @SerialName(OpenId4VCI.WALLET_LINK_CLAIM) val walletLink: Url? = null,
    @SerialName(TokenStatusList.STATUS_CLAIM) val status: Status? = null,
    @Required @SerialName(TS3.WALLET_VERSION_CLAIM) val walletVersion: NonBlankString,
    @Required @SerialName(TS3.WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM) val walletSolutionCertificationInformation: JsonElement,
    @Required @SerialName(TS3.CLIENT_STATUS_CLAIM) val clientStatus: ClientStatus,
)

@Serializable
@JsonIgnoreUnknownKeys
data class Confirmation private constructor(
    @Required @SerialName(RFC7800.JWK_METHOD_CLAIM) val jwk: JsonObjectJWK,
) {
    init {
        check(!jwk.isPrivate)
    }

    companion object {
        fun ofOrNull(jwk: JWK): Confirmation? = jwk.takeIf { !it.isPrivate }?.let(::Confirmation)
        fun of(jwk: JWK): Confirmation = ofOrNull(jwk) ?: throw IllegalArgumentException("jwk must not be private")
    }
}

@Serializable
data class ClientStatus(
    @Required
    @SerialName(TokenStatusList.STATUS_CLAIM)
    val status: Status,

    @Required
    @SerialName(RFC7519.EXPIRES_AT_CLAIM)
    @Serializable(with = InstantEpochSecondsSerializer::class)
    val expiresAt: Instant,
)

data class ClientAttestationPoP private constructor(
    val jwt: SignedJWT,
    val claims: ClientAttestationPoPClaims,
) {
    val signatureAlgorithm: JWSAlgorithm
        get() = jwt.header.algorithm

    companion object {
        fun ofOrNull(value: String): ClientAttestationPoP? = tryParse(value).getOrNull()
        fun of(value: String): ClientAttestationPoP = tryParse(value).getOrElse { throw IllegalArgumentException("value is not a valid Client Attestation PoP", it) }

        fun tryParse(value: String): Result<ClientAttestationPoP> = result {
            val jwt = SignedJWT.parse(value)

            jwt.header.requireType(JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_JWT_TYPE))
            jwt.header.requireAlgorithmOneOf(TS3.ALLOWED_ALGORITHMS)

            val claims = jwt.jwtClaimsSet.decodeAs<ClientAttestationPoPClaims>()
            ClientAttestationPoP(jwt, claims)
        }
    }
}

@Serializable
@JsonIgnoreUnknownKeys
data class ClientAttestationPoPClaims(
    @Required @SerialName(RFC7519.ISSUER_CLAIM) val issuer: NonBlankString,
    @Required @SerialName(RFC7519.AUDIENCE_CLAIM) val audience: Audience,
    @Required @SerialName(RFC7519.JWT_ID_CLAIM) val jwtId: NonBlankString,
    @Required @SerialName(RFC7519.ISSUED_AT_CLAIM) val issuedAt: EpochSecondsInstant,
    @SerialName(AttestationBasedClientAuthentication.CHALLENGE_CLAIM) val challenge: Challenge? = null,
    @SerialName(RFC7519.NOT_BEFORE_CLAIM) val notBefore: EpochSecondsInstant? = null,
)

private fun JWSHeader.requireType(expected: JOSEObjectType) {
    require(expected == type) {
        "Expected JWT type to be ${expected.type}, but got ${type?.type} instead"
    }
}

private fun JWSHeader.requireAlgorithmOneOf(expected: NonEmptySet<JWSAlgorithm>) {
    require(algorithm in expected) {
        "Expected JWS Algorithm to be one of ${expected.joinToString(", ") { it.name }} but got ${algorithm.name} instead"
    }
}
