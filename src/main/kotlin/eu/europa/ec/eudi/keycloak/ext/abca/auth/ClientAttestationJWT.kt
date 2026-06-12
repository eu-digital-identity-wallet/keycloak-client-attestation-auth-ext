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

import arrow.core.raise.result
import com.fasterxml.jackson.databind.ObjectMapper
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.keycloak.ext.abca.*
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.InstantEpochSecondsSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.net.URI
import kotlin.time.Instant

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

@JvmInline
@Serializable
value class WalletSolutionCertificationInformation(val certificationInformation: JsonElement) {
    init {
        require(
            (certificationInformation is JsonObject) ||
                ((certificationInformation is JsonPrimitive) && certificationInformation.isString),

        ) { "wallet solution certification information claim must be of type Json Object or String" }
    }
}

@JvmInline
value class ClientAttestationJWT private constructor(val jwt: SignedJWT) {
    val subject: String
        get() = jwt.jwtClaimsSet.subject

    val jwk: JWK
        get() = jwt.jwtClaimsSet.cnf().cnfJwk()

    val status: Status?
        get() = jwt.jwtClaimsSet.status()

    val walletName: String
        get() = jwt.jwtClaimsSet.walletName().getOrThrow()

    val walletVersion: String
        get() = jwt.jwtClaimsSet.walletVersion().getOrThrow()

    val walletSolutionCertificationInformation: WalletSolutionCertificationInformation
        get() = jwt.jwtClaimsSet.walletSolutionCertificationInformation().getOrThrow()

    val walletLink: URI?
        get() = jwt.jwtClaimsSet.walletLink().getOrThrow()

    val clientStatus: ClientStatus
        get() = jwt.jwtClaimsSet.clientStatus().getOrThrow()

    companion object {
        operator fun invoke(jwt: String): Result<ClientAttestationJWT> = result {
            invoke(SignedJWT.parse(jwt)).getOrThrow()
        }

        operator fun invoke(jwt: SignedJWT): Result<ClientAttestationJWT> = result {
            with(jwt) {
                requireIsSignedOrVerified()
                requireType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_JWT_TYPE)
                requireMandatoryClaims(
                    "iss",
                    "sub",
                    "exp",
                    "cnf",
                    OpenId4VCI.WALLET_NAME_CLAIM,
                    TS3.EUDI_WALLET_VERSION_CLAIM,
                    TS3.EUDI_WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM,
                    TS3.EUDI_CLIENT_STATUS_CLAIM,
                )
                verifySignature()
                requireValidConfirmationJwk()
                requireWalletName()
                requireWalletVersion()
                requireWalletSolutionCertificationInformation()
                requireClientStatus()
                ensureWalletLinkType()
            }
            ClientAttestationJWT(jwt)
        }
    }
}

@JvmInline
value class ClientAttestationPoPJWT private constructor(val jwt: SignedJWT) {
    val issuer: String
        get() = jwt.jwtClaimsSet.issuer

    val audience: List<String>
        get() = jwt.jwtClaimsSet.audience ?: emptyList()

    val challenge: Challenge?
        get() = jwt.jwtClaimsSet.getStringClaim(AttestationBasedClientAuthentication.CHALLENGE_CLAIM)?.let { Challenge(it) }

    companion object {
        operator fun invoke(jwt: String): Result<ClientAttestationPoPJWT> = result {
            invoke(SignedJWT.parse(jwt)).getOrThrow()
        }

        operator fun invoke(jwt: SignedJWT): Result<ClientAttestationPoPJWT> = result {
            with(jwt) {
                requireIsSignedOrVerified()
                requireNotMACSigned()
                requireType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_JWT_TYPE)
                requireMandatoryClaims("iss", "aud", "jti", "iat")
            }

            ClientAttestationPoPJWT(jwt)
        }
    }

    fun verifyPop(clientAttestationJWT: ClientAttestationJWT) {
        val jwk = clientAttestationJWT.jwk
        require(jwk is ECKey) { "Unsupported key type: ${jwk.algorithm}" }

        val verifier = ECDSAVerifier(jwk)
        val verified = this.jwt.verify(verifier)
        require(verified) { "Invalid signature" }
    }
}

private fun SignedJWT.verifySignature() {
    header.requireAllowedSigningAlgorithm()

    val jwk = header.extractJwk()

    DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_JWT_TYPE))
        jwsKeySelector = JWSVerificationKeySelector(
            header.algorithm,
            ImmutableJWKSet(JWKSet(jwk)),
        )
    }.also {
        it.process(this, null)
    }
}

private fun SignedJWT.requireMandatoryClaims(first: String, vararg remaining: String) = DefaultJWTClaimsVerifier<SecurityContext>(
    null,
    setOf(first, *remaining),
).apply {
    maxClockSkew = 60
}.verify(jwtClaimsSet, null)

private fun SignedJWT.requireIsSignedOrVerified() = require(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
    "Client attestation JWT is not signed"
}

private fun SignedJWT.requireNotMACSigned() = require(!header.algorithm.isMACSigning()) {
    "MAC signing algorithm not allowed"
}

private fun SignedJWT.requireValidConfirmationJwk(): JWK {
    val jwk = jwtClaimsSet.cnf().cnfJwk()
    require(!jwk.isPrivate) {
        "JWK must not be private"
    }
    return jwk
}

private fun SignedJWT.requireType(expectedType: String) {
    val typ = header.type?.type
    requireNotNull(typ) { "Missing JWT type" }
    require(typ == expectedType) { "Invalid JWT type" }
}

private fun SignedJWT.requireWalletName() {
    jwtClaimsSet.walletName().getOrThrow()
}

private fun SignedJWT.requireWalletVersion() {
    jwtClaimsSet.walletVersion().getOrThrow()
}

private fun SignedJWT.requireWalletSolutionCertificationInformation() {
    jwtClaimsSet.walletSolutionCertificationInformation().getOrThrow()
}

private fun SignedJWT.requireClientStatus() {
    jwtClaimsSet.clientStatus().getOrThrow()
}

private fun SignedJWT.ensureWalletLinkType() {
    if (null != jwtClaimsSet.getStringClaim(OpenId4VCI.WALLET_LINK_CLAIM)) {
        jwtClaimsSet.walletLink().getOrThrow()
    }
}

private fun JWTClaimsSet.walletName(): Result<String> = runCatching {
    requireNotNull(getStringClaim(OpenId4VCI.WALLET_NAME_CLAIM))
}

private fun JWTClaimsSet.cnf(): JsonObject = requireNotNull(getJSONObjectClaim(AttestationBasedClientAuthentication.CNF_CLAIM)).toJsonObject()

private fun JsonObject.cnfJwk(): JWK = requireNotNull(this[AttestationBasedClientAuthentication.CNF_JWK_CLAIM]).let {
    val jsonString = json.encodeToString(it)
    JWK.parse(jsonString)
}

private fun JWTClaimsSet.status(): Status? = getJSONObjectClaim(AttestationBasedClientAuthentication.STATUS_CLAIM)?.toJsonObject()?.let { jsonObj ->
    runCatching {
        json.decodeFromString(Status.serializer(), json.encodeToString(jsonObj))
    }.getOrNull()
}

private fun JWTClaimsSet.clientStatus(): Result<ClientStatus> = runCatching {
    val clientStatusClaim = JSONObjectUtils.toJSONString(requireNotNull(getJSONObjectClaim(TS3.EUDI_CLIENT_STATUS_CLAIM)))
    json.decodeFromString<ClientStatus>(clientStatusClaim)
}

private fun JWTClaimsSet.walletLink(): Result<URI?> = runCatching {
    val walletLinkClaim = getStringClaim(OpenId4VCI.WALLET_LINK_CLAIM)
    walletLinkClaim?.let { URI.create(it) }
}

private fun JWTClaimsSet.walletSolutionCertificationInformation(): Result<WalletSolutionCertificationInformation> = runCatching {
    val claim = getClaim(TS3.EUDI_WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM)
    val objectMapper = ObjectMapper()
    val jsonElement = json.parseToJsonElement(objectMapper.writeValueAsString(claim))
    WalletSolutionCertificationInformation(jsonElement)
}

private fun JWTClaimsSet.walletVersion(): Result<String> = runCatching {
    val walletVersionClaim = requireNotNull(getStringClaim(TS3.EUDI_WALLET_VERSION_CLAIM))
    walletVersionClaim
}

private fun JWSHeader.requireAllowedSigningAlgorithm() {
    require(algorithm in TS3.ALLOWED_ALGORITHMS) {
        "Signing algorithm not supported"
    }
}

private fun JWSHeader.extractJwk(): JWK {
    requireNotNull(x509CertChain) { "Missing x5c" }
    require(x509CertChain.isNotEmpty()) { "x5c must not be empty" }

    val x509 = X509CertUtils.parse(x509CertChain.first().decode())
    return JWK.parse(x509)
}

private fun Map<String, Any?>.toJsonObject(): JsonObject {
    val jsonString = JSONObjectUtils.toJSONString(this)
    return json.decodeFromString(jsonString)
}

private fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS

private val json = Json { ignoreUnknownKeys = true }
