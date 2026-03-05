package eu.europa.ec.eudi.keycloak.ext.abca.auth

import arrow.core.raise.result
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
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
import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

@JvmInline
value class ClientAttestationJWT private constructor(val jwt: SignedJWT) {
    val subject: String
        get() = jwt.jwtClaimsSet.subject

    val jwk: JWK
        get() = jwt.jwtClaimsSet.cnf().cnfJwk()

    val status: Status?
        get() = jwt.jwtClaimsSet.status()

    companion object {
        operator fun invoke(jwt: String): Result<ClientAttestationJWT> =
            result {
                invoke(SignedJWT.parse(jwt)).getOrThrow()
            }

        operator fun invoke(jwt: SignedJWT): Result<ClientAttestationJWT> =
            result {
                with(jwt) {
                    requireIsSignedOrVerified()
                    requireType(Spec.CLIENT_ATTESTATION_JWT_TYPE)
                    requireMandatoryClaims(setOf("iss", "sub", "exp", "cnf"))
                    verifySignature()
                    requireValidConfirmationJwk()
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
        get() = jwt.jwtClaimsSet.getStringClaim(Spec.CHALLENGE_CLAIM)?.let { Challenge(it) }

    companion object {
        operator fun invoke(jwt: String): Result<ClientAttestationPoPJWT> =
            result {
                invoke(SignedJWT.parse(jwt)).getOrThrow()
            }

        operator fun invoke(jwt: SignedJWT): Result<ClientAttestationPoPJWT> =
            result {
                with(jwt) {
                    requireIsSignedOrVerified()
                    requireNotMACSigned()
                    requireType(Spec.CLIENT_ATTESTATION_POP_JWT_TYPE)
                    requireMandatoryClaims(setOf("iss", "aud", "jti", "iat"))
                }

                ClientAttestationPoPJWT(jwt)
            }
    }

    fun verifyPop(clientAttestationJWT: ClientAttestationJWT) {
        fun JWK.verifier(): JWSVerifier = when (this) {
            is RSAKey -> RSASSAVerifier(this)
            is ECKey -> ECDSAVerifier(this)
            else -> error("Unsupported key type: ${this.algorithm}")
        }

        val verified = this.jwt.verify(clientAttestationJWT.jwk.verifier())
        require(verified) { "Invalid signature" }
    }
}

private fun SignedJWT.verifySignature() {
    val header = header

    // Try JWK directly from header, otherwise derive from first x5c certificate
    val headerJwk: JWK? = header.jwk
    val jwk: JWK? = headerJwk ?: header.x509CertChain?.firstOrNull()?.let { b64 ->
        X509CertUtils.parse(b64.decode())?.let { JWK.parse(it) }
    }

    requireNotNull(jwk) { "Missing JWK or x5c in JWS header" }

    DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType(Spec.CLIENT_ATTESTATION_JWT_TYPE))
        jwsKeySelector = JWSVerificationKeySelector(
            header.algorithm,
            ImmutableJWKSet(JWKSet(jwk)),
        )
    }.also {
        it.process(this, null)
    }
}

private fun SignedJWT.requireMandatoryClaims(claims: Set<String>) =
    DefaultJWTClaimsVerifier<SecurityContext>(
        null,
        claims,
    ).apply {
        maxClockSkew = 60
    }.verify(jwtClaimsSet, null)

private fun SignedJWT.requireIsSignedOrVerified() =
    require(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "Client attestation JWT is not signed"
    }

private fun SignedJWT.requireNotMACSigned() =
    require(!header.algorithm.isMACSigning()) {
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

private fun JWTClaimsSet.cnf(): JsonObject {
    return requireNotNull(getJSONObjectClaim(Spec.CNF_CLAIM)).toJsonObject()
}

private fun JsonObject.cnfJwk(): JWK {
    return requireNotNull(this[Spec.CNF_JWK_CLAIM]).let {
        val jsonString = Json.encodeToString(it)
        JWK.parse(jsonString)
    }
}

private fun JWTClaimsSet.status(): Status? {
    return getJSONObjectClaim(Spec.STATUS_CLAIM)?.toJsonObject()?.let { jsonObj ->
        runCatching {
            val json = Json { ignoreUnknownKeys = true }
            json.decodeFromString(Status.serializer(), Json.encodeToString(jsonObj))
        }.getOrNull()
    }
}

private fun Map<String, Any?>.toJsonObject(): JsonObject {
    val jsonString = JSONObjectUtils.toJSONString(this)
    return Json.decodeFromString(jsonString)
}

private fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS
