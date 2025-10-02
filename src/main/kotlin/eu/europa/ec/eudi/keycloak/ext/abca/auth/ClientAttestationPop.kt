package eu.europa.ec.eudi.keycloak.ext.abca.auth

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.RSASSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.Challenge

class ClientAttestationPop(private val jwt: SignedJWT) {

    val issuer: String = jwt.jwtClaimsSet.issuer
    val audiences = jwt.jwtClaimsSet.audience ?: emptyList()
    val challenge: Challenge? = jwt.jwtClaimsSet.getStringClaim(Spec.CHALLENGE_CLAIM)?.let { Challenge(it) }

    init {
        require(jwt.state == JWSObject.State.SIGNED || jwt.state == JWSObject.State.VERIFIED) {
            "Client attestation PoP JWT is not signed"
        }
        val typ = jwt.header.type?.type
        requireNotNull(typ) { "Missing JWT type" }
        require(typ == Spec.CLIENT_ATTESTATION_POP_JWT_TYPE) { "Invalid JWT type" }
        require(!jwt.header.algorithm.isMACSigning()) { "MAC signing algorithm not allowed" }
        requireNotNull(jwt.jwtClaimsSet.issuer) {
            "Missing issuer in client attestation PoP JWT"
        }
        require(!jwt.jwtClaimsSet.audience.isNullOrEmpty()) {
            "Missing audience in client attestation PoP JWT"
        }
        requireNotNull(jwt.jwtClaimsSet.jwtid) {
            "Missing jti in client attestation PoP JWT"
        }
        val iat = jwt.jwtClaimsSet.issueTime
        requireNotNull(iat) {
            "Missing iat in client attestation PoP JWT"
        }
        require(iat.time <= System.currentTimeMillis()) {
            "Invalid issuance time in client attestation PoP JWT"
        }
        jwt.jwtClaimsSet.notBeforeTime?.let {
            require(it.time <= System.currentTimeMillis()) {
                "Invalid not before time in client attestation PoP JWT"
            }
        }
    }

    fun verifyPop(clientAttestation: ClientAttestation) {
        val verified = jwt.verify(clientAttestation.jwk.verifier())
        require(verified) { "Invalid signature" }
    }

    fun JWK.verifier(): JWSVerifier = when (this) {
        is RSAKey -> RSASSAVerifier(this)
        is ECKey -> ECDSAVerifier(this)
        else -> error("Unsupported key type: ${this.algorithm}")
    }
}

private fun JWSAlgorithm.isMACSigning(): Boolean = this in MACSigner.SUPPORTED_ALGORITHMS
