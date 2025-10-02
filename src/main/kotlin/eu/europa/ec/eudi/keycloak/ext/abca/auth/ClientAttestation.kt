package eu.europa.ec.eudi.keycloak.ext.abca.auth

import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import kotlinx.serialization.json.Json
import org.keycloak.util.JsonSerialization
import java.util.*

class ClientAttestation(jwt: SignedJWT) {

    val issuer: String = jwt.jwtClaimsSet.issuer
    val subject: String = jwt.jwtClaimsSet.subject
    val expirationTime: Date = jwt.jwtClaimsSet.expirationTime
    val status: Status?
    val jwk: JWK

    init {
        val nowMillis = System.currentTimeMillis()
        require(jwt.state == JWSObject.State.SIGNED || jwt.state == JWSObject.State.VERIFIED) {
            "Client attestation JWT is not signed"
        }
        val typ = jwt.header.type?.type
        requireNotNull(typ) { "Missing JWT type" }
        require(typ == Spec.CLIENT_ATTESTATION_JWT_TYPE) { "Invalid JWT type" }
        requireNotNull(jwt.jwtClaimsSet.issuer) {
            "Missing issuer in client attestation JWT"
        }
        requireNotNull(jwt.jwtClaimsSet.subject) {
            "Missing subject in client attestation JWT"
        }
        requireNotNull(jwt.jwtClaimsSet.expirationTime) {
            "Missing expiration time in client attestation JWT"
        }
        require(expirationTime.time > nowMillis) {
            "Expired attestation JWT"
        }
        val cnf = jwt.jwtClaimsSet.getClaim(Spec.CNF_CLAIM) as Map<*, *>?
        requireNotNull(cnf) {
            "Missing cnf in client attestation JWT"
        }
        jwt.jwtClaimsSet.issueTime?.let {
            require(it.time <= nowMillis) {
                "Invalid issuance time in client attestation JWT"
            }
        }
        jwt.jwtClaimsSet.notBeforeTime?.let {
            require(it.time <= nowMillis) {
                "Invalid not before time in client attestation JWT"
            }
        }
        jwk = JWK.parse(JsonSerialization.writeValueAsString(cnf[Spec.JWK_CLAIM]))

        require(!jwk.isPrivate) {
            "JWK must not be private"
        }

        status = jwt.jwtClaimsSet.claims[Spec.STATUS_CLAIM]?.let { raw ->
            runCatching {
                val rawJson = JsonSerialization.writeValueAsString(raw)
                val json = Json { ignoreUnknownKeys = true }
                json.decodeFromString(Status.serializer(), rawJson)
            }.getOrNull()
        }
    }
}
