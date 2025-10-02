package eu.europa.ec.eudi.keycloak.ext.abca.challenge

import eu.europa.ec.eudi.keycloak.ext.abca.wellknown.AttestationBasedClientAuthenticationWellKnownProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.protocol.oid4vc.issuance.keybinding.CNonceHandler
import org.keycloak.protocol.oid4vc.issuance.keybinding.JwtCNonceHandler

@JvmInline
value class Challenge(val value: String) {
    init {
        require(value.isNotBlank()) { "Challenge must not be blank" }
    }

    companion object {
        operator fun invoke(session: KeycloakSession): Challenge = Challenge(session.challenge())
    }

    fun verify(session: KeycloakSession) = session.verifyChallenge(value)
}

internal fun KeycloakSession.challenge(): String {
    return cNonceHandler().buildCNonce(
        listOf(audience()),
        mapOf(JwtCNonceHandler.SOURCE_ENDPOINT to sourceEndpoint()),
    )
}

internal fun KeycloakSession.verifyChallenge(challenge: String) {
    cNonceHandler().verifyCNonce(
        challenge,
        listOf(audience()),
        mapOf(JwtCNonceHandler.SOURCE_ENDPOINT to sourceEndpoint()),
    )
}

internal fun KeycloakSession.sourceEndpoint() = AttestationBasedClientAuthenticationWellKnownProvider.challengeEndpoint(context)
internal fun KeycloakSession.audience() = AttestationBasedClientAuthenticationWellKnownProvider.issuer(context)
internal fun KeycloakSession.cNonceHandler() = getProvider(CNonceHandler::class.java) ?: error("No CNonceHandler found")
