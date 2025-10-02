package eu.europa.ec.eudi.keycloak.ext.abca.challenge

import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import jakarta.ws.rs.GET
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.CacheControl
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.models.KeycloakSession

class ChallengeEndpoint(private val session: KeycloakSession) {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    fun getChallenge(): Response {
        val entity = mapOf(
            Spec.ATTESTATION_CHALLENGE to Challenge(session).value,
        )

        // Ensure the response is never cached by intermediaries or clients
        val cacheControl = CacheControl().apply {
            isNoStore = true
            isNoCache = true
            isMustRevalidate = true
            isPrivate = false
        }

        return Response.ok(entity)
            .cacheControl(cacheControl)
            .header("Pragma", "no-cache")
            .build()
    }
}
