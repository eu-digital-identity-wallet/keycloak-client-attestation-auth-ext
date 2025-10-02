package eu.europa.ec.eudi.keycloak.ext.abca.challenge

import org.keycloak.models.KeycloakSession
import org.keycloak.services.resource.RealmResourceProvider

class ChallengeEndpointProvider(private val session: KeycloakSession) : RealmResourceProvider {

    override fun getResource(): Any = ChallengeEndpoint(session)

    override fun close() {
        // nothing to close
    }
}
