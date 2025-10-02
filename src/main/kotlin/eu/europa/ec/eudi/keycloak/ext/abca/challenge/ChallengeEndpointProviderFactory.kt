package eu.europa.ec.eudi.keycloak.ext.abca.challenge

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resource.RealmResourceProviderFactory

class ChallengeEndpointProviderFactory : RealmResourceProviderFactory {

    override fun create(session: KeycloakSession): RealmResourceProvider = ChallengeEndpointProvider(session)

    override fun init(config: Config.Scope?) {
        // no-op
    }

    override fun postInit(factory: KeycloakSessionFactory?) {
        // no-op
    }

    // Mount under /realms/{realm}/challenge
    override fun getId(): String = "challenge"

    override fun close() {
        // no-op
    }
}
