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
package eu.europa.ec.eudi.keycloak.ext.abca.wellknown

import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeRealmResourceProviderFactory
import eu.europa.ec.eudi.keycloak.ext.abca.util.context.invoke
import eu.europa.ec.eudi.keycloak.ext.abca.util.context.isEnabled
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.services.Urls
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.protocol.oauth2.OAuth2WellKnownProviderFactory as KeycloakOAuth2WellKnownProviderFactory
import org.keycloak.protocol.oidc.OIDCWellKnownProvider as KeycloakOIDCWellKnownProvider
import org.keycloak.protocol.oidc.OIDCWellKnownProviderFactory as KeycloakOIDCWellKnownProviderFactory
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation as KeycloakOIDCConfigurationRepresentation

class OIDCWellKnownProvider(
    private val session: KeycloakSession,
    openidConfigOverride: Map<String, Any?>?,
    includeClientScopes: Boolean,
) : KeycloakOIDCWellKnownProvider(session, openidConfigOverride, includeClientScopes) {
    override fun getConfig(): OIDCConfigurationRepresentation = session {
        OIDCConfigurationRepresentation(super.config as KeycloakOIDCConfigurationRepresentation)
            .apply {
                if (isEnabled<RealmResourceProvider>(ChallengeRealmResourceProviderFactory.ID)) {
                    challengeEndpoint = Urls.realmBase(session.context.uri.baseUri)
                        .path("{realm}")
                        .path(ChallengeRealmResourceProviderFactory.ID)
                        .build(session.context.realm.name)
                        .toString()
                }

                if (AttestationBasedClientAuthentication.AUTHENTICATION_METHOD in tokenEndpointAuthMethodsSupported) {
                    val algorithms = TS3.ALLOWED_ALGORITHMS
                        .filter { it.isEnabled() }
                        .map { it.name }

                    clientAttestationSigningAlgValuesSupported = algorithms
                    clientAttestationPoPSigningAlgValuesSupported = algorithms
                }
            }
    }
}

class OIDCWellKnownProviderFactory : KeycloakOIDCWellKnownProviderFactory() {
    private var includeClientScopes: Boolean = true

    override fun create(session: KeycloakSession): OIDCWellKnownProvider = OIDCWellKnownProvider(session, openidConfigOverride, includeClientScopes)

    override fun init(config: Config.Scope) {
        super.init(config)
        includeClientScopes = config.getBoolean("include-client-scopes", true)
    }

    override fun getPriority(): Int = super.priority + 1

    override fun isAvailableViaServerMetadata(): Boolean = true
}

class OAuth2WellKnownProviderFactory : KeycloakOAuth2WellKnownProviderFactory() {
    private var includeClientScopes: Boolean = true

    override fun create(session: KeycloakSession): OIDCWellKnownProvider = OIDCWellKnownProvider(session, openidConfigOverride, includeClientScopes)

    override fun init(config: Config.Scope) {
        super.init(config)
        includeClientScopes = config.getBoolean("include-client-scopes", true)
    }

    override fun getPriority(): Int = super.priority + 1

    override fun isAvailableViaServerMetadata(): Boolean = true
}
