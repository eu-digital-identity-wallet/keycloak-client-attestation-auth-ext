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

import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.wellknown.WellKnownProvider
import org.keycloak.wellknown.WellKnownProviderFactory
import java.util.*

/**
 * Augments the OAuth 2.0 Authorization Server Metadata
 * (/.well-known/oauth-authorization-server)
 * by adding:
 * - challenge_endpoint: URL to the realm challenge endpoint
 * - token_endpoint_auth_methods_supported: includes attest_jwt_client_auth
 * - client_attestation_signing_alg_values_supported: JWA algs for client attestation JWTs
 * - client_attestation_pop_signing_alg_values_supported: JWA algs for PoP JWTs bound to the attestation key
 */
class AttestationBasedClientAuthenticationWellKnownProviderFactory : WellKnownProviderFactory {
    override fun create(session: KeycloakSession): WellKnownProvider {
        // Find the default provider factory for oauth-authorization-server via ServiceLoader and delegate to it
        val loader = ServiceLoader.load(WellKnownProviderFactory::class.java, this::class.java.classLoader)
        val delegateFactory = loader.firstOrNull { it.id == "oauth-authorization-server" && it::class.java != this::class.java }
            ?: throw IllegalStateException("Default oauth-authorization-server WellKnownProviderFactory not found")
        val defaultProvider = delegateFactory.create(session)
        return AttestationBasedClientAuthenticationWellKnownProvider(defaultProvider, session)
    }

    override fun getId(): String = "oauth-authorization-server"

    override fun init(config: Config.Scope?) { /* no-op */ }

    override fun postInit(factory: KeycloakSessionFactory?) { /* no-op */ }

    override fun close() { /* no-op */ }
}
