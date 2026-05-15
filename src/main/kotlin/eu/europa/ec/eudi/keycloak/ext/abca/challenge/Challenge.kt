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
