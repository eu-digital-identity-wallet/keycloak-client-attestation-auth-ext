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

import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.CacheControl
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.models.KeycloakSession

class ChallengeEndpoint(private val session: KeycloakSession) {

    @POST
    @Path("")
    @Produces(MediaType.APPLICATION_JSON)
    fun getChallenge(): Response {
        val entity = mapOf(
            AttestationBasedClientAuthentication.ATTESTATION_CHALLENGE to Challenge(session).value,
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
