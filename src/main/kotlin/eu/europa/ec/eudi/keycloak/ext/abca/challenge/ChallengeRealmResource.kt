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
import eu.europa.ec.eudi.keycloak.ext.abca.util.provider
import io.ktor.http.*
import jakarta.ws.rs.HttpMethod
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.CacheControl
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.Provider
import org.keycloak.services.cors.Cors
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resource.RealmResourceProviderFactory
import java.util.*
import kotlin.time.Clock
import kotlin.time.toJavaInstant

interface ChallengeRealmResource {

    @Path("")
    @POST
    @Produces(MediaType.APPLICATION_JSON)
    fun generateNew(): Response
}

@Serializable
private data class ChallengeResponse(
    @Required @SerialName(AttestationBasedClientAuthentication.ATTESTATION_CHALLENGE_CLAIM) val challenge: Challenge,
)

class DefaultChallengeRealmResource(
    session: KeycloakSession,
    private val clock: Clock = Clock.System,
) : ChallengeRealmResource {
    private val challengeHandler = session.provider<ChallengeHandler>()
    private val cors = Cors.builder()
        .allowAllOrigins()
        .allowedMethods(HttpMethod.POST)

    override fun generateNew(): Response {
        val challenge = runBlocking {
            challengeHandler.generateNew()
        }
        val challengeResponse = ChallengeResponse(challenge)

        val builder = Response.ok(Json.encodeToString(challengeResponse), MediaType.APPLICATION_JSON)
            .cacheControl(
                CacheControl()
                    .apply {
                        isPrivate = false
                        isNoCache = true
                        isNoStore = true
                        isNoTransform = true
                        isMustRevalidate = true
                        isProxyRevalidate = true
                    },
            )
            .header(HttpHeaders.Pragma, "no-cache")
            .expires(Date.from(clock.now().toJavaInstant()))
        return cors.add(builder)
    }
}

class ChallengeRealmResourceProvider(private val session: KeycloakSession) : RealmResourceProvider {
    override fun getResource(): ChallengeRealmResource = DefaultChallengeRealmResource(session)

    override fun close() {
        // no-op
    }
}

class ChallengeRealmResourceProviderFactory : RealmResourceProviderFactory {
    override fun create(session: KeycloakSession): ChallengeRealmResourceProvider = ChallengeRealmResourceProvider(session)

    override fun init(config: Config.Scope) {
        // no-op
    }

    override fun postInit(factory: KeycloakSessionFactory) {
        // no-op
    }

    override fun close() {
        // no-op
    }

    override fun getId(): String = ID

    override fun dependsOn(): Set<Class<out Provider>> = setOf(ChallengeHandler::class.java)

    companion object {
        const val ID = "challenge"
    }
}
