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
package eu.europa.ec.eudi.keycloak.ext.abca.clientstatus

import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import arrow.core.raise.option
import com.fasterxml.jackson.core.type.TypeReference
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.auth.ClientStatus
import eu.europa.ec.eudi.keycloak.ext.abca.util.clientStatus
import kotlinx.serialization.json.Json
import org.keycloak.models.*
import org.keycloak.protocol.oidc.mappers.*
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.AccessToken
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.util.JsonSerialization
import org.slf4j.LoggerFactory
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

private val LOGGER = LoggerFactory.getLogger(ClientStatusProtocolMapper::class.java)

class ClientStatusProtocolMapper(private val clock: Clock = Clock.System) :
    AbstractOIDCProtocolMapper(),
    OIDCAccessTokenMapper,
    OIDCAccessTokenResponseMapper,
    TokenIntrospectionTokenMapper {

    override fun getDisplayCategory(): String = TOKEN_MAPPER_CATEGORY

    override fun getDisplayType(): String = "Client Status"

    override fun getId(): String = "client-status-protocol-mapper"

    override fun getHelpText(): String = "Maps the '${TS3.EUDI_CLIENT_STATUS_CLAIM}' Keycloak session attribute to the '${TS3.EUDI_CLIENT_STATUS_CLAIM}' claim of the token"

    override fun getConfigProperties(): List<ProviderConfigProperty> = buildList {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(this, ClientStatusProtocolMapper::class.java)
    }

    override fun transformAccessToken(
        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext,
    ): AccessToken = either {
        ensure(TS3.EUDI_CLIENT_STATUS_CLAIM !in token.otherClaims) { "AccessToken already contains ClientStatus" }

        val useLightweightAccessToken = getShouldUseLightweightToken(session)
        val includeInAccessToken =
            if (useLightweightAccessToken) {
                OIDCAttributeMapperHelper.includeInLightweightAccessToken(mappingModel)
            } else {
                OIDCAttributeMapperHelper.includeInAccessToken(mappingModel)
            }
        ensure(includeInAccessToken) { "$id is configured NOT to include ClientStatus in AccessToken" }

        val clientStatus = ensureNotNull(session.clientStatus) { "ClientStatus NOT found in KeycloakSession" }

        LOGGER.info("Adding ClientStatus to AccessToken")
        token.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = clientStatus.toJackson()

        token
    }.getOrElse {
        LOGGER.warn("ClientStatus NOT added to AccessToken: {}", it)
        token
    }

    override fun transformAccessTokenResponse(
        accessTokenResponse: AccessTokenResponse,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext,
    ): AccessTokenResponse = either {
        val clientStatus = ensureNotNull(session.clientStatus) { "ClientStatus NOT found in KeycloakSession" }
        context(session, clock) {
            clientStatus.associateWithAccessTokenOf(accessTokenResponse)
        }

        ensure(TS3.EUDI_CLIENT_STATUS_CLAIM !in accessTokenResponse.otherClaims) { "AccessTokenResponse already contains ClientStatus" }
        ensure(OIDCAttributeMapperHelper.includeInAccessTokenResponse(mappingModel)) {
            "$id is configured NOT to include ClientStatus in AccessTokenResponse"
        }

        LOGGER.info("Adding ClientStatus to AccessTokenResponse")
        accessTokenResponse.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = clientStatus.toJackson()

        accessTokenResponse
    }.getOrElse {
        LOGGER.warn("ClientStatus NOT added to AccessTokenResponse: {}", it)
        accessTokenResponse
    }

    override fun transformIntrospectionToken(
        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext,
    ): AccessToken = either {
        ensure(TS3.EUDI_CLIENT_STATUS_CLAIM !in token.otherClaims) { "Introspected AccessToken/RefreshToken already contains ClientStatus" }
        ensure(OIDCAttributeMapperHelper.includeInIntrospection(mappingModel)) {
            "$id is configured NOT to include ClientStatus in introspected AccessToken/RefreshToken"
        }

        val formData = checkNotNull(session.context.httpRequest.decodedFormParameters)
        val introspectedToken = checkNotNull(formData.getFirst(Constants.TOKEN))

        val clientStatusNotes = ensureNotNull(session.singleUseObjects().get(introspectedToken.toInfinispanKey())) {
            "NO ClientStatus associated with introspected AccessToken/RefreshToken in Infinispan"
        }
        val clientStatus = Json.decodeFromString<ClientStatus>(checkNotNull(clientStatusNotes[CLIENT_STATUS_NOTE_KEY]))

        LOGGER.info("Adding ClientStatus to introspected AccessToken/RefreshToken")
        token.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = clientStatus.toJackson()

        token
    }.getOrElse {
        LOGGER.warn("ClientStatus NOT added to introspected AccessToken/RefreshToken: {}", it)
        token
    }
}

private fun ClientStatus.toJackson(): Map<String, Any> = JsonSerialization.readValue(Json.encodeToString(this), object : TypeReference<Map<String, Any>>() {})

private const val CLIENT_STATUS_NOTE_KEY = TS3.EUDI_CLIENT_STATUS_CLAIM

private fun String.toInfinispanKey(): String = "$this.${CLIENT_STATUS_NOTE_KEY}"

context(session: KeycloakSession, clock: Clock)
private fun ClientStatus.associateWithAccessTokenOf(accessTokenResponse: AccessTokenResponse): Unit = either {
    val accessToken = ensureNotNull(accessTokenResponse.token) { "No AccessToken found in AccessTokenResponse" }
    LOGGER.debug("Associating AccessToken with ClientStatus in Infinispan")

    val lifespan = option {
        val lifespan = accessTokenResponse.expiresIn.seconds
        ensure(lifespan.isPositive())
        lifespan
    }.getOrElse {
        val clientStatusExpiresIn = expiresAt - clock.now()
        clientStatusExpiresIn
    }
    check(lifespan.isPositive())

    session.singleUseObjects().put(
        accessToken.toInfinispanKey(),
        lifespan.inWholeSeconds,
        mapOf(CLIENT_STATUS_NOTE_KEY to Json.encodeToString(this@associateWithAccessTokenOf)),
    )
}.getOrElse {
    LOGGER.warn("ClientStatus NOT associated with AccessToken of AccessTokenResponse: {}", it)
}
