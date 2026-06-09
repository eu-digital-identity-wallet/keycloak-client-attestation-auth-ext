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

import com.fasterxml.jackson.core.type.TypeReference
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.auth.ClientStatus
import eu.europa.ec.eudi.keycloak.ext.abca.util.clientStatus
import kotlinx.serialization.json.Json
import org.keycloak.Config
import org.keycloak.models.*
import org.keycloak.protocol.ProtocolMapper
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenResponseMapper
import org.keycloak.protocol.oidc.mappers.TokenIntrospectionTokenMapper
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.AccessToken
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.util.JsonSerialization
import org.slf4j.LoggerFactory
import kotlin.time.Clock

private val logger = LoggerFactory.getLogger(ClientStatusProtocolMapper::class.java)

class ClientStatusProtocolMapper(private val clock: Clock = Clock.System) :
    ProtocolMapper,
    OIDCAccessTokenMapper,
    OIDCAccessTokenResponseMapper,
    TokenIntrospectionTokenMapper {
    override fun getProtocol(): String = OIDCLoginProtocol.LOGIN_PROTOCOL

    override fun getDisplayCategory(): String = "Token mapper"

    override fun getDisplayType(): String = "Client Status"

    override fun close() {
        // no-op
    }

    override fun create(session: KeycloakSession): ClientStatusProtocolMapper = ClientStatusProtocolMapper()

    override fun init(config: Config.Scope?) {
        // no-op
    }

    override fun postInit(factory: KeycloakSessionFactory?) {
        // no-op
    }

    override fun getId(): String = "client-status-protocol-mapper"

    override fun getHelpText(): String = "Maps the '${TS3.EUDI_CLIENT_STATUS_CLAIM}' Keycloak session attribute to the '${TS3.EUDI_CLIENT_STATUS_CLAIM}' claim of the token"

    override fun getConfigProperties(): List<ProviderConfigProperty> = emptyList()

    override fun transformAccessToken(
        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext,
    ): AccessToken {
        if (TS3.EUDI_CLIENT_STATUS_CLAIM in token.otherClaims) {
            logger.debug("AccessToken already contains ClientStatus")
            return token
        }

        val clientStatus = session.clientStatus
        if (null != clientStatus) {
            logger.debug("Adding ClientStatus to AccessToken")
            token.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = clientStatus.toJackson()
        }

        return token
    }

    override fun transformAccessTokenResponse(
        accessTokenResponse: AccessTokenResponse,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext,
    ): AccessTokenResponse {
        if (TS3.EUDI_CLIENT_STATUS_CLAIM in accessTokenResponse.otherClaims) {
            logger.debug("AccessTokenResponse already contains ClientStatus")
            return accessTokenResponse
        }

        val clientStatus = session.clientStatus
        if (null != clientStatus) {
            logger.debug("Adding ClientStatus to AccessTokenResponse")
            accessTokenResponse.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = clientStatus.toJackson()

            val clientStatusExpiresIn by lazy { clientStatus.expiresAt - clock.now() }
            accessTokenResponse.token?.let {
                logger.debug("Associating AccessToken with ClientStatus in Infinispan")
                session.singleUseObjects().put(
                    "$it.${TS3.EUDI_CLIENT_STATUS_CLAIM}",
                    clientStatusExpiresIn.inWholeSeconds,
                    mapOf(TS3.EUDI_CLIENT_STATUS_CLAIM to Json.encodeToString(clientStatus)),
                )
            }
            accessTokenResponse.refreshToken?.let {
                logger.debug("Associating RefreshToken with ClientStatus in Infinispan")
                session.singleUseObjects().put(
                    "$it.${TS3.EUDI_CLIENT_STATUS_CLAIM}",
                    clientStatusExpiresIn.inWholeSeconds,
                    mapOf(TS3.EUDI_CLIENT_STATUS_CLAIM to Json.encodeToString(clientStatus)),
                )
            }
        }

        return accessTokenResponse
    }

    override fun transformIntrospectionToken(
        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSessionCtx: ClientSessionContext,
    ): AccessToken {
        if (TS3.EUDI_CLIENT_STATUS_CLAIM in token.otherClaims) {
            logger.debug("Introspected AccessToken/RefreshToken already contains ClientStatus")
            return token
        }

        val formData = session.context.httpRequest.decodedFormParameters
        val introspectedToken = checkNotNull(formData.getFirst(Constants.TOKEN))

        val clientStatusNotes = session.singleUseObjects().get("$introspectedToken.${TS3.EUDI_CLIENT_STATUS_CLAIM}")
        if (null == clientStatusNotes) {
            logger.debug("No ClientStatus associated with introspected AccessToken/RefreshToken in Infinispan")
            return token
        }
        val clientStatus = Json.decodeFromString<ClientStatus>(checkNotNull(clientStatusNotes[TS3.EUDI_CLIENT_STATUS_CLAIM]))

        logger.debug("Adding ClientStatus to introspected AccessToken/RefreshToken")
        token.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = clientStatus.toJackson()
        return token
    }
}

private fun ClientStatus.toJackson(): Map<String, Any> =
    JsonSerialization.readValue(Json.encodeToString(this), object : TypeReference<Map<String, Any>>() {})
