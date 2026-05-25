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

import com.nimbusds.jose.util.JSONObjectUtils
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.mappers.AbstractOIDCProtocolMapper
import org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.representations.AccessToken

class ClientStatusMapper : AbstractOIDCProtocolMapper(), OIDCAccessTokenMapper {
    override fun getDisplayCategory(): String = "Client Status Mapper"
    override fun getDisplayType(): String = "Client Status Mapper"
    override fun getHelpText(): String = "Maps the client status from the session note to the access token"
    override fun getConfigProperties(): List<ProviderConfigProperty> = listOf()

    override fun getId(): String = "client-status-mapper"

    override fun transformAccessToken(
        token: AccessToken,
        mappingModel: ProtocolMapperModel,
        session: KeycloakSession,
        userSession: UserSessionModel,
        clientSession: ClientSessionContext,
    ): AccessToken {
        val clientStatus = requireNotNull(clientSession.clientSession.userSession.notes[TS3.EUDI_CLIENT_STATUS_CLAIM]) {
            "client_status not found in user session"
        }
        token.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = JSONObjectUtils.parse(clientStatus)
        return token
    }
}
