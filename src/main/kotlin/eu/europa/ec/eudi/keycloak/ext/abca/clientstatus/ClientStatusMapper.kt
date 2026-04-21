package eu.europa.ec.eudi.keycloak.ext.abca.clientstatus

import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.auth.ClientStatus
import kotlinx.serialization.json.Json
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
        token.otherClaims[TS3.EUDI_CLIENT_STATUS_CLAIM] = Json.decodeFromString<ClientStatus>(clientStatus)
        return token
    }
}
