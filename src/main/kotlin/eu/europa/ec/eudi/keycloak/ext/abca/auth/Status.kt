package eu.europa.ec.eudi.keycloak.ext.abca.auth

import eu.europa.ec.eudi.statium.GetStatus
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.statium.StatusIndex
import eu.europa.ec.eudi.statium.StatusReference
import io.ktor.client.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.time.Clock

@Serializable
data class StatusList(
    @SerialName("idx") @Required val index: Int,
    @SerialName("uri") @Required val uri: String,
)

@Serializable
data class Status(
    @SerialName("status_list") val statusList: StatusList,
) {

    internal suspend fun verifyStatus(httpClient: HttpClient): eu.europa.ec.eudi.statium.Status {
        val getStatusListToken = GetStatusListToken.usingJwt(
            clock = Clock.System,
            httpClient = httpClient,
            verifyStatusListTokenSignature = { _, _ ->
                Result.success(Unit) // TODO
            },
        )
        val getStatus = GetStatus(getStatusListToken)
        val statusReference = StatusReference(
            index = StatusIndex(this.statusList.index),
            uri = this.statusList.uri,
        )
        return with(getStatus) {
            statusReference.status(at = null).getOrThrow()
        }
    }
}
