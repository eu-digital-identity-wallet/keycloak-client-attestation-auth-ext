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
