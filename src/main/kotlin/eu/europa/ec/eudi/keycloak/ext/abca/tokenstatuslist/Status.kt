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
package eu.europa.ec.eudi.keycloak.ext.abca.tokenstatuslist

import com.eygraber.uri.Uri
import eu.europa.ec.eudi.keycloak.ext.abca.TokenStatusList
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

@Serializable
@JsonIgnoreUnknownKeys
data class Status(
    @Required @SerialName(TokenStatusList.STATUS_LIST_CLAIM) val statusList: StatusList,
)

@Serializable
data class StatusList(
    @Required @SerialName(TokenStatusList.INDEX_CLAIM) val index: UInt,
    @Required @SerialName(TokenStatusList.URI_CLAIM) val uri: Uri,
)
