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
package eu.europa.ec.eudi.keycloak.ext.abca.trustvalidator

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import com.eygraber.uri.Url
import eu.europa.ec.eudi.keycloak.ext.abca.serialization.Base64X509Certificate
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys

fun interface TrustValidator {
    suspend fun isTrusted(chain: NonEmptyList<Base64X509Certificate>, context: VerificationContext): Boolean

    companion object {
        val Ignored = TrustValidator { _, _ -> true }
    }
}

@Serializable
enum class VerificationContext {
    @SerialName("WalletOrKeyStorageStatus")
    WALLET_OR_KEY_STORAGE_STATUS,

    @SerialName("WalletInstanceAttestation")
    WALLET_INSTANCE_ATTESTATION,
}

fun TrustValidator(
    httpClient: HttpClient,
    service: Url,
): TrustValidator = TrustValidator { chain, context -> httpClient.isTrusted(service, chain, context) }

private suspend fun HttpClient.isTrusted(
    service: Url,
    chain: NonEmptyList<Base64X509Certificate>,
    context: VerificationContext,
): Boolean = post(service.toString()) {
    setBody(TrustRequest(chain, context))
    contentType(ContentType.Application.Json)
    accept(ContentType.Application.Json)
    expectSuccess = true
}.body<TrustResponse>().trusted

@Serializable
private data class TrustRequest(
    @Required @SerialName("chain") @Serializable(with = NonEmptyListSerializer::class) val chain: NonEmptyList<Base64X509Certificate>,
    @Required @SerialName("verificationContext") val verificationContext: VerificationContext,
)

@Serializable
@JsonIgnoreUnknownKeys
internal data class TrustResponse(
    @Required @SerialName("trusted") val trusted: Boolean,
)
