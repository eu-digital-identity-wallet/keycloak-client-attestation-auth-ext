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
package eu.europa.ec.eudi.keycloak.ext.abca.trust

import arrow.core.NonEmptyList
import com.eygraber.uri.Url
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import java.security.cert.X509Certificate

internal suspend fun HttpClient.validateTrust(serviceUrl: Url, x5c: NonEmptyList<X509Certificate>, verificationContext: VerificationContext): TrustResult {
    val body = TrustRequest(x5c, verificationContext)
    val isTrusted = runCatching {
        val trustResponse = post(serviceUrl.toString()) {
            setBody(body)
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            expectSuccess = true
        }
        trustResponse.body<TrustResponse>().trusted
    }.getOrElse {
        return@validateTrust TrustResult.ServiceFailure
    }
    return if (isTrusted) {
        TrustResult.IsTrusted
    } else {
        TrustResult.IsUntrusted
    }
}
