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
import io.ktor.client.HttpClient
import io.ktor.http.Url
import java.security.cert.X509Certificate

fun interface IsClientAttestationIssuerTrusted {
    suspend operator fun invoke(x5c: NonEmptyList<X509Certificate>): TrustResult
    companion object
}

fun IsClientAttestationIssuerTrusted.Companion.usingTrustValidatorService(
    httpClient: HttpClient,
    service: Url,
): IsClientAttestationIssuerTrusted = IsClientAttestationIssuerTrusted { x5c ->
    httpClient.validateTrust(service, x5c, VerificationContext.WALLET_INSTANCE_ATTESTATION)
}

val IsClientAttestationIssuerTrusted.Companion.Ignored: IsClientAttestationIssuerTrusted get() = IsClientAttestationIssuerTrusted {
    TrustResult.IsTrusted
}
