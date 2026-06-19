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

import arrow.core.NonEmptyList
import arrow.core.toNonEmptyListOrNull
import com.eygraber.uri.Uri
import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier
import com.nimbusds.jose.proc.JWSVerificationKeySelector
import com.nimbusds.jose.proc.SecurityContext
import com.nimbusds.jose.util.X509CertUtils
import com.nimbusds.jwt.SignedJWT
import com.nimbusds.jwt.proc.DefaultJWTProcessor
import eu.europa.ec.eudi.keycloak.ext.abca.TokenStatusList
import eu.europa.ec.eudi.keycloak.ext.abca.trust.IsClientStatusIssuerTrusted
import eu.europa.ec.eudi.keycloak.ext.abca.trust.TrustResult
import eu.europa.ec.eudi.statium.GetStatus
import eu.europa.ec.eudi.statium.GetStatusListToken
import eu.europa.ec.eudi.statium.StatusIndex
import eu.europa.ec.eudi.statium.StatusReference
import io.ktor.client.*
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import java.security.cert.X509Certificate
import kotlin.time.Clock
import eu.europa.ec.eudi.statium.Status as StatiumStatus

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

suspend fun Status.verifyStatus(httpClient: HttpClient, isClientStatusIssuerTrusted: IsClientStatusIssuerTrusted): StatiumStatus {
    val getStatusListToken = GetStatusListToken.usingJwt(
        clock = Clock.System,
        httpClient = httpClient,
        verifyStatusListTokenSignature = { serializedStatusListToken, _ ->
            runCatching {
                val statusListToken = SignedJWT.parse(serializedStatusListToken)
                val signingCertificate = statusListToken.header.x5c()

                statusListToken.verify(signingCertificate.first())

                val trustResult = isClientStatusIssuerTrusted(signingCertificate)
                require(trustResult == TrustResult.IsTrusted) {
                    "Status List Token issuer is not trusted"
                }
            }
        },
    )

    val getStatus = GetStatus(getStatusListToken)
    val statusReference = StatusReference(
        index = StatusIndex(statusList.index.toInt()),
        uri = statusList.uri.toString(),
    )
    return with(getStatus) {
        statusReference.status(at = null).getOrThrow()
    }
}

private fun JWSHeader.x5c(): NonEmptyList<X509Certificate> {
    val decode = x509CertChain
        .orEmpty()
        .map { requireNotNull(X509CertUtils.parse(it.decode())) }
        .toNonEmptyListOrNull()

    requireNotNull(decode) { "x5c must not be empty" }

    return decode
}

private fun SignedJWT.verify(signingCertificate: X509Certificate) {
    val signingKey = JWK.parse(signingCertificate)
    DefaultJWTProcessor<SecurityContext>().apply {
        jwsTypeVerifier = DefaultJOSEObjectTypeVerifier(JOSEObjectType("statuslist+jwt"))
        jwsKeySelector = JWSVerificationKeySelector(
            header.algorithm,
            ImmutableJWKSet(JWKSet(signingKey)),
        )
    }.also {
        it.process(this, null)
    }
}
