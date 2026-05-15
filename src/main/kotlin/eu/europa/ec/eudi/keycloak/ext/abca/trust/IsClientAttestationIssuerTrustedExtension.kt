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

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.plugins.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonIgnoreUnknownKeys
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

fun IsClientAttestationIssuerTrusted.Companion.usingTrustValidatorService(
    httpClient: HttpClient,
    service: Url,
): IsClientAttestationIssuerTrusted = IsClientAttestationIssuerTrusted { x5c ->
    val body = TrustQueryRequest(x5c, "WalletInstanceAttestation")
    val trustResponse = runCatching {
        httpClient.post(service) {
            setBody(body)
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            expectSuccess = true
        }
    }.getOrElse {
        return@IsClientAttestationIssuerTrusted TrustResult.ServiceFailure
    }
    if (trustResponse.body<TrustResponse>().trusted) {
        TrustResult.IsTrusted
    } else {
        TrustResult.IsUntrusted
    }
}

val IsClientAttestationIssuerTrusted.Companion.Ignored: IsClientAttestationIssuerTrusted get() = IsClientAttestationIssuerTrusted {
    TrustResult.IsTrusted
}

@Serializable
private data class TrustQueryRequest(
    @Serializable(with = X509CertificateChainSerializer::class)
    val chain: List<X509Certificate>,
    val verificationContext: String,
)

private val base64 = Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)
private val certificateFactory = CertificateFactory.getInstance("X.509")
private object X509CertificateSerializer : KSerializer<X509Certificate> {

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("X509Certificate", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: X509Certificate) {
        val encoded = base64.encode(value.encoded)
        encoder.encodeString(encoded)
    }

    override fun deserialize(decoder: Decoder): X509Certificate {
        val cert = decoder.decodeString()
        val decoded = base64.decode(cert)
        return ByteArrayInputStream(decoded).use { inputStream ->
            certificateFactory.generateCertificate(inputStream) as X509Certificate
        }
    }
}
object X509CertificateChainSerializer : KSerializer<List<X509Certificate>> by ListSerializer(
    X509CertificateSerializer,
)

@Serializable
@JsonIgnoreUnknownKeys
private data class TrustResponse(
    @Required val trusted: Boolean,
)
