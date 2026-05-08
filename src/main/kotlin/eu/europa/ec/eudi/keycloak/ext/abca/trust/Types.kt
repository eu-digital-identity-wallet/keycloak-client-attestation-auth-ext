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

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
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

@Serializable
enum class VerificationContext {
    @SerialName("WalletOrKeyStorageStatus")
    WALLET_OR_KEY_STORAGE_STATUS,

    @SerialName("WalletInstanceAttestation")
    WALLET_INSTANCE_ATTESTATION,
}

sealed interface TrustResult {
    object IsTrusted : TrustResult
    object IsUntrusted : TrustResult
    object ServiceFailure : TrustResult
}

@Serializable
internal data class TrustRequest(
    @Serializable(with = X509CertificateChainSerializer::class)
    val chain: List<X509Certificate>,
    val verificationContext: VerificationContext,
)

internal val base64 = Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)
internal val certificateFactory = CertificateFactory.getInstance("X.509")
internal object X509CertificateSerializer : KSerializer<X509Certificate> {

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
internal data class TrustResponse(
    @Required val trusted: Boolean,
)
