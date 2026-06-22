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
package eu.europa.ec.eudi.keycloak.ext.abca.serialization

import com.nimbusds.jose.util.X509CertUtils
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import java.security.cert.X509Certificate
import kotlin.io.encoding.Base64

object X509CertificateBase64Serializer : KSerializer<X509Certificate> {
    private val base64 = Base64.withPadding(Base64.PaddingOption.ABSENT_OPTIONAL)

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("X509CertificateBase64", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: X509Certificate) {
        encoder.encodeString(base64.encode(value.encoded))
    }

    override fun deserialize(decoder: Decoder): X509Certificate = X509CertUtils.parseWithException(base64.decode(decoder.decodeString()))
}

typealias Base64X509Certificate =
    @Serializable(with = X509CertificateBase64Serializer::class)
    X509Certificate
