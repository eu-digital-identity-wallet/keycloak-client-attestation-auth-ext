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

import com.nimbusds.jose.jwk.JWK
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

object JWKJsonObjectSerializer : KSerializer<JWK> {
    private val serializer = JsonObject.serializer()

    override val descriptor: SerialDescriptor = SerialDescriptor("JWKJsonObject", serializer.descriptor)

    override fun serialize(encoder: Encoder, value: JWK) {
        val serialized = Json.decodeFromString<JsonObject>(value.toJSONString())
        encoder.encodeSerializableValue(serializer, serialized)
    }

    override fun deserialize(decoder: Decoder): JWK {
        val serialized = decoder.decodeSerializableValue(serializer)
        return JWK.parse(Json.encodeToString(serialized))
    }
}

typealias JsonObjectJWK =
    @Serializable(with = JWKJsonObjectSerializer::class)
    JWK
