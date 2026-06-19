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

import arrow.core.NonEmptyList
import arrow.core.serialization.NonEmptyListSerializer
import eu.europa.ec.eudi.keycloak.ext.abca.NonBlankString
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonTransformingSerializer

object AudienceSerializer : JsonTransformingSerializer<NonEmptyList<NonBlankString>>(NonEmptyListSerializer(NonBlankString.serializer())) {
    override fun transformSerialize(element: JsonElement): JsonElement = when (element) {
        is JsonArray ->
            if (1 == element.size) {
                element.first()
            } else {
                element
            }

        else -> element
    }

    override fun transformDeserialize(element: JsonElement): JsonElement = when (element) {
        !is JsonArray -> JsonArray(listOf(element))
        else -> element
    }
}

typealias Audience =
    @Serializable(with = AudienceSerializer::class)
    NonEmptyList<NonBlankString>
