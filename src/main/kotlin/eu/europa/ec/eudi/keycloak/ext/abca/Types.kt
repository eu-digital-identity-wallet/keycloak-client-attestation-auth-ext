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
package eu.europa.ec.eudi.keycloak.ext.abca

import kotlinx.serialization.Serializable

@Serializable
@JvmInline
value class NonBlankString private constructor(val value: String) {
    init {
        check(value.isNotBlank())
    }

    companion object {
        fun ofOrNull(value: String): NonBlankString? = value.takeIf { it.isNotBlank() }?.let(::NonBlankString)
        fun of(value: String): NonBlankString = ofOrNull(value) ?: throw IllegalArgumentException("value cannot be blank")
    }
}

fun String.toNonBlankStringOrNull(): NonBlankString? = NonBlankString.ofOrNull(this)
fun String.toNonBlankString(): NonBlankString = NonBlankString.of(this)
