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
package eu.europa.ec.eudi.keycloak.ext.abca.challenge

import kotlinx.serialization.Serializable

@Serializable
@JvmInline
value class Challenge private constructor(val value: String) {
    init {
        check(value.isNotBlank())
    }

    override fun toString(): String = value

    companion object {
        fun ofOrNull(value: String): Challenge? = value.takeIf { it.isNotBlank() }?.let(::Challenge)
        fun of(value: String): Challenge = ofOrNull(value) ?: throw IllegalArgumentException("value cannot be blank")
    }
}

fun String.toChallengeOrNull(): Challenge? = Challenge.ofOrNull(this)
fun String.toChallenge(): Challenge = Challenge.of(this)
