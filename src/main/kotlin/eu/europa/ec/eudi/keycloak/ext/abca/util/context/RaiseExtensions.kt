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
package eu.europa.ec.eudi.keycloak.ext.abca.util.context

import arrow.core.None
import arrow.core.raise.context.Raise
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import kotlin.contracts.contract

context(raise: Raise<None>)
fun ensure(condition: Boolean) {
    contract { returns() implies condition }
    raise.ensure(condition) { None }
}

context(raise: Raise<None>)
fun <T : Any> ensureNotNull(value: T?): T {
    contract { returns() implies (value != null) }
    return raise.ensureNotNull(value) { None }
}
