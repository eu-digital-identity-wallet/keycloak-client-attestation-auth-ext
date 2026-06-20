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
package eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation

import com.nimbusds.jwt.SignedJWT
import eu.europa.ec.eudi.statium.*
import io.ktor.client.*
import kotlin.time.Clock
import kotlin.time.Duration

class ClientStatusValidator(
    private val httpClient: HttpClient,
    private val clock: Clock,
    private val skew: Duration,
    private val isSignatureValid: suspend (SignedJWT) -> Boolean,
) {
    init {
        require(Duration.ZERO == skew || skew.isPositive())
    }

    suspend fun isValid(clientStatus: ClientStatus): Boolean {
        val getStatusListToken = GetStatusListToken.usingJwt(
            clock,
            httpClient,
            verifyStatusListTokenSignature = { serializedStatusListToken, _ ->
                val statusListToken = SignedJWT.parse(serializedStatusListToken)
                if (isSignatureValid(statusListToken)) {
                    Result.success(Unit)
                } else {
                    Result.failure(IllegalArgumentException("Status List Token signature is not valid"))
                }
            },
            skew,
        )

        val status = with(GetStatus(getStatusListToken)) {
            with(clientStatus.status.statusList) {
                StatusReference(StatusIndex(index.toInt()), uri.toString())
                    .status(null)
                    .getOrThrow()
            }
        }
        return Status.Valid == status
    }
}
