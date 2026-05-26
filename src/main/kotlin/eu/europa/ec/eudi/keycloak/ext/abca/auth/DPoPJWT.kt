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
package eu.europa.ec.eudi.keycloak.ext.abca.auth

import arrow.core.raise.result
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jwt.SignedJWT

@JvmInline
value class DPoPJWT private constructor(val jwt: SignedJWT) {

    val jwk: JWK
        get() = jwt.requireJwkHeader()

    companion object {
        operator fun invoke(jwt: String): Result<DPoPJWT> =
            result {
                val jwt = SignedJWT.parse(jwt)
                with(jwt) {
                    requireIsSignedOrVerified()
                    requireJwkHeader()
                    verifySignatureWithHeaderJwk()
                }
                DPoPJWT(jwt)
            }
    }
}
private fun SignedJWT.requireJwkHeader(): JWK = requireNotNull(header.jwk) { "Missing jwk header" }
private fun SignedJWT.verifySignatureWithHeaderJwk() {
    val jwk = requireJwkHeader()
    require(jwk is ECKey) { "Unsupported key type: ${jwk.algorithm}" }

    val verifier = ECDSAVerifier(jwk)
    require(verify(verifier)) { "Invalid DPoP Proof signature" }
}
private fun SignedJWT.requireIsSignedOrVerified() =
    require(state == JWSObject.State.SIGNED || state == JWSObject.State.VERIFIED) {
        "DPoP JWT is not signed"
    }
