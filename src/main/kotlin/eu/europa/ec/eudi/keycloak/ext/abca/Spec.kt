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

object Spec {
    const val AUTHENTICATION_METHOD = "attest_jwt_client_auth"
    const val CLIENT_ATTESTATION_JWT_TYPE = "oauth-client-attestation+jwt"
    const val CLIENT_ATTESTATION_POP_JWT_TYPE = "oauth-client-attestation-pop+jwt"
    const val HEADER_CLIENT_ATTESTATION = "OAuth-Client-Attestation"
    const val HEADER_CLIENT_ATTESTATION_POP = "OAuth-Client-Attestation-PoP"

    // client attestation claims
    const val CNF_CLAIM = "cnf"
    const val CNF_JWK_CLAIM = "jwk"
    const val STATUS_CLAIM = "status"

    // client attestation pop claims
    const val CHALLENGE_CLAIM = "challenge"

    // challenge
    const val ATTESTATION_CHALLENGE = "attestation_challenge"

    // metadata
    const val CLIENT_ATTESTATION_SIGNING_ALG_VALUES_SUPPORTED = "client_attestation_signing_alg_values_supported"
    const val CLIENT_ATTESTATION_POP_SIGNING_ALG_VALUES_SUPPORTED = "client_attestation_pop_signing_alg_values_supported"
    const val CHALLENGE_ENDPOINT = "challenge_endpoint"

    // Errors
    const val USE_ATTESTATION_CHALLENGE_ERROR = "use_attestation_challenge"
    const val USE_FRESH_ATTESTATION_ERROR = "use_fresh_attestation"
    const val INVALID_CLIENT_ATTESTATION_ERROR = "invalid_client_attestation"
}
