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

import com.nimbusds.jose.JWSAlgorithm

/**
 * [OAuth 2.0 Attestation-Based Client Authentication](https://www.ietf.org/archive/id/draft-ietf-oauth-attestation-based-client-auth-07.html)
 */
object AttestationBasedClientAuthentication {
    // Client authentication method
    const val AUTHENTICATION_METHOD = "attest_jwt_client_auth"

    // JWT types
    const val CLIENT_ATTESTATION_JWT_TYPE = "oauth-client-attestation+jwt"
    const val CLIENT_ATTESTATION_POP_JWT_TYPE = "oauth-client-attestation-pop+jwt"

    // HTTP Headers
    const val CLIENT_ATTESTATION_HEADER = "OAuth-Client-Attestation"
    const val CLIENT_ATTESTATION_POP_HEADER = "OAuth-Client-Attestation-PoP"
    const val CLIENT_ATTESTATION_CHALLENGE_HEADER = "OAuth-Client-Attestation-Challenge"

    // Claims
    const val CHALLENGE_CLAIM = "challenge"
    const val ATTESTATION_CHALLENGE_CLAIM = "attestation_challenge"

    // OAuth2 Authorization Server Metadata
    const val CLIENT_ATTESTATION_SUPPORTED_SIGNING_ALGORITHMS = "client_attestation_signing_alg_values_supported"
    const val CLIENT_ATTESTATION_POP_SUPPORTED_SIGNING_ALGORITHMS = "client_attestation_pop_signing_alg_values_supported"
    const val CHALLENGE_ENDPOINT = "challenge_endpoint"

    // Errors
    const val USE_ATTESTATION_CHALLENGE_ERROR = "use_attestation_challenge"
    const val USE_FRESH_ATTESTATION_ERROR = "use_fresh_attestation"
    const val INVALID_CLIENT_ATTESTATION_ERROR = "invalid_client_attestation"
}

/**
 * [Specification of Wallet Unit Attestations (WUA) used in issuance of PID and Attestations](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
 */
object TS3 {
    const val EUDI_WALLET_VERSION_CLAIM = "wallet_version"
    const val EUDI_WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM = "wallet_solution_certification_information"
    const val EUDI_CLIENT_STATUS_CLAIM = "client_status"

    val ALLOWED_ALGORITHMS = setOf(JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512)
}

/**
 * [SON Web Token (JWT)](https://www.rfc-editor.org/info/rfc7519/)
 */
object RFC7519 {
    const val EXPIRES_AT_CLAIM = "exp"
}

/**
 * [OpenID for Verifiable Credential Issuance 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
 */
object OpenId4VCI {
    const val WALLET_NAME_CLAIM = "wallet_name"
    const val WALLET_LINK_CLAIM = "wallet_link"
}

/**
 * [Token Status List (TSL)](https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-12.html)
 */
object TokenStatusList {
    const val STATUS_CLAIM = "status"

    const val STATUS_LIST_CLAIM = "status_list"
    const val INDEX_CLAIM = "idx"
    const val URI_CLAIM = "uri"
}

/**
 * [Proof-of-Possession Key Semantics for JSON Web Tokens (JWTs)](https://datatracker.ietf.org/doc/html/rfc7800)
 */
object RFC7800 {
    const val CONFIRMATION_CLAIM = "cnf"
    const val JWK_METHOD_CLAIM = "jwk"
}
