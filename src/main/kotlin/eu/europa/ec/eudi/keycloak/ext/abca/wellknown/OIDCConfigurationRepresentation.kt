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
package eu.europa.ec.eudi.keycloak.ext.abca.wellknown

import com.fasterxml.jackson.annotation.JsonProperty
import eu.europa.ec.eudi.keycloak.ext.abca.AttestationBasedClientAuthentication
import org.keycloak.util.JsonSerialization
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation as KeycloakOIDCConfigurationRepresentation

class OIDCConfigurationRepresentation(
    @JsonProperty(AttestationBasedClientAuthentication.CHALLENGE_ENDPOINT)
    var challengeEndpoint: String? = null,

    @JsonProperty(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_SIGNING_ALG_VALUES_SUPPORTED)
    var clientAttestationSigningAlgValuesSupported: List<String>? = null,

    @JsonProperty(AttestationBasedClientAuthentication.CLIENT_ATTESTATION_POP_SIGNING_ALG_VALUES_SUPPORTED)
    var clientAttestationPoPSigningAlgValuesSupported: List<String>? = null,
) : KeycloakOIDCConfigurationRepresentation()

fun OIDCConfigurationRepresentation(source: KeycloakOIDCConfigurationRepresentation): OIDCConfigurationRepresentation = JsonSerialization.valueFromString(
    JsonSerialization.writeValueAsString(source),
    OIDCConfigurationRepresentation::class.java,
)
