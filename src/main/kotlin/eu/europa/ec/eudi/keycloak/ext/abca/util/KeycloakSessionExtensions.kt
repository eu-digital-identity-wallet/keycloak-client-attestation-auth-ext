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
package eu.europa.ec.eudi.keycloak.ext.abca.util

import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import eu.europa.ec.eudi.keycloak.ext.abca.auth.ClientStatus
import eu.europa.ec.eudi.keycloak.ext.abca.util.context.isEnabled
import org.keycloak.crypto.SignatureProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.provider.Provider

internal var KeycloakSession.clientStatus: ClientStatus?
    get() = getAttribute(TS3.EUDI_CLIENT_STATUS_CLAIM, ClientStatus::class.java)
    set(value) = setAttribute(TS3.EUDI_CLIENT_STATUS_CLAIM, value)

inline fun <reified P : Provider> KeycloakSession.isEnabled(id: String): Boolean = null != keycloakSessionFactory.getProviderFactory(P::class.java, id) &&
    null != getProvider(P::class.java, id)

fun KeycloakSession.isEnabled(algorithm: JWSAlgorithm): Boolean = isEnabled<SignatureProvider>(algorithm.name)
