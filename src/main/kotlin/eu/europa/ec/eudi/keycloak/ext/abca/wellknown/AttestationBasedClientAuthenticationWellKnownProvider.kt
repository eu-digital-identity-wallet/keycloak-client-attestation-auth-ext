package eu.europa.ec.eudi.keycloak.ext.abca.wellknown

import com.fasterxml.jackson.core.type.TypeReference
import com.nimbusds.jose.JWSAlgorithm
import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import jakarta.ws.rs.core.UriInfo
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.services.Urls
import org.keycloak.urls.UrlType
import org.keycloak.util.JsonSerialization
import org.keycloak.wellknown.WellKnownProvider

class AttestationBasedClientAuthenticationWellKnownProvider(
    private val delegate: WellKnownProvider,
    private val session: KeycloakSession,
) : WellKnownProvider {

    override fun getConfig(): Any {
        val cfg = delegate.config
        // Convert to a mutable map so we can append custom properties regardless of the underlying representation
        val map: MutableMap<String, Any?> = JsonSerialization.mapper.convertValue(
            cfg,
            object : TypeReference<MutableMap<String, Any?>>() {},
        )
        val issuer = map["issuer"] as? String
        if (!issuer.isNullOrBlank()) {
            map[Spec.CHALLENGE_ENDPOINT] = challengeEndpoint(session.context)
        }
        // Ensure the new client authentication method is advertised
        addSupportedAuthMethod(map, "token_endpoint_auth_methods_supported", Spec.AUTHENTICATION_METHOD)

        // Advertise supported signing algorithms for attestation and PoP JWTs per draft spec
        addSigningAlgValuesSupported(
            map,
            Spec.CLIENT_ATTESTATION_SIGNING_ALG_VALUES_SUPPORTED,
            listOf(
                JWSAlgorithm.ES256.name,
                JWSAlgorithm.ES384.name,
                JWSAlgorithm.ES512.name,
            ),
        )
        addSigningAlgValuesSupported(
            map,
            Spec.CLIENT_ATTESTATION_POP_SIGNING_ALG_VALUES_SUPPORTED,
            listOf(
                JWSAlgorithm.ES256.name,
                JWSAlgorithm.ES384.name,
                JWSAlgorithm.ES512.name,
            ),
        )
        return map
    }

    override fun close() {
        delegate.close()
    }

    companion object {
        fun challengeEndpoint(context: KeycloakContext): String {
            return issuer(context) + "/challenge"
        }

        /**
         * Return the url of the issuer.
         */
        fun issuer(context: KeycloakContext): String? {
            val frontendUriInfo: UriInfo = context.getUri(UrlType.FRONTEND)
            return Urls.realmIssuer(
                frontendUriInfo.baseUri,
                context.realm.name,
            )
        }
    }
}
private fun concatPathLocal(base: String, segment: String): String =
    if (base.endsWith("/")) "$base$segment" else "$base/$segment"

private fun addSupportedAuthMethod(map: MutableMap<String, Any?>, key: String, method: String) {
    val current = map[key]
    val updated: MutableSet<String> = when (current) {
        is Collection<*> -> current.filterIsInstance<String>().toMutableSet()
        is Array<*> -> current.filterIsInstance<String>().toMutableSet()
        is String -> mutableSetOf(current)
        else -> mutableSetOf()
    }
    if (!updated.contains(method)) {
        updated.add(method)
    }
    map[key] = updated.toList()
}

private fun addSigningAlgValuesSupported(map: MutableMap<String, Any?>, key: String, values: List<String>) {
    val current = map[key]
    val updated: MutableSet<String> = when (current) {
        is Collection<*> -> current.filterIsInstance<String>().toMutableSet()
        is Array<*> -> current.filterIsInstance<String>().toMutableSet()
        is String -> mutableSetOf(current)
        else -> mutableSetOf()
    }
    updated.addAll(values)
    map[key] = updated.toList()
}
