package eu.europa.ec.eudi.keycloak.ext.abca.trust

import java.security.cert.X509Certificate

sealed interface TrustResult {
    object IsTrusted : TrustResult
    object IsUntrusted : TrustResult
    object ServiceFailure : TrustResult
}

fun interface IsClientAttestationIssuerTrusted {
    suspend operator fun invoke(x5c: List<X509Certificate>): TrustResult
    companion object
}
