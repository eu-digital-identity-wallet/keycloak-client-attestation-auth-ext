package eu.europa.ec.eudi.keycloak.ext.abca.trust

import arrow.core.NonEmptyList
import io.ktor.client.HttpClient
import io.ktor.http.Url
import java.security.cert.X509Certificate

fun interface IsClientStatusIssuerTrusted {
    suspend operator fun invoke(x5c: NonEmptyList<X509Certificate>): TrustResult
    companion object
}

fun IsClientStatusIssuerTrusted.Companion.usingTrustValidatorService(
    httpClient: HttpClient,
    service: Url,
): IsClientStatusIssuerTrusted = IsClientStatusIssuerTrusted { x5c ->
    httpClient.validateTrust(service, x5c, VerificationContext.WALLET_OR_KEY_STORAGE_STATUS)
}

val IsClientStatusIssuerTrusted.Companion.Ignored: IsClientStatusIssuerTrusted get() = IsClientStatusIssuerTrusted {
    TrustResult.IsTrusted
}
