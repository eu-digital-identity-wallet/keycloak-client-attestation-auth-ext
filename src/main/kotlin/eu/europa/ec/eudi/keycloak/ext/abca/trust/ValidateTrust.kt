package eu.europa.ec.eudi.keycloak.ext.abca.trust

import arrow.core.NonEmptyList
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.expectSuccess
import io.ktor.client.request.accept
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.Url
import io.ktor.http.contentType
import java.security.cert.X509Certificate

internal suspend fun HttpClient.validateTrust(serviceUrl: Url, x5c: NonEmptyList<X509Certificate>, verificationContext: VerificationContext): TrustResult {
    val body = TrustRequest(x5c, verificationContext)
    val isTrusted = runCatching {
        val trustResponse = post(serviceUrl) {
            setBody(body)
            contentType(ContentType.Application.Json)
            accept(ContentType.Application.Json)
            expectSuccess = true
        }
        trustResponse.body<TrustResponse>().trusted
    }.getOrElse {
        return@validateTrust TrustResult.ServiceFailure
    }
    return if (isTrusted) {
        TrustResult.IsTrusted
    } else {
        TrustResult.IsUntrusted
    }
}
