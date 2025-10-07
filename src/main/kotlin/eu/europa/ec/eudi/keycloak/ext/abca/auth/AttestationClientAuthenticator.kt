package eu.europa.ec.eudi.keycloak.ext.abca.auth

import eu.europa.ec.eudi.keycloak.ext.abca.Spec
import eu.europa.ec.eudi.keycloak.ext.abca.trust.LotlTrustStore
import eu.europa.ec.eudi.statium.Status
import jakarta.ws.rs.core.Response
import org.keycloak.OAuthErrorException
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.ClientAuthenticationFlowContext
import org.keycloak.authentication.ClientAuthenticator
import org.keycloak.authentication.authenticators.client.ClientAuthUtil
import org.keycloak.protocol.oauth2.OAuth2WellKnownProviderFactory
import org.keycloak.wellknown.WellKnownProvider
import java.security.cert.X509Certificate

class AttestationClientAuthenticator : ClientAuthenticator {

    override fun authenticateClient(context: ClientAuthenticationFlowContext) {
        val headers = context.httpRequest.httpHeaders

        val attestationHeader = headers.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION)
        if (attestationHeader.isNullOrBlank()) return context.failWith(AttestationFailure.MissingClientAttestation)

        val attestationPopHeader = headers.getHeaderString(Spec.HEADER_CLIENT_ATTESTATION_POP)
        if (attestationPopHeader.isNullOrBlank()) return context.failWith(AttestationFailure.MissingClientAttestationPop)

        val clientAttestation = runCatching {
            ClientAttestation(attestationHeader)
        }.getOrElse {
            return context.failWith(AttestationFailure.BadAttestationFormat)
        }

        val clientId = clientAttestation.subject

        // If the request form includes client_id, ensure it matches the attestation subject
        context.httpRequest.decodedFormParameters?.getFirst("client_id")?.let { reqClientId ->
            if (!reqClientId.equals(clientId, ignoreCase = false)) {
                return context.failWith(AttestationFailure.ClientIdMismatch)
            }
        }

        context.event.client(clientId)
        val client = context.session.clients().getClientByClientId(context.realm, clientId)
            ?: return context.failWith(AttestationFailure.ClientNotFound)
        context.client = client
        if (!client.isEnabled) return context.failWith(AttestationFailure.ClientDisabled)

        // Retrieve trusted certificates prepared by the background LOTL refresher
        val trusted: List<X509Certificate> = LotlTrustStore.get()
        if (trusted.isEmpty()) return context.failWith(AttestationFailure.NoTrustedCertificates)

        // TODO Verify the signature of the Client Attestation JWT against the trusted certificates

        // Status list validation
        clientAttestation.status?.let {
            if (it.verifyStatus() !is Status.Valid) {
                return context.failWith(AttestationFailure.InvalidStatus)
            }
        }

        // Parse client attestation PoP jwt
        val clientAttestationPop = runCatching {
            ClientAttestationPop(attestationPopHeader)
        }.getOrElse {
            return context.failWith(AttestationFailure.BadAttestationPopFormat)
        }

        runCatching {
            clientAttestationPop.verifyPop(clientAttestation)
        }.getOrElse {
            return context.failWith(AttestationFailure.InvalidPopSignature(it.message))
        }

        // Verify audience of PoP against the realm issuer from OAuth 2.0 metadata
        getIssuerFromOAuthMetadata(context)?.let {
            if (!clientAttestationPop.audiences.contains(it)) {
                return context.failWith(AttestationFailure.InvalidAudience)
            }
        }

        if (clientAttestationPop.issuer != clientAttestation.subject) {
            return context.failWith(AttestationFailure.ClientIdMismatch)
        }

        if (clientAttestationPop.challenge == null) {
            return context.failWith(AttestationFailure.MissingChallenge)
        }

        runCatching {
            clientAttestationPop.challenge.verify(context.session)
        }.getOrElse {
            return context.failWith(AttestationFailure.InvalidChallenge)
        }

        context.success()
    }

    override fun close() {
        // no-op
    }

    private sealed class AttestationFailure(
        val flowError: AuthenticationFlowError,
        val httpStatus: Int,
        val oauthError: String,
        val message: String,
        val eventError: String? = null,
    ) {
        object MissingClientAttestation : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.BAD_REQUEST.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client attestation header is missing",
            "invalid_client_attestation_missing",
        )
        object MissingClientAttestationPop : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.BAD_REQUEST.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Client attestation PoP header is missing",
            "invalid_client_attestation_pop_missing",
        )
        object BadAttestationFormat : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.BAD_REQUEST.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Could not parse client attestation JWT",
            "invalid_client_attestation_parse",
        )
        object BadAttestationPopFormat : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.BAD_REQUEST.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Could not parse client attestation PoP JWT",
            "invalid_client_attestation_pop_parse",
        )
        object ClientNotFound : AttestationFailure(
            AuthenticationFlowError.CLIENT_NOT_FOUND,
            Response.Status.UNAUTHORIZED.statusCode,
            OAuthErrorException.INVALID_CLIENT,
            "Client not found",
            "client_not_found",
        )
        object ClientDisabled : AttestationFailure(
            AuthenticationFlowError.CLIENT_DISABLED,
            Response.Status.UNAUTHORIZED.statusCode,
            OAuthErrorException.INVALID_CLIENT,
            "Client disabled",
            "client_disabled",
        )
        object ClientIdMismatch : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "client_id in request does not match client attestation subject",
            "client_id_mismatch",
        )
        object NoTrustedCertificates : AttestationFailure(
            AuthenticationFlowError.INTERNAL_ERROR,
            Response.Status.SERVICE_UNAVAILABLE.statusCode,
            "server_error",
            "Attestation trust anchors are not available",
            "lotl_trust_empty",
        )
        class InvalidPopSignature(msg: String?) : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            msg ?: "Invalid PoP signature",
            "invalid_client_attestation_pop_signature",
        )
        object InvalidAudience : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Invalid audience in client attestation PoP JWT",
            "invalid_client_attestation_audience",
        )
        object InvalidStatus : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Invalid status in client attestation JWT",
            "invalid_client_attestation_status",
        )
        object MissingChallenge : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED.statusCode,
            Spec.USE_ATTESTATION_CHALLENGE_ERROR,
            "Missing challenge in client attestation PoP JWT",
            "invalid_client_attestation_missing_challenge",
        )
        object InvalidChallenge : AttestationFailure(
            AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS,
            Response.Status.UNAUTHORIZED.statusCode,
            Spec.INVALID_CLIENT_ATTESTATION_ERROR,
            "Invalid or expired challenge in client attestation PoP JWT",
            "invalid_client_attestation_invalid_challenge",
        )
    }

    private fun getIssuerFromOAuthMetadata(context: ClientAuthenticationFlowContext): String? {
        val provider = runCatching {
            context.session.getProvider(WellKnownProvider::class.java, OAuth2WellKnownProviderFactory.PROVIDER_ID)
        }.getOrNull() ?: return null
        try {
            val cfg: Any? = runCatching { provider.config }.getOrNull()
            return when (cfg) {
                is Map<*, *> -> cfg["issuer"] as? String
                else -> null
            }
        } catch (_: Throwable) {
            return null
        } finally {
            runCatching { provider.close() }
        }
    }

    private fun ClientAuthenticationFlowContext.failWith(f: AttestationFailure) {
        f.eventError?.let { this.event.error(it) }
        val resp = ClientAuthUtil.errorResponse(f.httpStatus, f.oauthError, f.message)
        this.failure(f.flowError, resp)
    }
}
