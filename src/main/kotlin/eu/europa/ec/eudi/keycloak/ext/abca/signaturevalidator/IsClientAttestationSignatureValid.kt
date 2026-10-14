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
package eu.europa.ec.eudi.keycloak.ext.abca.signaturevalidator

import arrow.core.raise.result
import com.nimbusds.jose.crypto.ECDSAVerifier
import eu.europa.ec.eudi.keycloak.ext.abca.walletinstanceattestation.ClientAttestation
import eu.europa.esig.dss.enumerations.Indication
import eu.europa.esig.dss.enumerations.ValidationLevel
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier
import eu.europa.esig.dss.spi.validation.executor.CompleteValidationContextExecutor
import eu.europa.esig.dss.spi.x509.CertificateSource
import eu.europa.esig.dss.spi.x509.CommonCertificateSource
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource
import eu.europa.esig.dss.validation.SignedDocumentValidator
import java.util.Date
import kotlin.time.Clock
import kotlin.time.toJavaInstant

fun interface IsClientAttestationSignatureValid : suspend (ClientAttestation) -> SignatureVerificationResult {

    companion object {
        val Ignored: IsClientAttestationSignatureValid = { _ -> SignatureVerificationResult.Passed }

        fun jadesBB(clock: Clock): IsClientAttestationSignatureValid = { clientAttestation ->
            val trustAnchor = clientAttestation.x5c.first()

            val certificateVerifier: CommonCertificateVerifier = CommonCertificateVerifier(true).apply {
                val certificateSource: CertificateSource = CommonCertificateSource().apply { addCertificate(CertificateToken(trustAnchor)) }
                val trustedCertificateSource = CommonTrustedCertificateSource().apply { importAsTrusted(certificateSource) }

                setTrustedCertSources(trustedCertificateSource)
            }

            val validator =
                SignedDocumentValidator.fromDocument(InMemoryDocument(clientAttestation.jwt.serialize().toByteArray())).apply {
                    setCertificateVerifier(certificateVerifier)
                    setValidationLevel(ValidationLevel.BASIC_SIGNATURES)
                    setValidationContextExecutor(CompleteValidationContextExecutor.INSTANCE)
                    setValidationTime(Date.from(clock.now().toJavaInstant()))
                }

            val report = validator.validateDocument().simpleReport
            check(null != report.signatureIdList.singleOrNull()) { "JWT can not contain more than one signature" }

            val signatureId = report.firstSignatureId
            val indication = report.getIndication(signatureId)
            if (indication == Indication.TOTAL_PASSED) {
                SignatureVerificationResult.Passed
            } else {
                SignatureVerificationResult.Failed(
                    "JAdES B-B signature verification failed: indication=$indication, " +
                        "subIndication=${report.getSubIndication(signatureId)}",
                )
            }
        }

        fun jws(): IsClientAttestationSignatureValid = { clientAttestation ->
            val signingKey = clientAttestation.signingKey
            result {
                if (clientAttestation.jwt.verify(ECDSAVerifier(signingKey))) {
                    SignatureVerificationResult.Passed
                } else {
                    SignatureVerificationResult.Failed("Signature verification")
                }
            }.getOrElse {
                SignatureVerificationResult.Failed("Signature verification", it)
            }
        }
    }
}
