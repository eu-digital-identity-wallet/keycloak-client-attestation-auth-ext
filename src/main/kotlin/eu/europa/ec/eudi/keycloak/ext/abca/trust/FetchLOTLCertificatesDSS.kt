/*
 * Copyright (c) 2023 European Commission
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
package eu.europa.ec.eudi.keycloak.ext.abca.trust

import eu.europa.esig.dss.service.http.commons.CommonsDataLoader
import eu.europa.esig.dss.service.http.commons.FileCacheDataLoader
import eu.europa.esig.dss.spi.client.http.DSSCacheFileLoader
import eu.europa.esig.dss.spi.client.http.IgnoreDataLoader
import eu.europa.esig.dss.spi.tsl.TrustedListsCertificateSource
import eu.europa.esig.dss.spi.x509.KeyStoreCertificateSource
import eu.europa.esig.dss.tsl.cache.CacheCleaner
import eu.europa.esig.dss.tsl.function.GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate
import eu.europa.esig.dss.tsl.job.TLValidationJob
import eu.europa.esig.dss.tsl.source.LOTLSource
import eu.europa.esig.dss.tsl.sync.ExpirationAndSignatureCheckStrategy
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.URL
import java.nio.file.Files
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.function.Predicate
import kotlin.time.measureTimedValue

private val logger: Logger = LoggerFactory.getLogger(FetchLOTLCertificatesDSS::class.java)

data class TrustedListConfig(
    val location: URL,
    val serviceTypeFilter: String?,
    val keystoreConfig: KeyStoreConfig?,
)

data class KeyStoreConfig(
    val keystorePath: String,
    val keystoreType: String? = "JKS",
    val keystorePassword: CharArray? = "".toCharArray(),
    val keystore: KeyStore,
)

class FetchLOTLCertificatesDSS(
    private val executorService: ExecutorService = Executors.newFixedThreadPool(4),
) {

    fun invoke(
        trustedListConfig: TrustedListConfig,
    ): Result<List<X509Certificate>> = runCatching {
        val trustedListsCertificateSource = TrustedListsCertificateSource()

        val tlCacheDirectory = Files.createTempDirectory("lotl-cache").toFile()

        val offlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000)
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = IgnoreDataLoader()
        }

        val onlineLoader: DSSCacheFileLoader = FileCacheDataLoader().apply {
            setCacheExpirationTime(24 * 60 * 60 * 1000)
            setFileCacheDirectory(tlCacheDirectory)
            dataLoader = CommonsDataLoader()
        }

        val cacheCleaner = CacheCleaner().apply {
            setCleanMemory(true)
            setCleanFileSystem(true)
            setDSSFileLoader(offlineLoader)
        }

        val validationJob = TLValidationJob().apply {
            setListOfTrustedListSources(lotlSource(trustedListConfig))
            setOfflineDataLoader(offlineLoader)
            setOnlineDataLoader(onlineLoader)
            setTrustedListCertificateSource(trustedListsCertificateSource)
            setSynchronizationStrategy(ExpirationAndSignatureCheckStrategy())
            setCacheCleaner(cacheCleaner)
            setExecutorService(executorService)
        }

        logger.info("Starting validation job")
        val (certs, duration) = measureTimedValue {
            validationJob.onlineRefresh()

            trustedListsCertificateSource.certificates.map {
                it.certificate
            }
        }
        logger.info("Finished validation job in $duration")
        certs
    }

    private fun lotlSource(
        trustedListConfig: TrustedListConfig,
    ): LOTLSource = LOTLSource().apply {
        url = trustedListConfig.location.toExternalForm()
        trustedListConfig.keystoreConfig
            ?.let { lotlCertificateSource(it).getOrNull() }
            ?.let { certificateSource = it }
        isPivotSupport = true
        trustAnchorValidityPredicate = GrantedOrRecognizedAtNationalLevelTrustAnchorPeriodPredicate()
        tlVersions = listOf(5, 6)
        trustedListConfig.serviceTypeFilter?.let {
            trustServicePredicate = Predicate { tspServiceType ->
                tspServiceType.serviceInformation.serviceTypeIdentifier == it
            }
        }
    }

    private fun lotlCertificateSource(keystoreConfig: KeyStoreConfig): Result<KeyStoreCertificateSource> =
        runCatching {
            val inputStream = try {
                // Try to interpret as URL first
                val url = URL(keystoreConfig.keystorePath)
                url.openStream()
            } catch (_: Exception) {
                // Fallback to file system path
                Files.newInputStream(java.nio.file.Path.of(keystoreConfig.keystorePath))
            }
            KeyStoreCertificateSource(
                inputStream,
                keystoreConfig.keystoreType,
                keystoreConfig.keystorePassword,
            )
        }
}
