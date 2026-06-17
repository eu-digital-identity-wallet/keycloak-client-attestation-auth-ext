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
package eu.europa.ec.eudi.keycloak.ext.abca.challenge

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensureNotNull
import arrow.core.raise.option
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.SingleUseObjectProvider.REVOKED_KEY
import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderFactory
import org.keycloak.provider.Spi
import java.security.SecureRandom
import kotlin.io.encoding.Base64
import kotlin.random.Random
import kotlin.random.asKotlinRandom
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

sealed interface ChallengeValidationError {
    @JvmInline
    value class UseAttestationChallenge(val challenge: Challenge) : ChallengeValidationError
}

interface ChallengeHandler : Provider {

    /**
     * Creates a new [Challenge]
     */
    suspend fun generateNew(): Challenge

    /**
     * Checks if [value] corresponds to a valid [Challenge]. If valid, the matched Challenge is invalidated.
     */
    suspend fun validate(value: String): Either<ChallengeValidationError, Challenge>

    override fun close() {
        // no-op
    }
}

data class ChallengeBytes private constructor(val value: UInt) : Comparable<ChallengeBytes> {
    init {
        check(value >= MinimumValue)
    }

    override fun compareTo(other: ChallengeBytes): Int = value.compareTo(other.value)

    companion object {
        private val DefaultValue = 64u
        val Default: ChallengeBytes get() = ChallengeBytes(DefaultValue)

        private val MinimumValue = 32u
        val Minimum: ChallengeBytes get() = ChallengeBytes(MinimumValue)

        fun ofOrNull(value: UInt): ChallengeBytes? = value.takeIf { it >= MinimumValue }?.let(::ChallengeBytes)
        fun of(value: UInt): ChallengeBytes = ofOrNull(value) ?: throw IllegalArgumentException("value must be >= $MinimumValue")
    }
}

fun UInt.toChallengeBytesOrNull(): ChallengeBytes? = ChallengeBytes.ofOrNull(this)
fun UInt.toChallengeBytes(): ChallengeBytes = ChallengeBytes.of(this)

data class ChallengeLifespan private constructor(val value: Duration) : Comparable<ChallengeLifespan> {
    init {
        check(value.isPositive())
        check(value <= MaximumValue)
    }

    override fun compareTo(other: ChallengeLifespan): Int = value.compareTo(other.value)

    companion object {
        private val DefaultValue = 5.minutes
        val Default: ChallengeLifespan get() = ChallengeLifespan(DefaultValue)

        private val MaximumValue = 15.minutes
        val Maximum: ChallengeLifespan get() = ChallengeLifespan(MaximumValue)

        fun ofOrNull(value: Duration): ChallengeLifespan? = value.takeIf { it.isPositive() && it <= MaximumValue }?.let(::ChallengeLifespan)
        fun of(value: Duration): ChallengeLifespan = ofOrNull(value) ?: throw IllegalArgumentException("value must be positive and <= $MaximumValue")
    }
}

fun Duration.toChallengeLifespanOrNull(): ChallengeLifespan? = ChallengeLifespan.ofOrNull(this)
fun Duration.toChallengeLifespan(): ChallengeLifespan = ChallengeLifespan.of(this)

class DefaultChallengeHandler(
    private val session: KeycloakSession,
    private val bytes: ChallengeBytes = ChallengeBytes.Default,
    private val lifespan: ChallengeLifespan = ChallengeLifespan.Default,
) : ChallengeHandler {
    private val random by lazy { SecureRandom().asKotlinRandom() }
    private val base64 by lazy { Base64.UrlSafe.withPadding(Base64.PaddingOption.PRESENT) }

    override suspend fun generateNew(): Challenge = withContext(Dispatchers.IO) {
        val bytes = random.nextBytes(bytes.value.toInt())
        val encoded = base64.encode(bytes)
        val challenge = encoded.toChallenge()
        session.singleUseObjects().put(challenge.value, lifespan.value.inWholeSeconds, emptyMap())
        challenge
    }

    override suspend fun validate(value: String): Either<ChallengeValidationError, Challenge> = either {
        val challenge = withContext(Dispatchers.IO) {
            DefaultChallengeHandlerMutex.withLock {
                with(session.singleUseObjects()) {
                    option {
                        ensure(contains(value))
                        remove(value)
                        value.toChallenge()
                    }.getOrNull()
                }
            }
        }

        ensureNotNull(challenge) {
            ChallengeValidationError.UseAttestationChallenge(generateNew())
        }
    }

    companion object {
        private val DefaultChallengeHandlerMutex = Mutex()
    }
}

interface ChallengeHandlerProviderFactory : ProviderFactory<ChallengeHandler> {
    override fun init(config: Config.Scope) {
        // no-op
    }

    override fun postInit(factory: KeycloakSessionFactory) {
        // no-op
    }

    override fun close() {
        // no-op
    }
}

class DefaultChallengeHandlerProviderFactory : ChallengeHandlerProviderFactory {
    private lateinit var bytes: ChallengeBytes
    private lateinit var lifespan: ChallengeLifespan

    override fun create(session: KeycloakSession): ChallengeHandler = DefaultChallengeHandler(session, bytes, lifespan)

    override fun init(config: Config.Scope) {
        bytes = config.getInt("bytes")?.toUInt()?.toChallengeBytes() ?: ChallengeBytes.Default
        lifespan = config.get("lifespan")?.let { Duration.parse(it) }?.toChallengeLifespan() ?: ChallengeLifespan.Default
    }

    override fun getId(): String = "default"
}

class ChallengeHandlerSpi : Spi {
    override fun isInternal(): Boolean = false

    override fun getName(): String = "challenge-handler"

    override fun getProviderClass(): Class<out Provider> = ChallengeHandler::class.java

    override fun getProviderFactoryClass(): Class<out ProviderFactory<*>> = ChallengeHandlerProviderFactory::class.java
}
