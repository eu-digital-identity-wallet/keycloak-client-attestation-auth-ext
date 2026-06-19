import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm
import org.jetbrains.dokka.gradle.engine.parameters.VisibilityModifier
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion
import java.net.URI

object Meta {
    const val BASE_URL = "https://github.com/eu-digital-identity-wallet/keycloak-client-attestation-auth-ext"
}

plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.spotless)
    alias(libs.plugins.shadow)
    alias(libs.plugins.dokka)
    alias(libs.plugins.maven.publish)
    alias(libs.plugins.dependency.check)
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(enforcedPlatform(libs.kotlin.bom))
    implementation(enforcedPlatform(libs.kotlinx.serialization.bom))
    implementation(enforcedPlatform(libs.kotlinx.coroutines.bom))
    implementation(enforcedPlatform(libs.ktor.bom))
    implementation(enforcedPlatform(libs.arrow.stack))
    implementation(enforcedPlatform(libs.keycloak.dependencies.server.all))
    testImplementation(enforcedPlatform(libs.mockito.bom))
    testImplementation(enforcedPlatform(libs.jersey.bom))

    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)

    implementation(libs.kotlinx.serialization.json)

    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.kotlinx.coroutines.test)

    implementation(libs.ktor.client.okhttp)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    testImplementation(libs.ktor.client.mock)

    implementation(libs.arrow.core)
    implementation(libs.arrow.core.serialization)

    compileOnly(libs.keycloak.server.spi)
    compileOnly(libs.keycloak.services)
    testImplementation(libs.keycloak.server.spi)
    testImplementation(libs.keycloak.services)

    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.kotlin)

    testImplementation(libs.jersey.common)

    implementation(libs.nimbus.jose.jwt)
    testImplementation(libs.bouncycastle.bkpkix)
    testImplementation(libs.nimbus.oauth2)

    implementation(libs.statium)
    implementation(libs.uri.kmp)
}

java {
    sourceCompatibility = JavaVersion.toVersion(libs.versions.java.get())
}

kotlin {
    jvmToolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get())
        vendor = JvmVendorSpec.ADOPTIUM
    }
    compilerOptions {
        apiVersion = KotlinVersion.DEFAULT
        optIn.addAll(
            "kotlin.time.ExperimentalTime",
            "kotlin.io.encoding.ExperimentalEncodingApi",
            "kotlinx.serialization.ExperimentalSerializationApi",
        )
        freeCompilerArgs.addAll(
            "-Xconsistent-data-class-copy-visibility",
            "-Xcontext-parameters",
            "-Xannotation-default-target=param-property",
        )
    }
}

spotless {
    kotlin {
        target("**/*.kt")
        ktlint(libs.versions.ktlint.get())
            .editorConfigOverride(
                mapOf(
                    "ktlint_standard_no-wildcard-imports" to "disabled",
                ),
            )
        licenseHeaderFile("FileHeader.txt")
    }
    kotlinGradle {
        target("**/*.gradle.kts")
        ktlint(libs.versions.ktlint.get())
            .editorConfigOverride(
                mapOf(
                    "ktlint_standard_no-wildcard-imports" to "disabled",
                ),
            )
    }
}

tasks.shadowJar {
    archiveClassifier = ""
    enableAutoRelocation = true
    enableKotlinModuleRemapping = true
    relocationPrefix = "eu.europa.ec.eudi.keycloak.ext.abca.shadow"
}

tasks.test {
    useJUnitPlatform()
}

//
// Configuration of Dokka engine
//
dokka {
    moduleName = "EUDI ABCA Keycloak extension"

    dokkaSourceSets.main {
        documentedVisibilities = setOf(VisibilityModifier.Public, VisibilityModifier.Protected)

        val remoteSourceUrl = System.getenv()["GIT_REF_NAME"]?.let { URI.create("${Meta.BASE_URL}/tree/$it/src") }
        remoteSourceUrl
            ?.let {
                sourceLink {
                    localDirectory = projectDir.resolve("src")
                    remoteUrl = it
                    remoteLineSuffix = "#L"
                }
            }
    }
}

mavenPublishing {
    configure(KotlinJvm(javadocJar = JavadocJar.Dokka(tasks.dokkaGeneratePublicationHtml), sourcesJar = true))

    pom {
        ciManagement {
            system = "github"
            url = "${Meta.BASE_URL}/actions"
        }
    }
}

tasks.withType<GenerateModuleMetadata> {
    suppressedValidationErrors.addAll(
        "enforced-platform",
    )
}

dependencyCheck {
    formats = mutableListOf("XML", "HTML")

    nvd {
        apiKey = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString() ?: ""
        delay = 10000
        maxRetryCount = 2
    }
}
