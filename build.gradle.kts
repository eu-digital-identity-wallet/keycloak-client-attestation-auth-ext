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
    implementation(platform(libs.kotlin.bom))
    implementation(libs.kotlin.stdlib)
    testImplementation(libs.kotlin.test)

    implementation(platform(libs.kotlinx.serialization.bom))
    implementation(libs.kotlinx.serialization.json)

    implementation(platform(libs.kotlinx.coroutines.bom))
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.kotlinx.coroutines.test)

    implementation(platform(libs.ktor.bom))
    implementation(libs.ktor.client.okhttp)
    implementation(libs.ktor.client.content.negotiation)
    implementation(libs.ktor.serialization.kotlinx.json)
    testImplementation(libs.ktor.client.mock)

    implementation(platform(libs.arrow.stack))
    implementation(libs.arrow.core)
    implementation(libs.arrow.autoclose)

    implementation(platform(libs.keycloak.dependencies.server.all))
    compileOnly(libs.keycloak.server.spi)
    compileOnly(libs.keycloak.services)
    testImplementation(libs.keycloak.server.spi)
    testImplementation(libs.keycloak.services)

    testImplementation(platform(libs.mockito.bom))
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.kotlin)

    testImplementation(platform(libs.jersey.bom))
    testImplementation(libs.jersey.common)

    implementation(libs.nimbus.jose.jwt)
    implementation(libs.bouncycastle.bkpkix)
    testImplementation(libs.nimbus.oauth2)

    implementation(libs.statium)
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

tasks.jar {
    enabled = false
}

tasks.shadowJar {
    archiveClassifier.set("")
}

tasks.assemble {
    dependsOn(tasks.shadowJar)
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

dependencyCheck {
    formats = mutableListOf("XML", "HTML")

    nvd {
        apiKey = System.getenv("NVD_API_KEY") ?: properties["nvdApiKey"]?.toString() ?: ""
        delay = 10000
        maxRetryCount = 2
    }
}
