import org.gradle.api.file.DuplicatesStrategy
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

plugins {
    base
    `java-library`
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.spotless)
}

repositories {
    mavenCentral()
}

dependencies {
    // For building a Keycloak server-side extension (realm REST resource)
    compileOnly(libs.keycloak.server.spi)
    compileOnly(libs.keycloak.services)
    // JAX-RS API for annotations during compilation
    compileOnly(libs.jakarta.ws.rs.api)

    // DSS
    implementation(libs.dss.service)
    implementation(libs.dss.validation)
    implementation(libs.dss.tsl.validation)
    implementation(libs.dss.utils.apache.commons)

    // Nimbus JOSE+JWT for JWK/JWT processing in authenticator and tests
    implementation(libs.nimbus.jose.jwt)

    implementation(libs.eudi.lib.kmp.statium)
    implementation(libs.ktor)

    // Kotlinx Serialization JSON for parsing the 'status' claim
    implementation(libs.kotlinx.serialization.json)

    testImplementation(kotlin("test"))
    testImplementation(libs.keycloak.server.spi)
    testImplementation(libs.keycloak.services)
    testImplementation(libs.jakarta.ws.rs.api)
    testImplementation(libs.mockito.core)
    testImplementation(libs.mockito.inline)
    testImplementation(libs.mockito.kotlin)
    testImplementation(libs.nimbus.jose.jwt)
    // JAX-RS RuntimeDelegate implementation for Response builder in tests
    testRuntimeOnly(libs.jersey.common)
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
        apiVersion = KotlinVersion.KOTLIN_2_1
        freeCompilerArgs.add("-opt-in=kotlin.time.ExperimentalTime")
    }
}

spotless {
    kotlin {
        ktlint(libs.versions.ktlint.get())
    }
    kotlinGradle {
        ktlint(libs.versions.ktlint.get())
    }
}

tasks.register<Jar>("uberJar") {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    archiveClassifier = "uber"

    // Exclude signature files that become invalid when repackaged into a fat JAR
    // These can cause "Invalid signature file digest for Manifest main attributes" at runtime
    exclude(
        "META-INF/*.SF",
        "META-INF/*.DSA",
        "META-INF/*.RSA",
        "META-INF/*.EC",
        "META-INF/*.SIG",
        "META-INF/*SIGN*",
        "META-INF/INDEX.LIST",
    )

    from(sourceSets.main.get().output)

    dependsOn(configurations.runtimeClasspath)
    from({
        configurations.runtimeClasspath.get().filter { it.name.endsWith("jar") }.map { zipTree(it) }
    })

    // If a destination directory is provided via -PuberJarCopyDir=... (absolute or relative),
    // copy the produced uber JAR there after it is built.
    doLast {
        val jarFile = archiveFile.get().asFile
        val destDir = file("C:\\devel\\bin\\keycloak-26.3.4\\providers")
        project.copy {
            from(jarFile)
            into(destDir)
        }
        println("[uberJar] Copied ${jarFile.name} to ${destDir.absolutePath}")
    }
}

tasks.test {
    useJUnitPlatform()
}
