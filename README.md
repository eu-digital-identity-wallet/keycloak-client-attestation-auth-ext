Keycloak OAuth 2.0 Attestation‑Based Client Authentication (ABCA) Extensions

Overview
- This project provides three Keycloak extensions implementing parts of the OAuth 2.0 Attestation‑Based Client Authentication draft (draft‑ietf‑oauth‑attestation‑based‑client‑auth‑07):
  1) A realm‑level REST endpoint that issues a short‑lived cryptographic challenge ("nonce").
  2) A Keycloak Client Authenticator that verifies client attestation headers and a proof‑of‑possession (PoP) JWT.
  3) A Well‑Known provider that augments the OIDC discovery document with ABCA metadata (challenge endpoint URL and supported algorithms).

What’s in the box
- Challenge endpoint implementation: RealmResourceProvider + RealmResourceProviderFactory (registered via META‑INF/services).
- Client authenticator: Parses OAuth‑Client‑Attestation and OAuth‑Client‑Attestation‑PoP headers, loads trusted certificates from a LOTL‑based trust store, validates PoP JWT signature, and wires into Keycloak’s client auth flow.
- Well‑known augmentation: Adds challenge_endpoint and supported algorithm lists to the OIDC discovery document.

Stack / Tooling
- Language: Kotlin (JVM)
- Runtime target: Java 17
- Identity platform: Keycloak 26.3.4
- Build: Gradle (Kotlin DSL) with Gradle Version Catalog
- Lint/format: Spotless + ktlint
- JWT/JWK: Nimbus JOSE + JWT

Requirements
- JDK 17 (Adoptium/Temurin recommended; build config sets vendor = ADOPTIUM)
- Gradle wrapper (included): use ./gradlew.bat on Windows
- Keycloak 26.3.4 server to deploy the resulting provider JAR(s)

Setup and Build
- Format (optional) and build (Windows PowerShell):
  - ./gradlew.bat spotlessApply build
- Artifacts:
  - Regular JAR: build\libs\<name>-<version>.jar
  - Fat/uber JAR: ./gradlew.bat uberJar creates build\libs\<name>-<version>-uber.jar
    - Note: The uberJar task currently copies the built uber JAR to C:\devel\bin\keycloak-26.3.4\providers after build.
      TODO: Make this destination configurable (currently hard‑coded for local development).

Deploy to Keycloak
- Copy either the regular JAR (plus runtime deps if needed) or the uber JAR into your Keycloak providers directory. Examples:
  - Linux container: /opt/keycloak/providers
  - Windows distribution: <keycloak_install>\providers
- Restart Keycloak.
- This repository includes META‑INF/microprofile-config.properties with:
  - spi-realm-restapi-extension-enabled=true
  This enables the realm‑restapi‑extension SPI which Keycloak marks as internal.

Entry points (SPIs)
- Realm REST extension: src\main\resources\META-INF\services\org.keycloak.services.resource.RealmResourceProviderFactory -> ChallengeEndpointProviderFactory
- Well‑Known provider: src\main\resources\META-INF\services\org.keycloak.wellknown.WellKnownProviderFactory -> OAuthAuthorizationServerConfigWithChallengeFactory
- Client authenticator: src\main\resources\META-INF\services\org.keycloak.authentication.ClientAuthenticatorFactory -> AttestationClientAuthenticatorFactory

Usage
- Well‑known discovery augmentation:
  - The OIDC discovery document will include a challenge_endpoint field and supported lists for attestation and PoP algorithms.
- Challenge endpoint URL:
  - Advertised by well‑known as: {issuer}/protocol/openid-connect/ext/acba/challenge
  - Current implementation details:
    - The RealmResourceProviderFactory.getId() returns "protocol" and the resource class/method has no @Path, which effectively mounts GET at /realms/{realm}/protocol.
    - This is likely not the final desired path and may conflict with built‑in protocol routes.
    - TODO: Align the provider id and resource @Path to match the well‑known value (e.g., protocol/openid-connect/ext/acba/challenge).
- Example request (intended):
  - GET https://<host>/realms/<realm>/protocol/openid-connect/ext/acba/challenge
- Current response (per code):
  {
    "attestation_challenge": "<base64url>"
  }
  - Notes:
    - The current implementation does NOT include expires_in or issued_at. TODO: Add TTL/issued_at to match the draft example if required by clients.
    - Response headers set Cache-Control: no-store, no-cache and Pragma: no-cache.

Client Authenticator
- Headers expected by the authenticator (per draft):
  - OAuth-Client-Attestation: a signed JWT containing client metadata and a cnf.jwk binding key
  - OAuth-Client-Attestation-PoP: a PoP JWT signed by the cnf.jwk key
- Processing flow (high level):
  - Parses Client Attestation JWT; extracts sub (client_id) and cnf.jwk.
  - Loads trusted certificates via LotlTrustStore (LOTL refresh task keeps it updated).
  - TODO: Verify the Client Attestation JWT signature against the trusted certificates (placeholder exists in code).
  - Verifies the PoP JWT signature with the public key from cnf.jwk (RSA or EC currently; EdDSA support is a TODO).
  - Emits Keycloak events and returns OAuth error invalid_client_attestation on failures.

Gradle Tasks / Scripts
- ./gradlew.bat build — Compiles and packages the provider JAR(s).
- ./gradlew.bat test — Runs tests (JUnit Platform).
- ./gradlew.bat spotlessApply — Applies ktlint formatting via Spotless.
- ./gradlew.bat uberJar — Builds a fat JAR and copies it to a development Keycloak providers dir (see note above).

Environment and Configuration
- MicroProfile Config (bundled in JAR):
  - src\main\resources\META-INF\microprofile-config.properties
  - spi-realm-restapi-extension-enabled=true
- Optional ABCA LOTL refresher properties (can be provided via MicroProfile Config, system properties, or environment variables):
  - abca.lotl.url — URL to LOTL/TSL certificate bundle (example placeholder in file)
  - abca.lotl.refresh-interval-seconds — Refresh interval (seconds)
  - abca.lotl.http-timeout-ms — HTTP timeout (ms)
- Keycloak runtime flags: None required specifically for this extension beyond standard server configuration.
- TODO: Externalize uberJar copy destination via a Gradle property (e.g., -PuberJarCopyDir) or environment variable.

Tests
- Location: src\test\kotlin\org\keycloak\ext\abca\auth\AttestationClientAuthenticatorTest.kt
- Run: ./gradlew.bat test
- Coverage:
  - Includes tests around the AttestationClientAuthenticator behavior using mocked Keycloak components and Nimbus JOSE.
  - TODO: Add tests for challenge endpoint and well‑known provider.

Project Structure
- build.gradle.kts — Gradle build (Kotlin DSL); defines dependencies, Kotlin/JVM toolchain, Spotless, uberJar task.
- gradle\libs.versions.toml — Version catalog for dependencies and plugins.
- src\main\kotlin\org\keycloak\ext\abca\Spec.kt — Shared constants (e.g., header names, error codes).
- src\main\kotlin\org\keycloak\ext\abca\challenge\* — Challenge endpoint and provider factory.
- src\main\kotlin\org\keycloak\ext\abca\auth\* — Client authenticator and factory.
- src\main\kotlin\org\keycloak\ext\abca\trust\* — LOTL fetch/refresh and trust store logic.
- src\main\kotlin\org\keycloak\ext\abca\wellknown\* — Well‑known augmentation provider and factory.
- src\main\resources\META-INF\services\* — Service provider registrations.
- src\main\resources\META-INF\microprofile-config.properties — Enables realm REST extension SPI; optional ABCA config placeholders.
- src\test\kotlin\... — Tests.

License
- No LICENSE file detected in the repository.
- TODO: Add a LICENSE file (e.g., MIT, Apache‑2.0) and update this section accordingly.