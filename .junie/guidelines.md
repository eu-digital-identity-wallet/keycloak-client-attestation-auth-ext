# Project Guidelines

## Project Overview
This repository contains:
- A Keycloak realm-level REST endpoint returning a short‑lived cryptographic challenge ("nonce") in line with the OAuth 2.0 Attestation‑Based Client Authentication draft (draft‑ietf‑oauth‑attestation‑based‑client‑auth‑07).
- A Keycloak client authenticator that authenticates OAuth 2.0 clients in line with the same draft (attestation‑based client authentication).

- Endpoint: `/{realm}/challengeEndpoint` (HTTP GET)
- Response body example:
  {
    "challenge": "<base64url>",
    "expires_in": 300,
    "issued_at": 1736960000
  }
- Implementation approach: RealmResourceProvider + RealmResourceProviderFactory registered via `META-INF/services`.
- Language/Platform: Kotlin (JVM), Java 17, Keycloak 26.3.4.

Relevant classes:
- `src\main\kotlin\org\keycloak\ext\abca\challenge\ChallengeEndpoint.kt`
- `src\main\kotlin\org\keycloak\ext\abca\challenge\ChallengeEndpointProviderFactory.kt`
- `src\main\kotlin\org\keycloak\ext\abca\wellknown\*` (well-known support)
- `src\main\kotlin\org\keycloak\ext\abca\auth\*` (client authenticator pieces)
- Services registration under `src\main\resources\META-INF\services\`.

## Project Structure
- build scripts: `build.gradle.kts`, `gradle.properties`, `gradle\libs.versions.toml`
- Kotlin sources: `src\main\kotlin\org\keycloak\ext\abca\**`
- Resources (SPI/service descriptors and config): `src\main\resources\META-INF\**`
- README with usage and design notes: `README.md`

## How to Build
- Windows PowerShell: `./gradlew.bat build`
- Output JAR: `build\libs\` (regular jar). A fat jar task may exist if configured.

## Running/Using in Keycloak
- Copy the built JAR into Keycloak's `providers` directory.
- This project includes `microprofile-config.properties` enabling the realm REST extension SPI:
  `spi-realm-restapi-extension-enabled=true`.
- After (re)start, the endpoint is available at `https://<host>/realms/<realm>/challengeEndpoint`.

## Tests
- No unit tests are present at the moment. Junie does not need to run tests unless tests are added in the future. If tests are added, use `./gradlew.bat test`.

## Build Before Submit
- For code changes that may impact compilation, run `./gradlew.bat spotlessApply build` before submitting. For documentation‑only changes (like this guidelines file), a build is not required but is harmless.

## Code Style
- Kotlin idiomatic style targeting Java 17; prefer clear, null‑safe Kotlin APIs.
- Keep public API and SPI implementations small and focused; avoid Keycloak internal classes unless required by the SPI.

## Junie Workflow Notes
- Make minimal, targeted changes to satisfy the issue.
- Keep the user informed using the plan/status updates.
- Use Windows path separators (\\) and PowerShell commands in this environment.
- Use keycloak APIs where possible.
