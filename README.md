# Keycloak OAuth 2.0 Attestation‑Based Client Authentication Extensions

**Important!** Before you proceed, please read
the [EUDI Wallet Reference Implementation project description](https://github.com/eu-digital-identity-wallet/.github/blob/main/profile/reference-implementation.md)

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

## Table of Contents

* [Disclaimer](#disclaimer)
* [Overview](#overview)
* [What’s in the box](#whats-in-the-box)
* [Stack / Tooling](#stack--tooling)
* [Requirements](#requirements)
* [Setup and Build](#setup-and-build)
* [Deploy to Keycloak](#deploy-to-keycloak)
* [Entry points (SPIs)](#entry-points-spis)
* [How to enable WalletStatusMapper](#how-to-enable-walletstatusmapper)
* [Usage](#usage)
* [Client Authenticator](#client-authenticator)
* [Gradle Tasks / Scripts](#gradle-tasks--scripts)
* [Environment and Configuration](#environment-and-configuration)
* [Project Structure](#project-structure)
* [How to contribute](#how-to-contribute)
* [License](#license)

## Disclaimer

> [!IMPORTANT]
> This **experimental** Keycloak extension is implemented to serve the needs of the EUDI project only. 
> 
> It is created strictly for testing and development purposes and to enable the reference implementation's [kotlin issuer](https://github.com/eu-digital-identity-wallet/eudi-srv-pid-issuer) to achieve:
> - Compliance with [ARF's technical spcification TS3](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md)
> - Compliance with [ETSI TS 119 472-3 V1.1.1 (2026-03)](https://www.etsi.org/deliver/etsi_ts/119400_119499/11947203/01.01.01_60/ts_11947203v010101p.pdf)
> - Compliance with a trust model based on Lists of Trusted Entities as defined in [ETSI TS 119 602 V1.1.1 (2025-11)](https://www.etsi.org/deliver/etsi_ts/119600_119699/119602/01.01.01_60/ts_119602v010101p.pdf) and Lists of Trusted Lists as defined in [ETSI TS 119 612 V2.4.1 (2025-08)](https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf)
> 
> **This is by no means**:
> - Antagonistic to any Keycloak's community ongoing implementation activities to support Attestation‑Based Client Authentication (ex. [43136](https://github.com/keycloak/keycloak/issues/43136), [40413](https://github.com/keycloak/keycloak/discussions/40413)).
> - An official Keycloak extension. 
> - A production-ready Keycloak extension.

## Overview

This project provides the following Keycloak Providers implementing parts of the OAuth 2.0 Attestation‑Based Client Authentication draft (draft‑ietf‑oauth‑attestation‑based‑client‑auth‑07):
  1) A handler (Provider) for generating and validating short-lived cryptographic challenges. 
  2) A realm resource that issues short‑lived cryptographic challenges.
  3) A Client Authenticator that authenticates clients using Client Attestation and Client Attestation PoP HTTP Headers.
  4) A Well‑Known Provider that augments the OIDC discovery document with ABCA metadata (challenge endpoint URL and supported algorithms).
  5) A Protocol Mapper that maps the `client_status` claim of the Client Attestation to the Access Token, Access Token Response, or Introspection Endpoint Response.

## What’s in the box
- Challenge handler: Provider + ProviderFactory + SPI (registered via META‑INF/services).
- Challenge endpoint: RealmResource + RealmResourceProvider + RealmResourceProviderFactory (registered via META‑INF/services).
- Client authenticator: ClientAuthenticator + ClientAuthenticatorFactory (registered via META‑INF/services); Parses OAuth‑Client‑Attestation and OAuth‑Client‑Attestation‑PoP HTTP Headers, verifies the Client Attestation issuer is trusted, validates Client Attestation PoP signature, validates Challenge.
- Well‑Known augmentation: WellKnownProvider + WellKnownProviderFactory (registered via META‑INF/services); Adds `challenge_endpoint`, `client_attestation_signing_alg_values_supported`, and `client_attestation_pop_signing_alg_values_supported`, and augments `token_endpoint_auth_methods_supported` to the OIDC discovery document.
- Client Status Protocol Mapper: ProtocolMapper (registered via META‑INF/services); Adds `client_status` to Access Token, Access Token Response, Introspection Endpoint Response based on its configuration.

## Stack / Tooling
- Language: Kotlin (JVM)
- Runtime target: Java 21
- Identity platform: Keycloak 26.6.2
- Build: Gradle (Kotlin DSL) with Gradle Version Catalog
- Lint/format: Spotless + ktlint
- JWT/JWK: Nimbus JOSE + JWT

## Requirements
- JDK 21 (Adoptium/Temurin recommended; build config sets vendor = ADOPTIUM)
- Gradle wrapper (included): use ./gradlew.bat on Windows
- Keycloak 26.6.2 server to deploy the resulting provider JAR(s)

## Setup and Build
- Format (optional) and build (Windows PowerShell):
  - `./gradlew.bat spotlessApply build`
- The build task creates an artifacts that contains all its dependencies shaded into a single JAR: `build\libs\<name>-<version>.jar`

## Deploy to Keycloak
- Copy either the generated JAR into your Keycloak `providers` directory. Examples:
  - Linux container: /opt/keycloak/providers
  - Windows distribution: <keycloak_install>\providers
- Restart Keycloak.

## Entry points (SPIs)
- Challenge handler: 
    - src\main\resources\META-INF\services\org.keycloak.provider.Spi -> eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeHandlerSpi
    - src\main\resources\META-INF\services\eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeHandlerProviderFactory -> eu.europa.ec.eudi.keycloak.ext.abca.challenge.DefaultChallengeHandlerProviderFactory
- Realm Resource: src\main\resources\META-INF\services\org.keycloak.services.resource.RealmResourceProviderFactory -> eu.europa.ec.eudi.keycloak.ext.abca.challenge.ChallengeRealmResourceProviderFactory
- Client Authenticator: src\main\resources\META-INF\services\org.keycloak.authentication.ClientAuthenticatorFactory -> eu.europa.ec.eudi.keycloak.ext.abca.auth.AttestationBasedClientAuthenticatorFactory
- Well‑Known Provider: src\main\resources\META-INF\services\org.keycloak.wellknown.WellKnownProviderFactory -> eu.europa.ec.eudi.keycloak.ext.abca.wellknown.AttestationBasedClientAuthenticationWellKnownProviderFactory
- Client Status Protocol Mapper: src\main\resources\META-INF\services\org.keycloak.protocol.ProtocolMapper -> eu.europa.ec.eudi.keycloak.ext.abca.clientstatus.ClientStatusProtocolMapper

## How to enable ClientStatusProtocolMapper
1. Go to the desired client from the `Clients`
2. In `Client scopes` chose the desired client scope ex: `eudiw-abca-dedicated`
3. Choose `Add mapper` and select `By Configuration`
4. Select `Client Status Protocol Mapper` and give it a name ex: `client_status`
5. Configure the mapper
6. Click `Save`

## Usage
- Well‑known discovery augmentation:
  - The OIDC discovery document will include:
    - `challenge_endpoint`: URL of the challenge endpoint (example: {issuer}/challenge)
    - `token_endpoint_auth_methods_supported` adds `attest_jwt_client_auth`
    - `client_attestation_signing_alg_values_supported`: [ES256, ES384, ES512]
    - `client_attestation_pop_signing_alg_values_supported`: [ES256, ES384, ES512]
- Challenge endpoint URL:
  - Available at: https://<host>/realms/<realm>/challenge
- Example request:
  - GET https://<host>/realms/<realm>/challenge
- Current response (per code):
  {
    "attestation_challenge": "value"
  }
  - Notes:
    - Response headers set Cache-Control: no-store, no-cache and Pragma: no-cache.

## Client Authenticator
- Headers expected by the authenticator (per draft):
  - `OAuth-Client-Attestation`: a signed JWT containing client metadata and a cnf.jwk binding key
  - `OAuth-Client-Attestation-PoP`: a PoP JWT signed by the `cnf.jwk` key
- Processing flow (high level):
  - Parses Client Attestation JWT; extracts sub (client_id) and cnf.jwk.
  - Verify the Client Attestation JWT signature using the key of the first certificate in the x5c claim.
  - Verify the Issuer of the Client Attestation JWT is trusted.
  - Verifies the PoP JWT signature with the public key from cnf.jwk.
  - Verifies `client_status` is valid.
  - Emits Keycloak events and returns OAuth error invalid_client_attestation on failures.

## Trust Verification
This KeyCloak extension optionally integrates with [eudi-srv-trust-validator](https://github.com/eu-digital-identity-wallet/eudi-srv-trust-validator) to check whether the
Issuer of a Client Attestation JWT is trusted or not.

The URL of the Trust Validator Service can be configured using the Admin UI with the `Trust Validator Service URL` property either at the 
Authentication Flow level, or the OAuth 2.0 Client level.

> [!CAUTION]
> 
> When no URL is configured, all Client Attestation JWT Issuers are trusted!

## Gradle Tasks / Scripts
- ./gradlew.bat build — Compiles and packages the provider JARs (both Regular and Fat/uber JAR).
- ./gradlew.bat test — Runs tests (JUnit Platform).
- ./gradlew.bat spotlessApply — Applies ktlint formatting via Spotless.

## Environment and Configuration

The following `keycloak.conf` properties (or the equivalent command line arguments, or environment variables) can be used to configure the providers:

Property: `spi-challenge-handler--default--bytes`    
Description: The number of bytes a Challenge is composed of.  
Format: Unsigned Integer.  
Minimum value: 32  
Default value: 64  

Property: `spi-challenge-handler--default--lifespan`    
Description: Duration a Challenge is valid for.  
Format: ISO 8601 formatted Duration.  
Maximum value: PT15M  
Default value: PT5M  

## How to contribute

We welcome contributions to this project. To ensure that the process is smooth for everyone
involved, follow the guidelines found in [CONTRIBUTING.md](CONTRIBUTING.md).

## License

### License details

Copyright (c) 2023-2026 European Commission

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
