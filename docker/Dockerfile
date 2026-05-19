FROM quay.io/keycloak/keycloak:26.3.2-0

COPY build/libs/abca-keycloak-ext-0.0.1-SNAPSHOT-all.jar /opt/keycloak/providers/abca-keycloak-ext-0.0.1-SNAPSHOT-uber.jar

USER root
RUN chown -R keycloak:keycloak /opt/keycloak/providers

USER keycloak

RUN /opt/keycloak/bin/kc.sh build --features=dpop,passkeys