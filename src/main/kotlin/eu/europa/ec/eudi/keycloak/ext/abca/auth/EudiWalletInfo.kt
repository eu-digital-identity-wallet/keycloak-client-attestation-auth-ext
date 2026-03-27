package eu.europa.ec.eudi.keycloak.ext.abca.auth

import eu.europa.ec.eudi.keycloak.ext.abca.TS3
import kotlinx.serialization.Required
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

@Serializable
data class EudiWalletInfo(
    @Required
    @SerialName(TS3.EUDI_WALLET_GENERAL_INFO_CLAIM)
    val generalInfo: GeneralInfo,
)

@Serializable
data class GeneralInfo(
    @Required
    @SerialName(TS3.EUDI_WALLET_PROVIDER_NAME_CLAIM)
    val walletProviderName: String,
    @Required
    @SerialName(TS3.EUDI_WALLET_SOLUTION_ID_CLAIM)
    val walletSolutionId: String,
    @Required
    @SerialName(TS3.EUDI_WALLET_SOLUTION_VERSION_CLAIM)
    val walletSolutionVersion: String,
    @Required
    @SerialName(TS3.EUDI_WALLET_SOLUTION_CERTIFICATION_INFORMATION_CLAIM)
    val walletSolutionCertificationInformation: WalletSolutionCertificationInformation,
)

@JvmInline
@Serializable
value class WalletSolutionCertificationInformation(val certificationInformation: JsonElement) {
    init {
        require(
            certificationInformation is JsonObject ||
                (certificationInformation is JsonPrimitive && certificationInformation.isString),

        )
    }
}
