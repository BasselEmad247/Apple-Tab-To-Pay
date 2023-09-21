package steps

import java.util.*

class EncryptTabToPayDataResponse(
    val activationData: String, // Base64
    val encryptedPassData: String, // Base64 - This will include ( primaryAccountNumber - expiration - name - nonce - nonceSignature )
    val ephemeralPublicKey: String // Base64
)

fun encodeAndSendData(activationData: ByteArray, publicKey: ByteArray, encryptedData: ByteArray): EncryptTabToPayDataResponse {
    // Encode data as Base64 strings
    val activationDataString = Base64.getEncoder().encodeToString(activationData)
    val publicKeyString = Base64.getEncoder().encodeToString(publicKey)
    val encryptedDataString = Base64.getEncoder().encodeToString(encryptedData)

    return EncryptTabToPayDataResponse(publicKeyString, encryptedDataString, activationDataString)
}

//fun main() {
//    val activationData = "5572b844-e46a-4100-b6a4-a6d4c3cd265d".toByteArray()
//
//    // Encode and send data
//    val jsonResponse = encodeAndSendData(activationData, keyPairs.ephemeralPubKey, encryptedDataWithMac)
//    println("Activation Data: ${jsonResponse.activationData}")
//    println("Encrypted Pass Data: ${jsonResponse.encryptedPassData}")
//    println("Ephemeral Public Key: ${jsonResponse.ephemeralPublicKey}")
//}