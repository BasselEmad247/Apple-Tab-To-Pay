package steps

import org.json.JSONObject
import java.util.Base64

fun encodeAndSendData(activationData: ByteArray, publicKey: ByteArray, encryptedData: ByteArray): String {
    // Encode data as Base64 strings
    val activationDataString = Base64.getEncoder().encodeToString(activationData)
    val publicKeyString = Base64.getEncoder().encodeToString(publicKey)
    val encryptedDataString = Base64.getEncoder().encodeToString(encryptedData)

    // Create JSON object
    val json = JSONObject()
    json.put("activationData", activationDataString)
    json.put("publicKey", publicKeyString)
    json.put("encryptedData", encryptedDataString)

    // Return the JSON response
    return json.toString()
}

//fun main() {
//    val activationData = "5572b844-e46a-4100-b6a4-a6d4c3cd265d".toByteArray()
//
//    // Encode and send data
//    val jsonResponse = encodeAndSendData(activationData, keyPairs.ephPublicKey, encryptedDataWithMac)
//    println(jsonResponse)
//}