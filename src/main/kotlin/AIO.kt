import java.io.FileInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.KeyAgreement
import java.security.MessageDigest
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.crypto.engines.AESEngine
import org.bouncycastle.crypto.modes.GCMBlockCipher
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.util.encoders.Hex
import java.security.Security
import org.json.JSONObject
import java.util.Base64

fun extractApplePublicKey(certificateFilePath: String): ByteArray {
    // Load the certificate file
    val fileInputStream = FileInputStream(certificateFilePath)

    // Create a CertificateFactory instance for X.509 certificates
    val certificateFactory = CertificateFactory.getInstance("X.509")

    // Load the certificate
    val certificate = certificateFactory.generateCertificate(fileInputStream) as X509Certificate

    // Close the FileInputStream
    fileInputStream.close()

    // Retrieve the public key from the certificate
    val publicKey = certificate.publicKey
    val encodedPublicKey = publicKey.encoded

    // Extract the uncompressed format (65 bytes)
    val uncompressedPublicKey = ByteArray(65)
    System.arraycopy(encodedPublicKey, encodedPublicKey.size - 65, uncompressedPublicKey, 0, 65)

    return encodedPublicKey
}

class Keys(publicKey: PublicKey, privateKey: PrivateKey, ephemeralPublicKey: ByteArray) {
    val pubKey: PublicKey = publicKey
    val priKey: PrivateKey = privateKey
    val ephPublicKey: ByteArray = ephemeralPublicKey
}

fun generateEphemeralKeyPairs(encodedPublicKey: ByteArray): Keys {
    // Ephemeral Key Pairs
    val keyPairGenerator = KeyPairGenerator.getInstance("EC")
    val ecGenParameterSpec = ECGenParameterSpec("secp256r1") // NIST P-256.
    keyPairGenerator.initialize(ecGenParameterSpec)

    val keyPair = keyPairGenerator.genKeyPair()

    val publicKey = keyPair.public
    val ephemeralPublicKey = ByteArray(65)
    System.arraycopy(keyPair.public.encoded, encodedPublicKey.size - 65, ephemeralPublicKey, 0, 65)

    val privateKey = keyPair.private
    val privateKeyBytes = privateKey.encoded

    // Trim leading zeros if any
    if (privateKeyBytes.size > 32) {
        val trimmedPrivateKeyBytes = ByteArray(32)
        System.arraycopy(privateKeyBytes, privateKeyBytes.size - 32, trimmedPrivateKeyBytes, 0, 32)
    }

    return Keys(publicKey, privateKey, ephemeralPublicKey)
}

fun generateSharedSecret(applePublicKey: PublicKey, ephemeralPrivateKey: PrivateKey): String {
    val keyAgreement = KeyAgreement.getInstance("ECDH")
    keyAgreement.init(ephemeralPrivateKey)
    keyAgreement.doPhase(applePublicKey, true)

    val secretKey = keyAgreement.generateSecret()

    return bytesToHex(secretKey).uppercase()
}

// Helper method to convert bytes to hexadecimal string
fun bytesToHex(bytes: ByteArray): String {
    val stringBuilder = StringBuilder()
    for (b in bytes) {
        stringBuilder.append(String.format("%02x", b))
    }
    return stringBuilder.toString()
}

fun nistKdf(sharedSecret: ByteArray, ephemeralPublicKey: ByteArray): ByteArray {
    val counter = byteArrayOf(0x00, 0x00, 0x00, 0x01)
    val algorithmIdLength = byteArrayOf(0x0D)
    val algorithmId = byteArrayOf(
        0x69, 0x64, 0x2D, 0x61, 0x65, 0x73, 0x32, 0x35, 0x36, 0x2D, 0x47, 0x43, 0x4D
    )
    val partyUInfo = byteArrayOf(0x41, 0x70, 0x70, 0x6C, 0x65)

    val kdfInput = ByteArray(120)
    System.arraycopy(counter, 0, kdfInput, 0, counter.size)
    System.arraycopy(sharedSecret, 0, kdfInput, counter.size, sharedSecret.size)
    System.arraycopy(algorithmIdLength, 0, kdfInput, counter.size + sharedSecret.size, algorithmIdLength.size)
    System.arraycopy(algorithmId, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size, algorithmId.size)
    System.arraycopy(partyUInfo, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size + algorithmId.size, partyUInfo.size)
    System.arraycopy(ephemeralPublicKey, 0, kdfInput, counter.size + sharedSecret.size + algorithmIdLength.size + algorithmId.size + partyUInfo.size, ephemeralPublicKey.size)

    return kdfInput
}

fun hexStringToByteArray(hexString: String): ByteArray {
    val len = hexString.length
    val data = ByteArray(len / 2)
    var i = 0
    while (i < len) {
        data[i / 2] = ((Character.digit(hexString[i], 16) shl 4) + Character.digit(hexString[i + 1], 16)).toByte()
        i += 2
    }
    return data
}

fun byteArrayToHexString(byteArray: ByteArray): String {
    val result = StringBuilder()
    for (b in byteArray) {
        result.append(String.format("%02X", b))
    }
    return result.toString()
}

fun generateSharedAesKey(kdfInput: String): SecretKey {
    val sha256Digest = MessageDigest.getInstance("SHA-256")
    val hashBytes = sha256Digest.digest(hexStringToByteArray2(kdfInput))
    return SecretKeySpec(hashBytes, "AES")
}

fun hexStringToByteArray2(hexString: String): ByteArray {
    val hexChars = hexString.toCharArray()
    val byteLength = hexChars.size / 2
    val byteArray = ByteArray(byteLength)

    for (i in 0..<byteLength) {
        val startIndex = i * 2
        val hexValue = Integer.parseInt(hexChars[startIndex].toString() + hexChars[startIndex + 1], 16)
        byteArray[i] = hexValue.toByte()
    }

    return byteArray
}

fun bytesToHex2(bytes: ByteArray): String {
    val hexArray = "0123456789ABCDEF".toCharArray()
    val hexChars = CharArray(bytes.size * 2)
    for (i in bytes.indices) {
        val v = bytes[i].toInt() and 0xFF
        hexChars[i * 2] = hexArray[v ushr 4]
        hexChars[i * 2 + 1] = hexArray[v and 0x0F]
    }
    return String(hexChars)
}

fun encryptAesGcmWithMac(key: ByteArray, plaintext: ByteArray): ByteArray {
    Security.addProvider(BouncyCastleProvider())

    val cipher = GCMBlockCipher(AESEngine())
    val keyParam = KeyParameter(key)
    val params = AEADParameters(keyParam, 128, ByteArray(12)) // 12-byte null IV

    cipher.init(true, params)

    val ciphertext = ByteArray(cipher.getOutputSize(plaintext.size))

    val outputLength = cipher.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)
    cipher.doFinal(ciphertext, outputLength)

    // Append the MAC to the end of the ciphertext
    val mac = cipher.mac
    val encryptedDataWithMac = ByteArray(ciphertext.size + mac.size)
    System.arraycopy(ciphertext, 0, encryptedDataWithMac, 0, ciphertext.size)
    System.arraycopy(mac, 0, encryptedDataWithMac, ciphertext.size, mac.size)

    return encryptedDataWithMac
}

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

fun main() {
    // Specify the path to the certificate file
    val certificateFilePath = "src/main/resources/Certificate.crt"
    val extractedApplePublicKey = extractApplePublicKey(certificateFilePath)

    //------------------------------------------------------------------------------------------------------------------

    val keyPairs = generateEphemeralKeyPairs(extractedApplePublicKey)

    //------------------------------------------------------------------------------------------------------------------

    val sharedSecretHex = generateSharedSecret(keyPairs.pubKey, keyPairs.priKey)

    //------------------------------------------------------------------------------------------------------------------

    val sharedSecret = hexStringToByteArray(sharedSecretHex)
    val ephemeralPublicKey = hexStringToByteArray(bytesToHex(keyPairs.ephPublicKey))

    val kdfInput = nistKdf(sharedSecret, ephemeralPublicKey)
    val kdfInputHex = byteArrayToHexString(kdfInput)

    //------------------------------------------------------------------------------------------------------------------

    val aesKeyHex = bytesToHex2(generateSharedAesKey(kdfInputHex).encoded)

    //------------------------------------------------------------------------------------------------------------------

    val key = Hex.decode(aesKeyHex)

    // JSON payload (67 bytes), UTF-8 encoded
    val jsonPayload = "{\"Parameter1\":\"Value1\",\"Parameter2\":\"Value2\",\"Parameter3\":\"Value3\"}"
    val plaintext = jsonPayload.toByteArray(Charsets.UTF_8)

    val encryptedDataWithMac = encryptAesGcmWithMac(key, plaintext)

    //------------------------------------------------------------------------------------------------------------------

    val activationData = "5572b844-e46a-4100-b6a4-a6d4c3cd265d".toByteArray()

    // Encode and send data
    val jsonResponse = encodeAndSendData(activationData, keyPairs.ephPublicKey, encryptedDataWithMac)
    println(jsonResponse)
}