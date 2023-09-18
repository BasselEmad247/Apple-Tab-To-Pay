package steps

import java.io.FileInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

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

//fun main() {
//    // Specify the path to the certificate file
//    val certificateFilePath = "Certificate.crt"
//    val extractedApplePublicKey = extractApplePublicKey(certificateFilePath)
//}