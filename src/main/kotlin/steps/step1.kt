package steps

import java.io.FileInputStream
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

fun extractApplePublicKey(leafCertificateFilePath: String): PublicKey {
    // Load the certificate file
    val fileInputStream = FileInputStream(leafCertificateFilePath)

    // Create a CertificateFactory instance for X.509 certificates
    val certificateFactory = CertificateFactory.getInstance("X.509")

    // Load the certificate
    val certificate = certificateFactory.generateCertificate(fileInputStream) as X509Certificate

    // Close the FileInputStream
    fileInputStream.close()

    // Retrieve the public key from the certificate
    return certificate.publicKey
}

//fun main() {
//    // Specify the path to the leaf certificate file
//    val leafCertificateFilePath = "src/main/resources/Certificate.crt"
//    val extractedApplePublicKey = extractApplePublicKey(leafCertificateFilePath)
//}