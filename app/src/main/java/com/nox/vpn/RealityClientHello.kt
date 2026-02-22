package com.nox.vpn

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Reality v2 - Manual TLS ClientHello with auth in session_id
 *
 * We build ClientHello manually to control session_id field.
 * After sending ClientHello, we switch to standard TLS for the rest.
 *
 * Flow:
 * 1. Build ClientHello with auth in session_id
 * 2. Send to server (plaintext - server can read session_id)
 * 3. Server verifies auth, decides to handle or proxy
 * 4. Continue TLS handshake normally
 */
object RealityClientHello {
    const val TAG = "RealityHello"

    /**
     * Generate auth data for session_id
     * Format: hmac_tag(24) + timestamp(8) = 32 bytes
     */
    fun generateAuthSessionId(serverPublicKey: ByteArray): ByteArray {
        val sessionId = ByteArray(32)
        val random = SecureRandom()

        // Timestamp (8 bytes, big-endian, Unix seconds)
        val timestamp = System.currentTimeMillis() / 1000
        val timestampBytes = ByteBuffer.allocate(8)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(timestamp)
            .array()

        // HMAC-SHA256(server_pubkey, server_pubkey + timestamp)
        // Server uses server_pubkey as auth secret (derived from private key)
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(serverPublicKey, "HmacSHA256"))
        mac.update(serverPublicKey)
        mac.update(timestampBytes)
        val hmacFull = mac.doFinal()

        // session_id = hmac[:24] + timestamp
        System.arraycopy(hmacFull, 0, sessionId, 0, 24)
        System.arraycopy(timestampBytes, 0, sessionId, 24, 8)

        Log.d(TAG, "Generated session_id auth, timestamp=$timestamp")
        return sessionId
    }

    /**
     * Build TLS 1.2 ClientHello with custom session_id
     *
     * Structure:
     * - Record layer: type(1) + version(2) + length(2)
     * - Handshake: type(1) + length(3)
     * - ClientHello: version(2) + random(32) + session_id_len(1) + session_id + ...
     */
    fun buildClientHello(sni: String, sessionId: ByteArray): ByteArray {
        val random = SecureRandom()

        // Client random (32 bytes)
        val clientRandom = ByteArray(32)
        random.nextBytes(clientRandom)

        // Cipher suites (TLS 1.3 + TLS 1.2)
        val cipherSuites = byteArrayOf(
            // TLS 1.3
            0x13, 0x01,  // TLS_AES_128_GCM_SHA256
            0x13, 0x02,  // TLS_AES_256_GCM_SHA384
            0x13, 0x03,  // TLS_CHACHA20_POLY1305_SHA256
            // TLS 1.2
            0xc0.toByte(), 0x2c,  // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc0.toByte(), 0x2b,  // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc0.toByte(), 0x30,  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0xc0.toByte(), 0x2f,  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        )

        // SNI extension
        val sniBytes = sni.toByteArray(Charsets.US_ASCII)
        val sniExtension = ByteBuffer.allocate(9 + sniBytes.size)
        sniExtension.putShort(0x0000.toShort())  // extension type: server_name
        sniExtension.putShort((5 + sniBytes.size).toShort())  // extension length
        sniExtension.putShort((3 + sniBytes.size).toShort())  // server_name_list length
        sniExtension.put(0x00)  // name_type: host_name
        sniExtension.putShort(sniBytes.size.toShort())  // host_name length
        sniExtension.put(sniBytes)

        // Supported versions extension (TLS 1.3)
        val versionsExtension = byteArrayOf(
            0x00, 0x2b,  // extension type: supported_versions
            0x00, 0x05,  // extension length
            0x04,        // versions length
            0x03, 0x04,  // TLS 1.3
            0x03, 0x03   // TLS 1.2
        )

        // Supported groups extension
        val groupsExtension = byteArrayOf(
            0x00, 0x0a,  // extension type: supported_groups
            0x00, 0x08,  // extension length
            0x00, 0x06,  // groups length
            0x00, 0x1d,  // x25519
            0x00, 0x17,  // secp256r1
            0x00, 0x18   // secp384r1
        )

        // Signature algorithms extension
        val sigAlgsExtension = byteArrayOf(
            0x00, 0x0d,  // extension type: signature_algorithms
            0x00, 0x10,  // extension length
            0x00, 0x0e,  // algorithms length
            0x04, 0x03,  // ecdsa_secp256r1_sha256
            0x05, 0x03,  // ecdsa_secp384r1_sha384
            0x08, 0x04,  // rsa_pss_rsae_sha256
            0x08, 0x05,  // rsa_pss_rsae_sha384
            0x08, 0x06,  // rsa_pss_rsae_sha512
            0x04, 0x01,  // rsa_pkcs1_sha256
            0x05, 0x01   // rsa_pkcs1_sha384
        )

        // Key share extension (x25519)
        val keySharePrivate = ByteArray(32)
        random.nextBytes(keySharePrivate)
        // For simplicity, use random as public key (server will generate real keys)
        val keySharePublic = ByteArray(32)
        random.nextBytes(keySharePublic)

        val keyShareExtension = ByteBuffer.allocate(40)
        keyShareExtension.putShort(0x0033.toShort())  // extension type: key_share
        keyShareExtension.putShort(36.toShort())     // extension length
        keyShareExtension.putShort(34.toShort())     // key_share_entry length
        keyShareExtension.putShort(0x001d.toShort()) // group: x25519
        keyShareExtension.putShort(32.toShort())     // key_exchange length
        keyShareExtension.put(keySharePublic)

        // EC point formats
        val ecFormatsExtension = byteArrayOf(
            0x00, 0x0b,  // extension type: ec_point_formats
            0x00, 0x02,  // extension length
            0x01,        // formats length
            0x00         // uncompressed
        )

        // Combine all extensions
        val extensions = sniExtension.array() +
                versionsExtension +
                groupsExtension +
                sigAlgsExtension +
                keyShareExtension.array() +
                ecFormatsExtension

        // Build ClientHello body
        val clientHelloBody = ByteBuffer.allocate(
            2 +  // client_version
            32 + // random
            1 +  // session_id_length
            sessionId.size +
            2 +  // cipher_suites_length
            cipherSuites.size +
            1 +  // compression_methods_length
            1 +  // compression_methods (null)
            2 +  // extensions_length
            extensions.size
        )
        clientHelloBody.order(ByteOrder.BIG_ENDIAN)

        clientHelloBody.putShort(0x0303.toShort())  // TLS 1.2 (for compatibility, real version in extension)
        clientHelloBody.put(clientRandom)
        clientHelloBody.put(sessionId.size.toByte())
        clientHelloBody.put(sessionId)
        clientHelloBody.putShort(cipherSuites.size.toShort())
        clientHelloBody.put(cipherSuites)
        clientHelloBody.put(1)  // compression_methods_length
        clientHelloBody.put(0)  // null compression
        clientHelloBody.putShort(extensions.size.toShort())
        clientHelloBody.put(extensions)

        val clientHelloBodyBytes = clientHelloBody.array()

        // Build Handshake message
        val handshake = ByteBuffer.allocate(4 + clientHelloBodyBytes.size)
        handshake.put(0x01)  // ClientHello
        handshake.put(0)     // length high byte
        handshake.putShort(clientHelloBodyBytes.size.toShort())  // length
        handshake.put(clientHelloBodyBytes)

        val handshakeBytes = handshake.array()

        // Build TLS record
        val record = ByteBuffer.allocate(5 + handshakeBytes.size)
        record.put(0x16)  // Handshake
        record.putShort(0x0301.toShort())  // TLS 1.0 (record layer version)
        record.putShort(handshakeBytes.size.toShort())
        record.put(handshakeBytes)

        Log.d(TAG, "Built ClientHello: ${record.array().size} bytes, session_id=${sessionId.size} bytes")
        return record.array()
    }
}
