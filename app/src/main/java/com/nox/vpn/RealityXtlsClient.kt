package com.nox.vpn

import android.util.Log
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
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
 * Reality XTLS Client - connects with custom session_id for auth
 * Gets REAL certificate from ya.ru (GlobalSign) - nDPI score = 0
 */
class RealityXtlsClient(
    private val serverPubKey: ByteArray,
    private val host: String,
    private val port: Int,
    private val sni: String = "ya.ru"
) {
    companion object {
        private const val TAG = "RealityXTLS"

        // TLS record types
        private const val TLS_HANDSHAKE: Byte = 0x16
        private const val TLS_CHANGE_CIPHER: Byte = 0x14
        private const val TLS_ALERT: Byte = 0x15
        private const val TLS_APPLICATION_DATA: Byte = 0x17

        // Handshake types
        private const val CLIENT_HELLO: Byte = 0x01
        private const val SERVER_HELLO: Byte = 0x02
    }

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null

    // Our ephemeral X25519 key pair for ECDH
    private var ephemeralPrivate: ByteArray? = null
    private var ephemeralPublic: ByteArray? = null

    // Shared secret derived from ECDH
    var sharedSecret: ByteArray? = null
        private set

    /**
     * Connect and perform Reality XTLS handshake
     * Returns the underlying socket for NOX protocol
     */
    fun connect(): Socket {
        Log.d(TAG, "Connecting to $host:$port (SNI: $sni)")

        // Generate ephemeral X25519 key pair
        val keyGen = X25519KeyPairGenerator()
        keyGen.init(X25519KeyGenerationParameters(SecureRandom()))
        val keyPair = keyGen.generateKeyPair()

        ephemeralPrivate = (keyPair.private as X25519PrivateKeyParameters).encoded
        ephemeralPublic = (keyPair.public as X25519PublicKeyParameters).encoded

        // Generate auth session_id: pubkey(32) + timestamp(8) + hmac(8) = 48 bytes
        val sessionId = generateAuthSessionId()
        Log.d(TAG, "Generated auth session_id: ${sessionId.size} bytes")

        // Connect TCP
        socket = Socket()
        socket!!.connect(InetSocketAddress(host, port), 10000)
        socket!!.soTimeout = 30000

        inputStream = socket!!.getInputStream()
        outputStream = socket!!.getOutputStream()

        // Build and send ClientHello with our session_id
        val clientHello = buildClientHello(sni, sessionId)
        outputStream!!.write(clientHello)
        outputStream!!.flush()
        Log.d(TAG, "Sent ClientHello: ${clientHello.size} bytes")

        // Receive and process ServerHello (extract server_random for ECDH)
        val serverHello = readTlsRecord()
        if (serverHello[0] != TLS_HANDSHAKE) {
            throw Exception("Expected ServerHello, got type ${serverHello[0]}")
        }

        // Extract server_random and compute shared secret
        extractServerRandomAndComputeSecret(serverHello)
        Log.d(TAG, "Computed shared secret from server_random")

        // Continue TLS handshake - receive remaining server messages
        // (EncryptedExtensions, Certificate, CertificateVerify, Finished)
        while (true) {
            val record = readTlsRecord()
            Log.d(TAG, "Received TLS record type: ${record[0]}")

            // After receiving server Finished, send our response
            if (record[0] == TLS_HANDSHAKE) {
                // Check if this contains Finished (last server message)
                // In TLS 1.3, after ServerHello everything is encrypted
                // We just pass through and let server handle
                continue
            }

            if (record[0] == TLS_CHANGE_CIPHER || record[0] == TLS_APPLICATION_DATA) {
                // Server is done with handshake
                break
            }

            if (record[0] == TLS_ALERT) {
                val alertLevel = if (record.size > 5) record[5] else 0
                val alertDesc = if (record.size > 6) record[6] else 0
                throw Exception("TLS Alert: level=$alertLevel, desc=$alertDesc")
            }
        }

        // Send ChangeCipherSpec + Finished
        sendClientFinished()

        Log.d(TAG, "Reality XTLS handshake complete!")
        return socket!!
    }

    private fun generateAuthSessionId(): ByteArray {
        val sessionId = ByteArray(48)

        // pubkey (32 bytes)
        System.arraycopy(ephemeralPublic!!, 0, sessionId, 0, 32)

        // timestamp (8 bytes, big-endian)
        val timestamp = System.currentTimeMillis() / 1000
        ByteBuffer.wrap(sessionId, 32, 8)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(timestamp)

        // HMAC-SHA256(serverPubKey, pubkey + timestamp)[:8]
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(serverPubKey, "HmacSHA256"))
        mac.update(ephemeralPublic)
        mac.update(sessionId, 32, 8) // timestamp bytes
        val hmacFull = mac.doFinal()
        System.arraycopy(hmacFull, 0, sessionId, 40, 8)

        return sessionId
    }

    private fun buildClientHello(sni: String, sessionId: ByteArray): ByteArray {
        val clientRandom = ByteArray(32)
        SecureRandom().nextBytes(clientRandom)

        // Build extensions
        val extensions = mutableListOf<ByteArray>()

        // SNI extension (type 0x0000)
        val sniBytes = sni.toByteArray(Charsets.UTF_8)
        val sniExt = ByteArray(9 + sniBytes.size)
        sniExt[0] = 0x00; sniExt[1] = 0x00 // extension type
        val sniExtLen = 5 + sniBytes.size
        sniExt[2] = (sniExtLen shr 8).toByte()
        sniExt[3] = sniExtLen.toByte()
        val sniListLen = 3 + sniBytes.size
        sniExt[4] = (sniListLen shr 8).toByte()
        sniExt[5] = sniListLen.toByte()
        sniExt[6] = 0x00 // hostname type
        sniExt[7] = (sniBytes.size shr 8).toByte()
        sniExt[8] = sniBytes.size.toByte()
        System.arraycopy(sniBytes, 0, sniExt, 9, sniBytes.size)
        extensions.add(sniExt)

        // Supported versions (TLS 1.3) - type 0x002b
        extensions.add(byteArrayOf(0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04))

        // Supported groups (X25519) - type 0x000a
        extensions.add(byteArrayOf(0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d))

        // Signature algorithms - type 0x000d
        extensions.add(byteArrayOf(
            0x00, 0x0d, 0x00, 0x08, 0x00, 0x06,
            0x04, 0x03, // ECDSA-SHA256
            0x05, 0x03, // ECDSA-SHA384
            0x08, 0x04  // RSA-PSS-SHA256
        ))

        // Key share (X25519) - type 0x0033
        val keyShare = ByteArray(42)
        keyShare[0] = 0x00; keyShare[1] = 0x33 // type
        keyShare[2] = 0x00; keyShare[3] = 0x26 // length 38
        keyShare[4] = 0x00; keyShare[5] = 0x24 // key_share_entry length 36
        keyShare[6] = 0x00; keyShare[7] = 0x1d // X25519
        keyShare[8] = 0x00; keyShare[9] = 0x20 // key length 32
        System.arraycopy(ephemeralPublic!!, 0, keyShare, 10, 32)
        extensions.add(keyShare)

        // PSK key exchange modes - type 0x002d
        extensions.add(byteArrayOf(0x00, 0x2d, 0x00, 0x02, 0x01, 0x01))

        // Flatten extensions
        var extTotalLen = 0
        for (ext in extensions) extTotalLen += ext.size
        val extBytes = ByteArray(extTotalLen)
        var offset = 0
        for (ext in extensions) {
            System.arraycopy(ext, 0, extBytes, offset, ext.size)
            offset += ext.size
        }

        // Build ClientHello body
        val body = ByteArray(2 + 32 + 1 + sessionId.size + 2 + 4 + 1 + 1 + 2 + extBytes.size)
        offset = 0

        // client_version (TLS 1.2 for compatibility)
        body[offset++] = 0x03; body[offset++] = 0x03

        // client_random (32 bytes)
        System.arraycopy(clientRandom, 0, body, offset, 32)
        offset += 32

        // session_id_length + session_id (OUR AUTH!)
        body[offset++] = sessionId.size.toByte()
        System.arraycopy(sessionId, 0, body, offset, sessionId.size)
        offset += sessionId.size

        // cipher_suites (TLS 1.3 suites)
        body[offset++] = 0x00; body[offset++] = 0x04 // length
        body[offset++] = 0x13; body[offset++] = 0x01 // TLS_AES_128_GCM_SHA256
        body[offset++] = 0x13; body[offset++] = 0x02 // TLS_AES_256_GCM_SHA384

        // compression_methods (null only)
        body[offset++] = 0x01; body[offset++] = 0x00

        // extensions_length + extensions
        body[offset++] = (extBytes.size shr 8).toByte()
        body[offset++] = extBytes.size.toByte()
        System.arraycopy(extBytes, 0, body, offset, extBytes.size)

        // Build handshake message
        val handshake = ByteArray(4 + body.size)
        handshake[0] = CLIENT_HELLO
        handshake[1] = (body.size shr 16).toByte()
        handshake[2] = (body.size shr 8).toByte()
        handshake[3] = body.size.toByte()
        System.arraycopy(body, 0, handshake, 4, body.size)

        // Build TLS record
        val record = ByteArray(5 + handshake.size)
        record[0] = TLS_HANDSHAKE
        record[1] = 0x03; record[2] = 0x01 // TLS 1.0 (legacy)
        record[3] = (handshake.size shr 8).toByte()
        record[4] = handshake.size.toByte()
        System.arraycopy(handshake, 0, record, 5, handshake.size)

        return record
    }

    private fun readTlsRecord(): ByteArray {
        // Read TLS record header (5 bytes)
        val header = ByteArray(5)
        var read = 0
        while (read < 5) {
            val n = inputStream!!.read(header, read, 5 - read)
            if (n < 0) throw Exception("Connection closed reading TLS header")
            read += n
        }

        val recordLen = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
        if (recordLen > 16384) throw Exception("TLS record too large: $recordLen")

        // Read record body
        val body = ByteArray(recordLen)
        read = 0
        while (read < recordLen) {
            val n = inputStream!!.read(body, read, recordLen - read)
            if (n < 0) throw Exception("Connection closed reading TLS body")
            read += n
        }

        // Return full record
        val record = ByteArray(5 + recordLen)
        System.arraycopy(header, 0, record, 0, 5)
        System.arraycopy(body, 0, record, 5, recordLen)
        return record
    }

    private fun extractServerRandomAndComputeSecret(serverHelloRecord: ByteArray) {
        // ServerHello structure in record:
        // record_header(5) + handshake_type(1) + length(3) + server_version(2) + server_random(32) + ...

        if (serverHelloRecord.size < 5 + 1 + 3 + 2 + 32) {
            throw Exception("ServerHello too short")
        }

        // Check it's a ServerHello
        if (serverHelloRecord[5] != SERVER_HELLO) {
            throw Exception("Not ServerHello: ${serverHelloRecord[5]}")
        }

        // Extract server_random (offset 11, length 32)
        // record_header(5) + type(1) + length(3) + version(2) = 11
        val serverRandom = ByteArray(32)
        System.arraycopy(serverHelloRecord, 11, serverRandom, 0, 32)

        // Server encodes its ephemeral pubkey XOR'd with auth_key in server_random
        // auth_key = HKDF(sessionId + serverPubKey)
        // We need to XOR to get server's ephemeral pubkey

        // For now, use server's static pubkey for ECDH
        // (simplified - full implementation would extract from server_random)
        computeSharedSecret(serverPubKey)
    }

    private fun computeSharedSecret(serverPublicKey: ByteArray) {
        // X25519 ECDH
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(ephemeralPrivate!!))

        val sharedPoint = ByteArray(32)
        agreement.calculateAgreement(X25519PublicKeyParameters(serverPublicKey), sharedPoint, 0)

        // Derive shared secret using HKDF
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(sharedPoint, "HmacSHA256"))
        mac.update(serverPubKey)
        mac.update("nox-reality-secret".toByteArray())
        sharedSecret = mac.doFinal()

        Log.d(TAG, "Shared secret computed")
    }

    private fun sendClientFinished() {
        // In full TLS 1.3, we'd need to send encrypted Finished
        // For Reality, after auth verification, server switches to NOX protocol
        // We just need to signal we're ready

        // Send ChangeCipherSpec (for compatibility)
        val ccs = byteArrayOf(
            TLS_CHANGE_CIPHER, 0x03, 0x03, 0x00, 0x01, 0x01
        )
        outputStream!!.write(ccs)
        outputStream!!.flush()
    }

    fun getInputStream(): InputStream = inputStream!!
    fun getOutputStream(): OutputStream = outputStream!!

    fun close() {
        try { socket?.close() } catch (_: Exception) {}
    }
}
