package com.nox.vpn

import android.util.Log
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.net.ssl.SSLSocket

/**
 * NOX v3 Protocol Implementation using Google Tink
 *
 * Handshake:
 * 1. Client generates ephemeral X25519 keypair
 * 2. Client sends ClientHello: client_ephemeral(32) + nonce(24) + len_xor(2) + encrypted_payload
 * 3. Server sends ServerHello: server_ephemeral(32) + nonce(24) + len_xor(2) + encrypted_payload
 * 4. Both derive session keys using HKDF
 *
 * Data frames:
 * encrypted_length(4) + ciphertext(includes 16-byte tag)
 */
class NoxProtocol(
    private val serverPublicKey: ByteArray,
    private val socket: SSLSocket
) {
    companion object {
        const val TAG = "NoxProtocol"
        const val KEY_SIZE = 32
        const val NONCE_SIZE = 24  // XChaCha20 uses 24-byte nonce
        const val TAG_SIZE = 16
        const val MTU = 1280
        const val FRAME_TYPE_DATA: Byte = 0x01
    }

    private lateinit var txCipher: NoxCipher
    private lateinit var rxCipher: NoxCipher
    private var assignedIp: String = ""

    private val random = SecureRandom()

    /**
     * Perform NOX handshake and derive session keys
     * @return assigned IPv4 address
     */
    fun handshake(): String {
        val input = socket.inputStream
        val output = socket.outputStream

        // Generate client ephemeral keypair using Tink's X25519
        val clientPrivate = X25519.generatePrivateKey()
        val clientPublic = X25519.publicFromPrivate(clientPrivate)

        Log.d(TAG, "Client public key: ${clientPublic.toHex()}")
        Log.d(TAG, "Server public key: ${serverPublicKey.toHex()}")

        // Build ClientHello payload
        val padding = ByteArray(64)
        random.nextBytes(padding)

        val timestamp = System.currentTimeMillis() * 1000 // microseconds
        val caps: Short = 0x20 // CapBatch
        val mtu: Short = MTU.toShort()
        val sessionId = ByteArray(8)
        random.nextBytes(sessionId)

        // Payload: padding_len(1) + padding + timestamp(8) + ephemeral(32) + caps(2) + mtu(2) + session_id(8)
        val payload = ByteBuffer.allocate(1 + padding.size + 8 + 32 + 2 + 2 + 8)
        payload.order(ByteOrder.BIG_ENDIAN)
        payload.put(padding.size.toByte())
        payload.put(padding)
        payload.putLong(timestamp)
        payload.put(clientPublic)
        payload.putShort(caps)
        payload.putShort(mtu)
        payload.put(sessionId)
        val payloadBytes = payload.array()

        // Derive early key: DH(client_ephemeral, server_static)
        val esSecret = X25519.computeSharedSecret(clientPrivate, serverPublicKey)
        Log.d(TAG, "ES shared secret: ${esSecret.toHex()}")

        val earlyKey = Hkdf.computeHkdf(
            "HMACSHA256",
            esSecret,
            null, // no salt
            "noxv3-hello".toByteArray(),
            KEY_SIZE
        )
        Log.d(TAG, "Early key: ${earlyKey.toHex()}")

        // Encrypt ClientHello using Tink's XChaCha20-Poly1305
        val nonce = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce)

        val earlyCipher = XChaCha20Poly1305(earlyKey)
        val ciphertext = earlyCipher.encrypt(payloadBytes, nonce)

        Log.d(TAG, "Nonce: ${nonce.toHex()}")
        Log.d(TAG, "Ciphertext length: ${ciphertext.size}")

        // Wire format: client_ephemeral(32) + nonce(24) + len_xor(2) + ciphertext
        val totalLen = ciphertext.size
        val wire = ByteBuffer.allocate(32 + NONCE_SIZE + 2 + totalLen)
        wire.put(clientPublic)
        wire.put(nonce)

        // XOR'd length
        val lenBytes = ByteArray(2)
        lenBytes[0] = ((totalLen shr 8) and 0xFF).toByte()
        lenBytes[1] = (totalLen and 0xFF).toByte()
        lenBytes[0] = (lenBytes[0].toInt() xor nonce[0].toInt()).toByte()
        lenBytes[1] = (lenBytes[1].toInt() xor nonce[1].toInt()).toByte()
        wire.put(lenBytes)
        wire.put(ciphertext)

        output.write(wire.array())
        output.flush()
        Log.d(TAG, "Sent ClientHello: ${wire.array().size} bytes")

        // Read ServerHello
        // First: server_ephemeral(32)
        val serverEphemeral = readFull(input, 32)
        Log.d(TAG, "Server ephemeral: ${serverEphemeral.toHex()}")

        // Derive full session key
        val eeSecret = X25519.computeSharedSecret(clientPrivate, serverEphemeral)
        Log.d(TAG, "EE shared secret: ${eeSecret.toHex()}")

        val transcript = sha256(payloadBytes)
        val combined = esSecret + eeSecret
        val sessionKey = Hkdf.computeHkdf(
            "HMACSHA256",
            combined,
            transcript,
            "noxv3-session".toByteArray(),
            KEY_SIZE
        )
        Log.d(TAG, "Session key: ${sessionKey.toHex()}")

        // Read rest of ServerHello
        val serverNonce = readFull(input, NONCE_SIZE)
        val serverLenEnc = readFull(input, 2)
        serverLenEnc[0] = (serverLenEnc[0].toInt() xor serverNonce[0].toInt()).toByte()
        serverLenEnc[1] = (serverLenEnc[1].toInt() xor serverNonce[1].toInt()).toByte()
        val serverLen = ((serverLenEnc[0].toInt() and 0xFF) shl 8) or (serverLenEnc[1].toInt() and 0xFF)

        Log.d(TAG, "Server ciphertext length: $serverLen")

        if (serverLen < 50 || serverLen > 1024) {
            throw Exception("Invalid ServerHello length: $serverLen")
        }

        val serverCiphertext = readFull(input, serverLen)

        // Decrypt ServerHello
        val hsKey = Hkdf.computeHkdf(
            "HMACSHA256",
            sessionKey,
            null,
            "noxv3-serverhello".toByteArray(),
            KEY_SIZE
        )
        val hsCipher = XChaCha20Poly1305(hsKey)
        val serverPayload = hsCipher.decrypt(serverCiphertext, serverNonce)

        // Parse ServerHello
        // Format: padding_len(1) + padding + server_ephemeral(32) + ipv4(4) + ipv6(16) + prefix4(1) + prefix6(1) + mtu(2) + session(8) + time(8)
        val paddingLen = serverPayload[0].toInt() and 0xFF
        val ipv4Offset = 1 + paddingLen + 32

        if (serverPayload.size < ipv4Offset + 4) {
            throw Exception("ServerHello too short: ${serverPayload.size}")
        }

        val ipv4Bytes = serverPayload.sliceArray(ipv4Offset until ipv4Offset + 4)
        assignedIp = "${ipv4Bytes[0].toInt() and 0xFF}.${ipv4Bytes[1].toInt() and 0xFF}.${ipv4Bytes[2].toInt() and 0xFF}.${ipv4Bytes[3].toInt() and 0xFF}"

        Log.d(TAG, "Assigned IP: $assignedIp")

        // Create TX/RX ciphers
        val txKey = Hkdf.computeHkdf("HMACSHA256", sessionKey, null, "noxv3-tx".toByteArray(), KEY_SIZE)
        val rxKey = Hkdf.computeHkdf("HMACSHA256", sessionKey, null, "noxv3-rx".toByteArray(), KEY_SIZE)
        txCipher = NoxCipher(txKey)
        rxCipher = NoxCipher(rxKey)

        return assignedIp
    }

    /**
     * Send a VPN packet through the NOX tunnel
     */
    fun sendPacket(data: ByteArray) {
        // Frame: type(1) + data
        val frame = ByteArray(1 + data.size)
        frame[0] = FRAME_TYPE_DATA
        System.arraycopy(data, 0, frame, 1, data.size)

        // Encrypt
        val seq = txCipher.nextSeq()
        val encrypted = txCipher.seal(frame)

        // Wire: encrypted_length(4) + ciphertext
        val lenBytes = ByteArray(4)
        val mask = txCipher.lengthMask(seq)
        ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).putInt(encrypted.size)
        for (i in 0..3) {
            lenBytes[i] = (lenBytes[i].toInt() xor mask[i].toInt()).toByte()
        }

        val wire = ByteArray(4 + encrypted.size)
        System.arraycopy(lenBytes, 0, wire, 0, 4)
        System.arraycopy(encrypted, 0, wire, 4, encrypted.size)

        socket.outputStream.write(wire)
    }

    /**
     * Receive a VPN packet from the NOX tunnel
     * @return the decrypted packet data, or null if non-data frame
     */
    fun receivePacket(): ByteArray? {
        val input = socket.inputStream

        // Read encrypted length (4 bytes)
        val lenBytes = readFull(input, 4)
        val seq = rxCipher.currentSeq()
        val mask = rxCipher.lengthMask(seq)
        for (i in 0..3) {
            lenBytes[i] = (lenBytes[i].toInt() xor mask[i].toInt()).toByte()
        }
        val length = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).int

        if (length < TAG_SIZE || length > MTU + 1 + TAG_SIZE + 100) {
            throw Exception("Invalid frame length: $length")
        }

        // Read ciphertext
        val ciphertext = readFull(input, length)

        // Decrypt
        val frame = rxCipher.open(ciphertext)
            ?: throw Exception("Decryption failed")

        // Parse frame
        if (frame.isEmpty()) return null
        val frameType = frame[0]

        if (frameType != FRAME_TYPE_DATA) return null

        return frame.sliceArray(1 until frame.size)
    }

    fun getAssignedIp(): String = assignedIp

    // ============ Helpers ============

    private fun sha256(data: ByteArray): ByteArray {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        return digest.digest(data)
    }

    private fun readFull(input: InputStream, length: Int): ByteArray {
        val buf = ByteArray(length)
        var read = 0
        while (read < length) {
            val n = input.read(buf, read, length - read)
            if (n < 0) throw Exception("Connection closed")
            read += n
        }
        return buf
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /**
     * Cipher state for data frames using Tink
     */
    inner class NoxCipher(private val key: ByteArray) {
        private var seq: Long = 0
        private val lengthKey = Hkdf.computeHkdf("HMACSHA256", key, null, "noxv3-length".toByteArray(), KEY_SIZE)
        private val aead = XChaCha20Poly1305(key)

        fun nextSeq(): Long = seq++
        fun currentSeq(): Long = seq

        fun seal(plaintext: ByteArray): ByteArray {
            val currentSeq = nextSeq()
            val nonce = buildNonce(currentSeq)
            return aead.encrypt(plaintext, nonce)
        }

        fun open(ciphertext: ByteArray): ByteArray? {
            val currentSeq = seq++
            val nonce = buildNonce(currentSeq)
            return try {
                aead.decrypt(ciphertext, nonce)
            } catch (e: Exception) {
                Log.e(TAG, "Decryption failed: ${e.message}")
                null
            }
        }

        fun lengthMask(seq: Long): ByteArray {
            val mask = ByteArray(4)
            val seqBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(seq).array()
            mask[0] = (lengthKey[0].toInt() xor seqBytes[4].toInt()).toByte()
            mask[1] = (lengthKey[1].toInt() xor seqBytes[5].toInt()).toByte()
            mask[2] = (lengthKey[2].toInt() xor seqBytes[6].toInt()).toByte()
            mask[3] = (lengthKey[3].toInt() xor seqBytes[7].toInt()).toByte()
            return mask
        }

        private fun buildNonce(seq: Long): ByteArray {
            val nonce = ByteArray(NONCE_SIZE)
            System.arraycopy(lengthKey, 0, nonce, 0, 16)
            ByteBuffer.wrap(nonce, 16, 8).order(ByteOrder.BIG_ENDIAN).putLong(seq)
            return nonce
        }
    }
}
