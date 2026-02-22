package com.nox.vpn

import android.util.Log
import com.google.crypto.tink.subtle.Hkdf
import com.google.crypto.tink.subtle.X25519
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.net.Socket

/**
 * NOX v3 Protocol Implementation
 * Uses BouncyCastle for XChaCha20-Poly1305 with explicit nonce control
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
    private val socket: Socket  // Changed from SSLSocket to Socket for Reality XTLS compatibility
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
        val caps: Short = 0x00 // Simple frame mode (not batch!)
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

        // Encrypt ClientHello using XChaCha20-Poly1305 (BouncyCastle)
        val nonce = ByteArray(NONCE_SIZE)
        random.nextBytes(nonce)

        val ciphertext = xchachaSeal(earlyKey, nonce, payloadBytes)

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
        val serverPayload = xchachaOpen(hsKey, serverNonce, serverCiphertext)
            ?: throw Exception("Failed to decrypt ServerHello")

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
     * Server protocol: encrypted_length(2) + ciphertext
     * Frame format: type(1) + flags(1) + padding_len(1) + data
     */
    fun sendPacket(data: ByteArray) {
        // Frame: type(1) + flags(1) + padding_len(1) + data
        val frame = ByteArray(3 + data.size)
        frame[0] = FRAME_TYPE_DATA  // type
        frame[1] = 0                // flags
        frame[2] = 0                // padding_len
        System.arraycopy(data, 0, frame, 3, data.size)

        // Encrypt frame - txCipher.seal() uses current seq then increments
        val encrypted = txCipher.seal(frame)

        // Get seq AFTER seal (server uses seq after increment for length encryption)
        val seq = txCipher.currentSeq()

        // Wire: encrypted_length(2) + ciphertext (server uses 2 bytes!)
        val lenBytes = ByteArray(2)
        val mask = txCipher.lengthMask2(seq)
        lenBytes[0] = ((encrypted.size shr 8) and 0xFF).toByte()
        lenBytes[1] = (encrypted.size and 0xFF).toByte()
        lenBytes[0] = (lenBytes[0].toInt() xor mask[0].toInt()).toByte()
        lenBytes[1] = (lenBytes[1].toInt() xor mask[1].toInt()).toByte()

        val wire = ByteArray(2 + encrypted.size)
        System.arraycopy(lenBytes, 0, wire, 0, 2)
        System.arraycopy(encrypted, 0, wire, 2, encrypted.size)

        socket.outputStream.write(wire)
        socket.outputStream.flush()
    }

    /**
     * Receive a VPN packet from the NOX tunnel
     * Server protocol: encrypted_length(2) + ciphertext
     * Frame format: type(1) + flags(1) + padding_len(1) + padding + data
     * @return the decrypted packet data, or null if non-data frame
     */
    fun receivePacket(): ByteArray? {
        val input = socket.inputStream

        // Read encrypted length (2 bytes - server uses 2!)
        val lenBytes = readFull(input, 2)

        // Increment seq BEFORE decryption (server does this)
        rxCipher.incrementSeq()
        val seq = rxCipher.currentSeq()

        val mask = rxCipher.lengthMask2(seq)
        lenBytes[0] = (lenBytes[0].toInt() xor mask[0].toInt()).toByte()
        lenBytes[1] = (lenBytes[1].toInt() xor mask[1].toInt()).toByte()
        val length = ((lenBytes[0].toInt() and 0xFF) shl 8) or (lenBytes[1].toInt() and 0xFF)

        if (length < TAG_SIZE || length > MTU + 3 + TAG_SIZE + 256) {
            throw Exception("Invalid frame length: $length")
        }

        // Read ciphertext
        val ciphertext = readFull(input, length)

        // Decrypt using seq-1 (server does Open(fc.rxSeq-1, ...))
        val frame = rxCipher.open(seq - 1, ciphertext)
            ?: throw Exception("Decryption failed")

        // Parse frame: type(1) + flags(1) + padding_len(1) + padding + data
        if (frame.size < 3) return null
        val frameType = frame[0]
        // val flags = frame[1]  // not used for now
        val paddingLen = frame[2].toInt() and 0xFF

        if (frame.size < 3 + paddingLen) return null

        if (frameType != FRAME_TYPE_DATA) return null

        // Return data after header and padding
        return frame.sliceArray(3 + paddingLen until frame.size)
    }

    fun getAssignedIp(): String = assignedIp

    // ============ XChaCha20-Poly1305 using BouncyCastle ============

    /**
     * HChaCha20 - derives subkey from key and first 16 bytes of nonce
     */
    private fun hchacha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        require(key.size == 32) { "Key must be 32 bytes" }
        require(nonce16.size == 16) { "Nonce must be 16 bytes" }

        // Constants "expand 32-byte k"
        val state = IntArray(16)
        state[0] = 0x61707865
        state[1] = 0x3320646e
        state[2] = 0x79622d32
        state[3] = 0x6b206574

        // Key
        for (i in 0..7) {
            state[4 + i] = littleEndianToInt(key, i * 4)
        }

        // Nonce
        for (i in 0..3) {
            state[12 + i] = littleEndianToInt(nonce16, i * 4)
        }

        // 20 rounds
        for (i in 0..9) {
            quarterRound(state, 0, 4, 8, 12)
            quarterRound(state, 1, 5, 9, 13)
            quarterRound(state, 2, 6, 10, 14)
            quarterRound(state, 3, 7, 11, 15)
            quarterRound(state, 0, 5, 10, 15)
            quarterRound(state, 1, 6, 11, 12)
            quarterRound(state, 2, 7, 8, 13)
            quarterRound(state, 3, 4, 9, 14)
        }

        // Extract output (first 4 and last 4 words)
        val output = ByteArray(32)
        intToLittleEndian(state[0], output, 0)
        intToLittleEndian(state[1], output, 4)
        intToLittleEndian(state[2], output, 8)
        intToLittleEndian(state[3], output, 12)
        intToLittleEndian(state[12], output, 16)
        intToLittleEndian(state[13], output, 20)
        intToLittleEndian(state[14], output, 24)
        intToLittleEndian(state[15], output, 28)

        return output
    }

    private fun quarterRound(state: IntArray, a: Int, b: Int, c: Int, d: Int) {
        state[a] = state[a] + state[b]; state[d] = rotl32(state[d] xor state[a], 16)
        state[c] = state[c] + state[d]; state[b] = rotl32(state[b] xor state[c], 12)
        state[a] = state[a] + state[b]; state[d] = rotl32(state[d] xor state[a], 8)
        state[c] = state[c] + state[d]; state[b] = rotl32(state[b] xor state[c], 7)
    }

    private fun rotl32(v: Int, n: Int): Int = (v shl n) or (v ushr (32 - n))

    private fun littleEndianToInt(bs: ByteArray, off: Int): Int =
        (bs[off].toInt() and 0xFF) or
        ((bs[off + 1].toInt() and 0xFF) shl 8) or
        ((bs[off + 2].toInt() and 0xFF) shl 16) or
        ((bs[off + 3].toInt() and 0xFF) shl 24)

    private fun intToLittleEndian(n: Int, bs: ByteArray, off: Int) {
        bs[off] = n.toByte()
        bs[off + 1] = (n ushr 8).toByte()
        bs[off + 2] = (n ushr 16).toByte()
        bs[off + 3] = (n ushr 24).toByte()
    }

    /**
     * XChaCha20-Poly1305 encryption with explicit nonce
     */
    private fun xchachaSeal(key: ByteArray, nonce24: ByteArray, plaintext: ByteArray): ByteArray {
        require(nonce24.size == 24) { "Nonce must be 24 bytes" }

        // Derive subkey using HChaCha20
        val subkey = hchacha20(key, nonce24.sliceArray(0..15))

        // Create ChaCha20 nonce: 4 zero bytes + last 8 bytes of original nonce
        val chacha20Nonce = ByteArray(12)
        System.arraycopy(nonce24, 16, chacha20Nonce, 4, 8)

        // Encrypt with ChaCha20
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(subkey), chacha20Nonce))

        // Generate Poly1305 key (first 32 bytes of keystream)
        val polyKey = ByteArray(64)
        engine.processBytes(polyKey, 0, 64, polyKey, 0)
        val poly1305Key = polyKey.sliceArray(0..31)

        // Encrypt plaintext
        val ciphertext = ByteArray(plaintext.size)
        engine.processBytes(plaintext, 0, plaintext.size, ciphertext, 0)

        // Compute Poly1305 tag
        val mac = Poly1305()
        mac.init(KeyParameter(poly1305Key))
        mac.update(ciphertext, 0, ciphertext.size)

        // Padding for ciphertext
        val padLen = (16 - (ciphertext.size % 16)) % 16
        if (padLen > 0) {
            mac.update(ByteArray(padLen), 0, padLen)
        }

        // Lengths (8 bytes each, little-endian)
        val lenBuf = ByteArray(16)
        longToLittleEndian(0L, lenBuf, 0) // no AAD
        longToLittleEndian(plaintext.size.toLong(), lenBuf, 8)
        mac.update(lenBuf, 0, 16)

        val tag = ByteArray(16)
        mac.doFinal(tag, 0)

        // Return ciphertext + tag
        return ciphertext + tag
    }

    /**
     * XChaCha20-Poly1305 decryption with explicit nonce
     */
    private fun xchachaOpen(key: ByteArray, nonce24: ByteArray, ciphertextWithTag: ByteArray): ByteArray? {
        require(nonce24.size == 24) { "Nonce must be 24 bytes" }
        if (ciphertextWithTag.size < TAG_SIZE) return null

        val ciphertext = ciphertextWithTag.sliceArray(0 until ciphertextWithTag.size - TAG_SIZE)
        val tag = ciphertextWithTag.sliceArray(ciphertextWithTag.size - TAG_SIZE until ciphertextWithTag.size)

        // Derive subkey using HChaCha20
        val subkey = hchacha20(key, nonce24.sliceArray(0..15))

        // Create ChaCha20 nonce
        val chacha20Nonce = ByteArray(12)
        System.arraycopy(nonce24, 16, chacha20Nonce, 4, 8)

        // Generate Poly1305 key
        val engine = ChaCha7539Engine()
        engine.init(true, ParametersWithIV(KeyParameter(subkey), chacha20Nonce))
        val polyKey = ByteArray(64)
        engine.processBytes(polyKey, 0, 64, polyKey, 0)
        val poly1305Key = polyKey.sliceArray(0..31)

        // Verify tag
        val mac = Poly1305()
        mac.init(KeyParameter(poly1305Key))
        mac.update(ciphertext, 0, ciphertext.size)

        val padLen = (16 - (ciphertext.size % 16)) % 16
        if (padLen > 0) {
            mac.update(ByteArray(padLen), 0, padLen)
        }

        val lenBuf = ByteArray(16)
        longToLittleEndian(0L, lenBuf, 0)
        longToLittleEndian(ciphertext.size.toLong(), lenBuf, 8)
        mac.update(lenBuf, 0, 16)

        val computedTag = ByteArray(16)
        mac.doFinal(computedTag, 0)

        if (!constantTimeEquals(tag, computedTag)) {
            Log.e(TAG, "Tag verification failed")
            return null
        }

        // Decrypt
        engine.init(true, ParametersWithIV(KeyParameter(subkey), chacha20Nonce))
        // Skip first 64 bytes (Poly1305 key)
        val skip = ByteArray(64)
        engine.processBytes(skip, 0, 64, skip, 0)

        val plaintext = ByteArray(ciphertext.size)
        engine.processBytes(ciphertext, 0, ciphertext.size, plaintext, 0)

        return plaintext
    }

    private fun longToLittleEndian(n: Long, bs: ByteArray, off: Int) {
        bs[off] = n.toByte()
        bs[off + 1] = (n ushr 8).toByte()
        bs[off + 2] = (n ushr 16).toByte()
        bs[off + 3] = (n ushr 24).toByte()
        bs[off + 4] = (n ushr 32).toByte()
        bs[off + 5] = (n ushr 40).toByte()
        bs[off + 6] = (n ushr 48).toByte()
        bs[off + 7] = (n ushr 56).toByte()
    }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var result = 0
        for (i in a.indices) {
            result = result or (a[i].toInt() xor b[i].toInt())
        }
        return result == 0
    }

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
     * Cipher state for data frames
     * Matches server's CipherState implementation
     */
    inner class NoxCipher(private val key: ByteArray) {
        private var seq: Long = 0
        private val lengthKey = Hkdf.computeHkdf("HMACSHA256", key, null, "noxv3-length".toByteArray(), KEY_SIZE)

        fun incrementSeq() { seq++ }
        fun currentSeq(): Long = seq

        /**
         * Encrypt plaintext. Uses current seq, then increments.
         * Matches server: Seal(plaintext) then txSeq++
         */
        fun seal(plaintext: ByteArray): ByteArray {
            val currentSeq = seq
            seq++
            val nonce = buildNonce(currentSeq)
            return xchachaSeal(key, nonce, plaintext)
        }

        /**
         * Decrypt ciphertext using specific seq.
         * Matches server: Open(rxSeq-1, ciphertext)
         */
        fun open(useSeq: Long, ciphertext: ByteArray): ByteArray? {
            val nonce = buildNonce(useSeq)
            return xchachaOpen(key, nonce, ciphertext)
        }

        /**
         * Generate 2-byte length mask for given seq.
         * Matches server's lengthMask() for EncryptLength/DecryptLength
         * Server code: mask[0] = lengthKey[0] ^ seqBytes[6]
         *              mask[1] = lengthKey[1] ^ seqBytes[7]
         */
        fun lengthMask2(seq: Long): ByteArray {
            val mask = ByteArray(2)
            val seqBytes = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(seq).array()
            // Server uses last 2 bytes of seq (indices 6, 7)
            mask[0] = (lengthKey[0].toInt() xor seqBytes[6].toInt()).toByte()
            mask[1] = (lengthKey[1].toInt() xor seqBytes[7].toInt()).toByte()
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
