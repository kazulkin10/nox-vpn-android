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
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

/**
 * Reality v2 TLS Socket
 *
 * Approach: Send auth immediately after TLS handshake as first bytes.
 * Server reads first 32 bytes after TLS, checks auth, then processes NOX.
 *
 * This is simpler than modifying ClientHello session_id.
 * Auth is encrypted inside TLS, invisible to TSPU.
 */
class RealityTlsSocket(
    private val serverHost: String,
    private val serverPort: Int,
    private val serverSni: String,
    private val serverPublicKey: ByteArray  // 32 bytes - server's X25519 public key
) {
    companion object {
        const val TAG = "RealityTLS"
        const val AUTH_SIZE = 32  // hmac(24) + timestamp(8)
    }

    private var sslSocket: SSLSocket? = null
    private val random = SecureRandom()

    /**
     * Connect, perform TLS handshake, send auth
     * @return input/output streams (auth already sent)
     */
    fun connect(): Pair<InputStream, OutputStream> {
        Log.d(TAG, "Connecting to $serverHost:$serverPort (SNI: $serverSni)")

        // Create SSL socket with trust-all (we verify via NOX handshake)
        val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        })

        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, trustAllCerts, random)
        val factory = sslContext.socketFactory

        val socket = factory.createSocket() as SSLSocket
        socket.connect(InetSocketAddress(serverHost, serverPort), 10000)

        // Set SNI
        val sslParams = socket.sslParameters
        sslParams.serverNames = listOf(javax.net.ssl.SNIHostName(serverSni))
        socket.sslParameters = sslParams

        // Configure TLS
        socket.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
        socket.soTimeout = 30000

        // Perform TLS handshake
        socket.startHandshake()
        Log.d(TAG, "TLS handshake complete")

        sslSocket = socket

        // Send auth immediately after TLS
        val auth = generateAuth()
        socket.outputStream.write(auth)
        socket.outputStream.flush()
        Log.d(TAG, "Auth sent: ${auth.size} bytes")

        return Pair(socket.inputStream, socket.outputStream)
    }

    /**
     * Generate authentication data
     * Format: hmac_tag(24) + timestamp(8) = 32 bytes
     *
     * Server verifies: HMAC(server_private_key, server_pubkey + timestamp)
     */
    private fun generateAuth(): ByteArray {
        val auth = ByteArray(AUTH_SIZE)

        // Timestamp (8 bytes, big-endian, Unix seconds)
        val timestamp = System.currentTimeMillis() / 1000
        val timestampBytes = ByteBuffer.allocate(8)
            .order(ByteOrder.BIG_ENDIAN)
            .putLong(timestamp)
            .array()

        // HMAC-SHA256(server_pubkey, server_pubkey + timestamp)
        // Note: we use server_pubkey as HMAC key because client doesn't have server_private_key
        // Server will verify using its private key
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(serverPublicKey, "HmacSHA256"))
        mac.update(serverPublicKey)
        mac.update(timestampBytes)
        val hmacFull = mac.doFinal()

        // auth = hmac[:24] + timestamp
        System.arraycopy(hmacFull, 0, auth, 0, 24)
        System.arraycopy(timestampBytes, 0, auth, 24, 8)

        Log.d(TAG, "Generated auth, timestamp=$timestamp")
        return auth
    }

    fun getInputStream(): InputStream = sslSocket!!.inputStream
    fun getOutputStream(): OutputStream = sslSocket!!.outputStream

    fun close() {
        try { sslSocket?.close() } catch (_: Exception) {}
        sslSocket = null
    }
}
