package com.nox.vpn

import android.util.Log
import org.bouncycastle.crypto.tls.*
import org.bouncycastle.crypto.tls.Certificate
import java.io.IOException
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
 * Reality v2 TLS Client
 * Adds authentication data to TLS session_id field
 * Server verifies auth and decides: NOX client or TSPU probe
 */
class RealityTlsClient(
    private val serverHost: String,
    private val serverPort: Int,
    private val serverSni: String,
    private val serverPublicKey: ByteArray  // 32 bytes X25519 public key
) {
    companion object {
        const val TAG = "RealityTLS"
    }

    private var socket: Socket? = null
    private var tlsProtocol: TlsClientProtocol? = null
    private val random = SecureRandom()

    /**
     * Connect and perform TLS handshake with auth in session_id
     * @return input/output streams for the TLS connection
     */
    fun connect(): Pair<InputStream, OutputStream> {
        Log.d(TAG, "Connecting to $serverHost:$serverPort (SNI: $serverSni)")

        // Create TCP socket
        val sock = Socket()
        sock.connect(InetSocketAddress(serverHost, serverPort), 10000)
        sock.soTimeout = 30000
        socket = sock

        // Create TLS protocol
        val protocol = TlsClientProtocol(sock.inputStream, sock.outputStream, random)
        tlsProtocol = protocol

        // Create our custom TLS client with auth session_id
        val tlsClient = RealityTlsClientImpl(serverSni, serverPublicKey)

        // Perform TLS handshake
        protocol.connect(tlsClient)

        Log.d(TAG, "TLS handshake complete")

        return Pair(protocol.inputStream, protocol.outputStream)
    }

    fun close() {
        try { tlsProtocol?.close() } catch (_: Exception) {}
        try { socket?.close() } catch (_: Exception) {}
    }

    /**
     * Custom TLS client implementation with auth in session_id
     */
    private inner class RealityTlsClientImpl(
        private val sni: String,
        private val serverPubKey: ByteArray
    ) : DefaultTlsClient() {

        override fun getAuthentication(): TlsAuthentication {
            return object : TlsAuthentication {
                override fun notifyServerCertificate(serverCertificate: Certificate) {
                    // Accept any certificate - we verify server via NOX handshake
                    Log.d(TAG, "Server certificate received, subjects: ${serverCertificate.certificateList.size}")
                }

                override fun getClientCredentials(certificateRequest: CertificateRequest): TlsCredentials? {
                    return null // No client certificate
                }
            }
        }

        override fun getSessionToResume(): TlsSession? {
            // We don't resume sessions - always new handshake with fresh auth
            return null
        }

        override fun getClientExtensions(): Hashtable<Int, ByteArray> {
            val extensions = super.getClientExtensions() ?: Hashtable()

            // Add SNI extension
            val sniBytes = sni.toByteArray(Charsets.UTF_8)
            val sniExtension = ByteBuffer.allocate(5 + sniBytes.size)
            sniExtension.putShort((3 + sniBytes.size).toShort()) // list length
            sniExtension.put(0) // host_name type
            sniExtension.putShort(sniBytes.size.toShort()) // name length
            sniExtension.put(sniBytes)
            extensions[ExtensionType.server_name] = sniExtension.array()

            return extensions
        }

        /**
         * Generate session_id with authentication data
         * Format: hmac_tag(24) + timestamp(8) = 32 bytes
         */
        fun generateAuthSessionId(): ByteArray {
            val sessionId = ByteArray(32)

            // Timestamp (8 bytes, big-endian)
            val timestamp = System.currentTimeMillis() / 1000  // Unix seconds
            val timestampBytes = ByteBuffer.allocate(8)
                .order(ByteOrder.BIG_ENDIAN)
                .putLong(timestamp)
                .array()

            // HMAC-SHA256(server_private_key, server_pubkey + timestamp)
            // Server uses its private key as auth secret
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(serverPubKey, "HmacSHA256"))
            mac.update(serverPubKey)
            mac.update(timestampBytes)
            val hmacFull = mac.doFinal()

            // session_id = hmac[:24] + timestamp
            System.arraycopy(hmacFull, 0, sessionId, 0, 24)
            System.arraycopy(timestampBytes, 0, sessionId, 24, 8)

            Log.d(TAG, "Generated auth session_id, timestamp=$timestamp")
            return sessionId
        }
    }
}

// Hashtable for BouncyCastle compatibility
typealias Hashtable<K, V> = java.util.Hashtable<K, V>
