package com.nox.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager
import java.security.cert.X509Certificate

class NoxVpnService : VpnService() {

    companion object {
        const val CHANNEL_ID = "nox_vpn"
        const val NOTIFICATION_ID = 1
        const val TAG = "NoxVPN"

        // VPN Configuration
        const val VPN_ROUTE = "0.0.0.0"
        const val VPN_DNS = "94.140.14.14"  // AdGuard DNS - блокирует рекламу
        const val VPN_MTU = 1280

        // Auto-reconnect settings
        const val MAX_RECONNECT_ATTEMPTS = 10
        const val INITIAL_RECONNECT_DELAY_MS = 1000L
        const val MAX_RECONNECT_DELAY_MS = 30000L

        @Volatile
        var isRunning = false

        @Volatile
        var bytesIn = 0L

        @Volatile
        var bytesOut = 0L

        @Volatile
        var reconnectAttempts = 0

        @Volatile
        var isFallbackMode = false
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var activeSocket: java.net.Socket? = null  // Can be SSLSocket or raw Socket
    private var noxProtocol: NoxProtocol? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var fallbackMode = false

    private var serverHost = ""
    private var serverPort = 443
    private var serverSni = "ya.ru"
    private var serverPublicKey = ""

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        Log.d(TAG, "Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "STOP") {
            stopVpn()
            return START_NOT_STICKY
        }

        // Get config from intent
        serverHost = intent?.getStringExtra("host") ?: "194.5.79.246"
        serverPort = intent?.getIntExtra("port", 443) ?: 443
        serverSni = intent?.getStringExtra("sni") ?: "www.sberbank.ru"
        serverPublicKey = intent?.getStringExtra("publicKey")
            ?: "108c5e2765fd1ee8152fe10d093dd2129cfd7ee55da916605fd2125108d9b565"

        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
        startVpn()

        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return
        isRunning = true
        reconnectAttempts = 0

        scope.launch {
            connectWithRetry()
        }
    }

    private suspend fun connectWithRetry() {
        while (isRunning && reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
            try {
                // 1. Connect to server
                connectToServer()

                // Reset retry counter on successful connection
                reconnectAttempts = 0

                // 2. Start packet forwarding (blocks until disconnected)
                startForwarding()

                // If we're in fallback mode, don't reconnect - just exit
                if (fallbackMode) {
                    Log.d(TAG, "Fallback mode ended, stopping...")
                    break
                }

                // If we get here, connection was lost
                if (!isRunning) break

                Log.d(TAG, "Connection lost, will reconnect...")
                withContext(Dispatchers.Main) {
                    updateNotification("Reconnecting...")
                }

            } catch (e: Exception) {
                Log.e(TAG, "VPN error: ${e.message}", e)

                // If we're already in fallback mode, don't retry
                if (fallbackMode) {
                    Log.d(TAG, "In fallback mode, not retrying")
                    break
                }

                reconnectAttempts++

                if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                    withContext(Dispatchers.Main) {
                        updateNotification("Connection failed")
                    }
                    stopVpn()
                    return
                }

                // Exponential backoff
                val delay = minOf(
                    INITIAL_RECONNECT_DELAY_MS * (1 shl reconnectAttempts),
                    MAX_RECONNECT_DELAY_MS
                )

                withContext(Dispatchers.Main) {
                    updateNotification("Reconnecting in ${delay/1000}s (#$reconnectAttempts)")
                }

                // Close old socket
                try { activeSocket?.close() } catch (_: Exception) {}
                activeSocket = null
                noxProtocol = null

                delay(delay)
            }
        }
    }

    private suspend fun connectToServer() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Connecting to $serverHost:$serverPort (SNI: $serverSni)")

        val pubKey = hexToBytes(serverPublicKey)
        var socket: java.net.Socket? = null

        // Try Reality XTLS first (REAL certificate, score=0)
        try {
            Log.d(TAG, "Trying Reality XTLS mode...")
            val xtlsClient = RealityXtlsClient(pubKey, serverHost, serverPort, serverSni)
            socket = xtlsClient.connect()
            Log.d(TAG, "Reality XTLS connected!")
        } catch (e: Exception) {
            Log.w(TAG, "Reality XTLS failed: ${e.message}, falling back to standard TLS")

            // Fallback to standard TLS
            val trustAllCerts = arrayOf<TrustManager>(object : X509TrustManager {
                override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
                override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            })
            val sslContext = SSLContext.getInstance("TLSv1.3")
            sslContext.init(null, trustAllCerts, java.security.SecureRandom())
            val factory = sslContext.socketFactory as SSLSocketFactory

            val fallbackSsl = factory.createSocket() as SSLSocket
            fallbackSsl.connect(InetSocketAddress(serverHost, serverPort), 10000)
            fallbackSsl.sslParameters = fallbackSsl.sslParameters.apply {
                serverNames = listOf(javax.net.ssl.SNIHostName(serverSni))
            }
            fallbackSsl.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
            fallbackSsl.soTimeout = 30000
            fallbackSsl.startHandshake()

            // Send Reality v2 auth after TLS
            val auth = generateRealityAuth(pubKey)
            fallbackSsl.outputStream.write(auth)
            fallbackSsl.outputStream.flush()
            Log.d(TAG, "Reality v2 auth sent: ${auth.size} bytes")

            socket = fallbackSsl
        }

        activeSocket = socket
        Log.d(TAG, "TLS handshake complete")

        // Try NOX protocol handshake
        try {
            val protocol = NoxProtocol(pubKey, socket ?: throw Exception("Socket is null"))
            val assignedIp = protocol.handshake()

            Log.d(TAG, "NOX handshake complete, assigned IP: $assignedIp")
            noxProtocol = protocol
            fallbackMode = false
            isFallbackMode = false

            // Establish VPN interface with assigned IP
            establishVpnInterface(assignedIp)

            withContext(Dispatchers.Main) {
                updateNotification("Connected: $assignedIp")
            }
        } catch (e: Exception) {
            Log.e(TAG, "NOX handshake failed: ${e.message}, switching to FALLBACK mode")

            // Close failed socket - we don't need it in fallback
            try { socket?.close() } catch (_: Exception) {}
            socket = null

            activeSocket = null
            noxProtocol = null
            fallbackMode = true
            isFallbackMode = true

            // Use fixed IP for fallback - VPN will work but no internet
            val fallbackIp = "10.0.0.99"
            establishVpnInterface(fallbackIp)

            withContext(Dispatchers.Main) {
                updateNotification("⚠️ FALLBACK MODE - NO INTERNET! Fix NOX!")
            }

            Log.w(TAG, "FALLBACK MODE: VPN active but NO INTERNET - NOX handshake broken!")
        }
    }

    private fun establishVpnInterface(assignedIp: String) {
        // Close existing interface if any
        vpnInterface?.close()

        Log.d(TAG, "Creating VPN interface with IP: $assignedIp")

        val builder = Builder()
            .setSession("NOX VPN")
            .setMtu(VPN_MTU)
            .addAddress(assignedIp, 24)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(VPN_DNS)
            .addDnsServer("94.140.15.15")  // AdGuard DNS backup
            .setBlocking(true)

        // Route all traffic through VPN (split tunnel)
        builder.addRoute("0.0.0.0", 1)
        builder.addRoute("128.0.0.0", 1)

        // Exclude VPN app itself to prevent loop
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Could not exclude self: ${e.message}")
        }

        // Create VPN interface
        val iface = builder.establish()

        if (iface == null) {
            Log.e(TAG, "CRITICAL: VPN interface is NULL! User may need to grant permission.")
            throw Exception("VPN interface creation failed - check permissions!")
        }

        vpnInterface = iface
        Log.d(TAG, "SUCCESS: VPN interface established! IP=$assignedIp, fd=${iface.fd}")
        Log.d(TAG, "VPN key icon should now be visible on device!")
    }

    private suspend fun startForwarding() = withContext(Dispatchers.IO) {
        val vpnFd = vpnInterface?.fileDescriptor
        if (vpnFd == null) {
            Log.e(TAG, "VPN interface not established!")
            return@withContext
        }

        Log.d(TAG, "VPN interface ready, starting forwarding (fallback=$fallbackMode)")

        val vpnInput = FileInputStream(vpnFd)
        val vpnOutput = FileOutputStream(vpnFd)

        if (fallbackMode) {
            // FALLBACK MODE: raw relay without NOX encryption
            startFallbackForwarding(vpnInput, vpnOutput)
        } else {
            // NORMAL MODE: NOX protocol
            val protocol = noxProtocol
            if (protocol == null) {
                Log.e(TAG, "NOX protocol not initialized!")
                return@withContext
            }
            startNoxForwarding(vpnInput, vpnOutput, protocol)
        }
    }

    private suspend fun startNoxForwarding(
        vpnInput: FileInputStream,
        vpnOutput: FileOutputStream,
        protocol: NoxProtocol
    ) = withContext(Dispatchers.IO) {
        val buffer = ByteArray(VPN_MTU)

        val outJob = scope.launch {
            try {
                while (isActive && isRunning) {
                    val length = vpnInput.read(buffer)
                    if (length > 0) {
                        val packet = buffer.copyOf(length)
                        protocol.sendPacket(packet)
                        bytesOut += length
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NOX outbound error: ${e.message}")
            }
        }

        val inJob = scope.launch {
            try {
                while (isActive && isRunning) {
                    val packet = protocol.receivePacket()
                    if (packet != null && packet.isNotEmpty()) {
                        vpnOutput.write(packet)
                        bytesIn += packet.size
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "NOX inbound error: ${e.message}")
            }
        }

        outJob.join()
        inJob.join()
    }

    private suspend fun startFallbackForwarding(
        vpnInput: FileInputStream,
        vpnOutput: FileOutputStream
    ) = withContext(Dispatchers.IO) {
        // FALLBACK MODE: VPN created but no data forwarding
        // Just hold the VPN interface open and wait
        // This shows the key icon and proves VPN works, but no internet
        Log.w(TAG, "FALLBACK MODE ACTIVE - VPN created, no data forwarding!")
        Log.w(TAG, "NOX protocol not working - fix the server!")

        // Just read and discard packets from TUN to prevent buffer overflow
        val buffer = ByteArray(VPN_MTU)
        try {
            while (isActive && isRunning) {
                val length = vpnInput.read(buffer)
                if (length > 0) {
                    bytesOut += length
                    // Packets are discarded - no internet in fallback mode
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Fallback read error: ${e.message}")
        }
    }

    private fun stopVpn() {
        isRunning = false
        scope.cancel()

        try {
            activeSocket?.close()
        } catch (e: Exception) {}

        try {
            vpnInterface?.close()
        } catch (e: Exception) {}

        activeSocket = null
        noxProtocol = null
        vpnInterface = null
        bytesIn = 0
        bytesOut = 0

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        Log.d(TAG, "VPN stopped")
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "NOX VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection status"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(status: String): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, NoxVpnService::class.java).apply {
            action = "STOP"
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("NOX VPN")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_launcher)
            .setContentIntent(pendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Disconnect", stopPendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateNotification(status: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, createNotification(status))
    }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }

    /**
     * Generate Reality v2 authentication data
     * Format: hmac_tag(24) + timestamp(8) = 32 bytes
     * Server verifies: HMAC-SHA256(server_pubkey, server_pubkey + timestamp)
     */
    private fun generateRealityAuth(serverPubKey: ByteArray): ByteArray {
        val auth = ByteArray(32)

        // Timestamp (8 bytes, big-endian, Unix seconds)
        val timestamp = System.currentTimeMillis() / 1000
        val timestampBytes = java.nio.ByteBuffer.allocate(8)
            .order(java.nio.ByteOrder.BIG_ENDIAN)
            .putLong(timestamp)
            .array()

        // HMAC-SHA256(server_pubkey, server_pubkey + timestamp)
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(serverPubKey, "HmacSHA256"))
        mac.update(serverPubKey)
        mac.update(timestampBytes)
        val hmacFull = mac.doFinal()

        // auth = hmac[:24] + timestamp
        System.arraycopy(hmacFull, 0, auth, 0, 24)
        System.arraycopy(timestampBytes, 0, auth, 24, 8)

        Log.d(TAG, "Generated Reality auth, timestamp=$timestamp")
        return auth
    }
}
