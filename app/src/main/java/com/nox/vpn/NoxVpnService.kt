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
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

class NoxVpnService : VpnService() {

    companion object {
        const val CHANNEL_ID = "nox_vpn"
        const val NOTIFICATION_ID = 1
        const val TAG = "NoxVPN"

        // VPN Configuration
        const val VPN_ADDRESS = "10.0.0.2"
        const val VPN_ROUTE = "0.0.0.0"
        const val VPN_DNS = "8.8.8.8"
        const val VPN_MTU = 1280

        @Volatile
        var isRunning = false

        @Volatile
        var bytesIn = 0L

        @Volatile
        var bytesOut = 0L
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var sslSocket: SSLSocket? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private var serverHost = ""
    private var serverPort = 8443
    private var serverSni = "www.sberbank.ru"

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
        serverPort = intent?.getIntExtra("port", 8443) ?: 8443
        serverSni = intent?.getStringExtra("sni") ?: "www.sberbank.ru"

        startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
        startVpn()

        return START_STICKY
    }

    private fun startVpn() {
        if (isRunning) return
        isRunning = true

        scope.launch {
            try {
                // 1. Establish TUN interface
                establishVpnInterface()

                // 2. Connect to server
                connectToServer()

                // 3. Start packet forwarding
                startForwarding()

            } catch (e: Exception) {
                Log.e(TAG, "VPN error: ${e.message}", e)
                withContext(Dispatchers.Main) {
                    updateNotification("Connection failed")
                }
                stopVpn()
            }
        }
    }

    private fun establishVpnInterface() {
        val builder = Builder()
            .setSession("NOX VPN")
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 24)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer(VPN_DNS)
            .addDnsServer("1.1.1.1")
            .setBlocking(true)

        // Exclude local networks
        builder.addRoute("0.0.0.0", 1)
        builder.addRoute("128.0.0.0", 1)

        // Allow bypass for the VPN server itself
        try {
            builder.addDisallowedApplication(packageName)
        } catch (e: Exception) {
            Log.w(TAG, "Could not exclude self")
        }

        vpnInterface = builder.establish()
        Log.d(TAG, "VPN interface established")
    }

    private suspend fun connectToServer() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Connecting to $serverHost:$serverPort (SNI: $serverSni)")

        // Create SSL socket with custom SNI
        val sslContext = SSLContext.getInstance("TLSv1.3")
        sslContext.init(null, null, null)
        val factory = sslContext.socketFactory as SSLSocketFactory

        val socket = factory.createSocket() as SSLSocket
        socket.connect(InetSocketAddress(serverHost, serverPort), 10000)

        // Set SNI
        val sslParams = socket.sslParameters
        sslParams.serverNames = listOf(javax.net.ssl.SNIHostName(serverSni))
        socket.sslParameters = sslParams

        // Configure protocols
        socket.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
        socket.soTimeout = 30000

        // Start handshake
        socket.startHandshake()

        sslSocket = socket
        Log.d(TAG, "Connected to server")

        withContext(Dispatchers.Main) {
            updateNotification("Connected")
        }
    }

    private suspend fun startForwarding() = withContext(Dispatchers.IO) {
        val vpnFd = vpnInterface?.fileDescriptor ?: return@withContext
        val vpnInput = FileInputStream(vpnFd)
        val vpnOutput = FileOutputStream(vpnFd)
        val socket = sslSocket ?: return@withContext
        val serverInput = socket.inputStream
        val serverOutput = socket.outputStream

        // Buffer for packets
        val buffer = ByteBuffer.allocate(VPN_MTU + 4)
        val readBuffer = ByteArray(VPN_MTU + 4)

        // Launch coroutines for bidirectional forwarding
        val outJob = scope.launch {
            // TUN -> Server
            try {
                while (isActive && isRunning) {
                    val length = vpnInput.read(readBuffer, 4, VPN_MTU)
                    if (length > 0) {
                        // Prepend length header
                        readBuffer[0] = (length shr 24).toByte()
                        readBuffer[1] = (length shr 16).toByte()
                        readBuffer[2] = (length shr 8).toByte()
                        readBuffer[3] = length.toByte()

                        serverOutput.write(readBuffer, 0, length + 4)
                        serverOutput.flush()
                        bytesOut += length
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Outbound error: ${e.message}")
            }
        }

        val inJob = scope.launch {
            // Server -> TUN
            try {
                val header = ByteArray(4)
                while (isActive && isRunning) {
                    // Read length header
                    var read = 0
                    while (read < 4) {
                        val n = serverInput.read(header, read, 4 - read)
                        if (n < 0) throw Exception("Connection closed")
                        read += n
                    }

                    val length = ((header[0].toInt() and 0xFF) shl 24) or
                                 ((header[1].toInt() and 0xFF) shl 16) or
                                 ((header[2].toInt() and 0xFF) shl 8) or
                                 (header[3].toInt() and 0xFF)

                    if (length > 0 && length <= VPN_MTU) {
                        // Read packet
                        read = 0
                        while (read < length) {
                            val n = serverInput.read(readBuffer, read, length - read)
                            if (n < 0) throw Exception("Connection closed")
                            read += n
                        }

                        vpnOutput.write(readBuffer, 0, length)
                        bytesIn += length
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Inbound error: ${e.message}")
            }
        }

        // Wait for both jobs
        outJob.join()
        inJob.join()
    }

    private fun stopVpn() {
        isRunning = false
        scope.cancel()

        try {
            sslSocket?.close()
        } catch (e: Exception) {}

        try {
            vpnInterface?.close()
        } catch (e: Exception) {}

        sslSocket = null
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
}
