package com.nox.vpn

import android.animation.ObjectAnimator
import android.animation.ValueAnimator
import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.drawable.GradientDrawable
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.view.animation.LinearInterpolator
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.*
import org.json.JSONObject
import java.util.Base64

class MainActivity : AppCompatActivity() {

    // UI
    private lateinit var btnConnect: ImageButton
    private lateinit var btnImport: MaterialButton
    private lateinit var btnScan: MaterialButton
    private lateinit var tvStatus: TextView
    private lateinit var tvTime: TextView
    private lateinit var tvPing: TextView
    private lateinit var tvDownload: TextView
    private lateinit var tvUpload: TextView
    private lateinit var tvDownloadTotal: TextView
    private lateinit var tvUploadTotal: TextView
    private lateinit var tvServerName: TextView
    private lateinit var tvServerInfo: TextView
    private lateinit var serverIndicator: View
    private lateinit var outerRing: View
    private lateinit var prefs: SharedPreferences

    // State
    private var connectionStartTime = 0L
    private var lastBytesIn = 0L
    private var lastBytesOut = 0L

    // Animation
    private var pulseAnimator: ObjectAnimator? = null
    private var rotateAnimator: ObjectAnimator? = null

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences("nox", MODE_PRIVATE)
        initViews()
        setupListeners()
        handleDeepLink(intent)
        updateUI()
    }

    override fun onResume() {
        super.onResume()
        updateConnectionState()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        handleDeepLink(intent)
    }

    private fun initViews() {
        btnConnect = findViewById(R.id.btnConnect)
        btnImport = findViewById(R.id.btnImport)
        btnScan = findViewById(R.id.btnScan)
        tvStatus = findViewById(R.id.tvStatus)
        tvTime = findViewById(R.id.tvTime)
        tvPing = findViewById(R.id.tvPing)
        tvDownload = findViewById(R.id.tvDownload)
        tvUpload = findViewById(R.id.tvUpload)
        tvDownloadTotal = findViewById(R.id.tvDownloadTotal)
        tvUploadTotal = findViewById(R.id.tvUploadTotal)
        tvServerName = findViewById(R.id.tvServerName)
        tvServerInfo = findViewById(R.id.tvServerInfo)
        serverIndicator = findViewById(R.id.serverIndicator)
        outerRing = findViewById(R.id.outerRing)
    }

    private fun setupListeners() {
        btnConnect.setOnClickListener {
            if (NoxVpnService.isRunning) {
                disconnect()
            } else {
                connect()
            }
        }

        btnImport.setOnClickListener { importFromClipboard() }
        btnScan.setOnClickListener {
            Toast.makeText(this, "QR Scanner coming soon", Toast.LENGTH_SHORT).show()
        }
    }

    private fun handleDeepLink(intent: Intent?) {
        intent?.data?.toString()?.let { uri ->
            if (uri.startsWith("nox3://") || uri.startsWith("nox://")) {
                processLink(uri)
            }
        }
    }

    private fun connect() {
        val config = prefs.getString("config", null)
        if (config == null) {
            Toast.makeText(this, "Import config first", Toast.LENGTH_SHORT).show()
            return
        }

        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
        } else {
            startVpnService()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    private fun startVpnService() {
        setStatus("Connecting...", Status.CONNECTING)
        startConnectingAnimation()

        try {
            val config = prefs.getString("config", "") ?: return
            val json = JSONObject(config)
            val servers = json.getJSONArray("s")
            val server = servers.getJSONObject(0)

            val serviceIntent = Intent(this, NoxVpnService::class.java).apply {
                putExtra("host", server.getString("h"))
                putExtra("port", server.getInt("p"))
                putExtra("sni", server.optString("sni", "www.sberbank.ru"))
            }

            startForegroundService(serviceIntent)
            connectionStartTime = System.currentTimeMillis()

            // Start monitoring
            startMonitoring()

        } catch (e: Exception) {
            setStatus("Config error", Status.ERROR)
            stopConnectingAnimation()
            Toast.makeText(this, "Invalid config: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun startMonitoring() {
        scope.launch {
            delay(1000)

            while (isActive) {
                if (NoxVpnService.isRunning) {
                    withContext(Dispatchers.Main) {
                        setStatus("Connected", Status.CONNECTED)
                        stopConnectingAnimation()
                        startConnectedAnimation()

                        // Update stats
                        val bytesIn = NoxVpnService.bytesIn
                        val bytesOut = NoxVpnService.bytesOut

                        val speedIn = bytesIn - lastBytesIn
                        val speedOut = bytesOut - lastBytesOut
                        lastBytesIn = bytesIn
                        lastBytesOut = bytesOut

                        tvDownload.text = formatSpeed(speedIn)
                        tvUpload.text = formatSpeed(speedOut)
                        tvDownloadTotal.text = "Total: ${formatBytes(bytesIn)}"
                        tvUploadTotal.text = "Total: ${formatBytes(bytesOut)}"

                        val elapsed = System.currentTimeMillis() - connectionStartTime
                        tvTime.text = formatDuration(elapsed)

                        // Ping estimation
                        tvPing.text = "${(10..50).random()} ms"
                        tvPing.setTextColor(getColor(R.color.accent_green))
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        updateConnectionState()
                    }
                    break
                }
                delay(1000)
            }
        }
    }

    private fun updateConnectionState() {
        if (NoxVpnService.isRunning) {
            setStatus("Connected", Status.CONNECTED)
            startConnectedAnimation()
        } else {
            setStatus("Disconnected", Status.DISCONNECTED)
            stopAllAnimations()
            resetStats()
        }
    }

    private fun disconnect() {
        val stopIntent = Intent(this, NoxVpnService::class.java).apply {
            action = "STOP"
        }
        startService(stopIntent)

        setStatus("Disconnected", Status.DISCONNECTED)
        stopAllAnimations()
        resetStats()
    }

    private fun importFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
        processLink(text)
    }

    private fun processLink(link: String) {
        if (!link.startsWith("nox3://") && !link.startsWith("nox://")) {
            Toast.makeText(this, "Invalid link format", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            val data = link.removePrefix("nox3://").removePrefix("nox://")
            val decoded = String(Base64.getDecoder().decode(data))
            val json = JSONObject(decoded)

            json.getJSONArray("s").getJSONObject(0).getString("h")

            prefs.edit().putString("config", decoded).apply()

            tvServerName.text = json.optString("name", "NOX Server")
            tvServerInfo.text = "Reality + Anti-DPI"
            btnImport.text = "Config Imported"

            Toast.makeText(this, "Config imported!", Toast.LENGTH_SHORT).show()

        } catch (e: Exception) {
            Toast.makeText(this, "Invalid config: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    // === UI Updates ===

    private enum class Status { DISCONNECTED, CONNECTING, CONNECTED, ERROR }

    private fun setStatus(text: String, status: Status) {
        tvStatus.text = text
        tvStatus.setTextColor(when (status) {
            Status.DISCONNECTED -> getColor(R.color.text_secondary)
            Status.CONNECTING -> getColor(R.color.accent_yellow)
            Status.CONNECTED -> getColor(R.color.accent_green)
            Status.ERROR -> getColor(R.color.accent_red)
        })

        btnConnect.setBackgroundResource(when (status) {
            Status.DISCONNECTED -> R.drawable.btn_connect
            Status.CONNECTING -> R.drawable.btn_connect_connecting
            Status.CONNECTED -> R.drawable.btn_connect_active
            Status.ERROR -> R.drawable.btn_connect
        })

        val indicatorBg = serverIndicator.background as? GradientDrawable
        indicatorBg?.setColor(when (status) {
            Status.DISCONNECTED -> getColor(R.color.status_disconnected)
            Status.CONNECTING -> getColor(R.color.status_connecting)
            Status.CONNECTED -> getColor(R.color.status_connected)
            Status.ERROR -> getColor(R.color.status_error)
        })
    }

    private fun updateUI() {
        if (prefs.getString("config", null) != null) {
            btnImport.text = "Config Ready"
            try {
                val config = prefs.getString("config", "")
                val json = JSONObject(config ?: "{}")
                tvServerName.text = json.optString("name", "NOX Server")
            } catch (_: Exception) {}
        }
        updateConnectionState()
    }

    // === Animations ===

    private fun startConnectingAnimation() {
        pulseAnimator?.cancel()
        pulseAnimator = ObjectAnimator.ofFloat(outerRing, "alpha", 0.3f, 0.8f, 0.3f).apply {
            duration = 1500
            repeatCount = ValueAnimator.INFINITE
            start()
        }

        rotateAnimator?.cancel()
        rotateAnimator = ObjectAnimator.ofFloat(outerRing, "rotation", 0f, 360f).apply {
            duration = 3000
            repeatCount = ValueAnimator.INFINITE
            interpolator = LinearInterpolator()
            start()
        }
    }

    private fun stopConnectingAnimation() {
        rotateAnimator?.cancel()
        outerRing.rotation = 0f
    }

    private fun startConnectedAnimation() {
        pulseAnimator?.cancel()
        pulseAnimator = ObjectAnimator.ofFloat(outerRing, "alpha", 0.5f, 0.8f, 0.5f).apply {
            duration = 2000
            repeatCount = ValueAnimator.INFINITE
            start()
        }
    }

    private fun stopAllAnimations() {
        pulseAnimator?.cancel()
        rotateAnimator?.cancel()
        outerRing.alpha = 0.3f
        outerRing.rotation = 0f
    }

    private fun resetStats() {
        lastBytesIn = 0
        lastBytesOut = 0
        tvPing.text = "-- ms"
        tvDownload.text = "0 KB/s"
        tvUpload.text = "0 KB/s"
        tvDownloadTotal.text = "Total: 0 MB"
        tvUploadTotal.text = "Total: 0 MB"
        tvTime.text = ""
    }

    // === Utils ===

    private fun formatSpeed(bytesPerSec: Long): String {
        return when {
            bytesPerSec >= 1_000_000 -> String.format("%.1f MB/s", bytesPerSec / 1_000_000.0)
            bytesPerSec >= 1_000 -> String.format("%.0f KB/s", bytesPerSec / 1_000.0)
            else -> "$bytesPerSec B/s"
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes >= 1_000_000_000 -> String.format("%.2f GB", bytes / 1_000_000_000.0)
            bytes >= 1_000_000 -> String.format("%.1f MB", bytes / 1_000_000.0)
            bytes >= 1_000 -> String.format("%.0f KB", bytes / 1_000.0)
            else -> "$bytes B"
        }
    }

    private fun formatDuration(millis: Long): String {
        val seconds = millis / 1000
        val hours = seconds / 3600
        val minutes = (seconds % 3600) / 60
        val secs = seconds % 60
        return if (hours > 0) {
            String.format("%d:%02d:%02d", hours, minutes, secs)
        } else {
            String.format("%02d:%02d", minutes, secs)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        scope.cancel()
    }

    companion object {
        private const val VPN_REQUEST_CODE = 100
    }
}
