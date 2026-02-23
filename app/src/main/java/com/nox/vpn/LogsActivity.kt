package com.nox.vpn

import android.os.Bundle
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.button.MaterialButton
import kotlinx.coroutines.*

class LogsActivity : AppCompatActivity() {

    private lateinit var tvLogs: TextView
    private lateinit var scrollView: ScrollView
    private lateinit var btnSend: MaterialButton
    private lateinit var btnRefresh: MaterialButton
    private lateinit var btnClear: MaterialButton

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var autoRefreshJob: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_logs)

        tvLogs = findViewById(R.id.tvLogs)
        scrollView = findViewById(R.id.scrollView)
        btnSend = findViewById(R.id.btnSend)
        btnRefresh = findViewById(R.id.btnRefresh)
        btnClear = findViewById(R.id.btnClear)

        btnSend.setOnClickListener { sendLogs() }
        btnRefresh.setOnClickListener { refreshLogs() }
        btnClear.setOnClickListener { clearLogs() }

        refreshLogs()
        startAutoRefresh()
    }

    private fun refreshLogs() {
        val logs = AppLogger.getAllFormatted()
        tvLogs.text = if (logs.isEmpty()) "No logs yet" else logs

        // Scroll to bottom
        scrollView.post {
            scrollView.fullScroll(ScrollView.FOCUS_DOWN)
        }
    }

    private fun sendLogs() {
        btnSend.isEnabled = false
        btnSend.text = "Sending..."

        scope.launch {
            val success = AppLogger.sendToServer()
            btnSend.isEnabled = true
            btnSend.text = "📤 Send to Server"

            if (success) {
                Toast.makeText(this@LogsActivity, "✅ Logs sent!", Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this@LogsActivity, "❌ Failed to send logs", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun clearLogs() {
        AppLogger.clear()
        refreshLogs()
        Toast.makeText(this, "Logs cleared", Toast.LENGTH_SHORT).show()
    }

    private fun startAutoRefresh() {
        autoRefreshJob = scope.launch {
            while (isActive) {
                delay(2000)
                refreshLogs()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        autoRefreshJob?.cancel()
        scope.cancel()
    }
}
