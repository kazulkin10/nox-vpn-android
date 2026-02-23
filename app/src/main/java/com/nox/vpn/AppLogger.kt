package com.nox.vpn

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue

/**
 * Application-wide logger that stores logs in memory
 * and can send them to the server for debugging
 */
object AppLogger {
    private const val MAX_LOGS = 500
    private const val SERVER_URL = "http://194.5.79.246:9000/logs"  // Relay server

    private val logs = ConcurrentLinkedQueue<LogEntry>()
    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    data class LogEntry(
        val timestamp: Long,
        val level: String,
        val tag: String,
        val message: String
    ) {
        fun format(): String {
            val time = dateFormat.format(Date(timestamp))
            return "[$time] $level/$tag: $message"
        }
    }

    fun d(tag: String, message: String) {
        add("D", tag, message)
        Log.d(tag, message)
    }

    fun i(tag: String, message: String) {
        add("I", tag, message)
        Log.i(tag, message)
    }

    fun w(tag: String, message: String) {
        add("W", tag, message)
        Log.w(tag, message)
    }

    fun e(tag: String, message: String, throwable: Throwable? = null) {
        val fullMsg = if (throwable != null) "$message: ${throwable.message}" else message
        add("E", tag, fullMsg)
        if (throwable != null) {
            Log.e(tag, message, throwable)
        } else {
            Log.e(tag, message)
        }
    }

    private fun add(level: String, tag: String, message: String) {
        val entry = LogEntry(System.currentTimeMillis(), level, tag, message)
        logs.add(entry)

        // Keep only last MAX_LOGS entries
        while (logs.size > MAX_LOGS) {
            logs.poll()
        }
    }

    fun getAll(): List<LogEntry> = logs.toList()

    fun getAllFormatted(): String {
        return logs.toList().joinToString("\n") { it.format() }
    }

    fun clear() {
        logs.clear()
    }

    /**
     * Send logs to server via HTTP (bypasses VPN)
     * Returns true if successful
     */
    suspend fun sendToServer(): Boolean = withContext(Dispatchers.IO) {
        try {
            val logsText = getAllFormatted()
            if (logsText.isEmpty()) {
                return@withContext true
            }

            val deviceInfo = """
                |=== Device Info ===
                |Time: ${Date()}
                |Android: ${android.os.Build.VERSION.SDK_INT}
                |Device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}
                |App: 4.8-logs
                |=== Logs ===
                |$logsText
            """.trimMargin()

            val url = URL(SERVER_URL)
            val conn = url.openConnection() as HttpURLConnection
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.setRequestProperty("Content-Type", "text/plain; charset=utf-8")
            conn.connectTimeout = 10000
            conn.readTimeout = 10000

            OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { writer ->
                writer.write(deviceInfo)
            }

            val responseCode = conn.responseCode
            conn.disconnect()

            d("AppLogger", "Logs sent to server, response: $responseCode")
            responseCode == 200
        } catch (e: Exception) {
            e("AppLogger", "Failed to send logs", e)
            false
        }
    }
}
