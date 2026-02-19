package com.nox.vpn

import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import kotlinx.coroutines.*
import org.json.JSONObject
import java.net.Socket
import java.util.Base64
import javax.net.ssl.SSLSocketFactory

class MainActivity : AppCompatActivity() {

    private lateinit var btnConnect: Button
    private lateinit var btnImport: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvPing: TextView
    private lateinit var tvDown: TextView
    private lateinit var tvUp: TextView
    private lateinit var prefs: SharedPreferences

    private var isConnected = false
    private var isConnecting = false
    private var socket: Socket? = null
    private var job: Job? = null
    private var bytesDown = 0L
    private var bytesUp = 0L

    private val scope = CoroutineScope(Dispatchers.Main + SupervisorJob())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        prefs = getSharedPreferences("nox", MODE_PRIVATE)

        btnConnect = findViewById(R.id.btnConnect)
        btnImport = findViewById(R.id.btnImport)
        tvStatus = findViewById(R.id.tvStatus)
        tvPing = findViewById(R.id.tvPing)
        tvDown = findViewById(R.id.tvDown)
        tvUp = findViewById(R.id.tvUp)

        btnConnect.setOnClickListener { toggleConnection() }
        btnImport.setOnClickListener { importFromClipboard() }

        // Handle deep link
        intent?.data?.toString()?.let { processLink(it) }

        // Network change listener for auto-reconnect
        registerNetworkCallback()

        updateUI()
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        cm.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                if (isConnected || isConnecting) {
                    // Network changed - reconnect
                    scope.launch {
                        delay(500)
                        if (!isConnected) reconnect()
                    }
                }
            }

            override fun onLost(network: Network) {
                if (isConnected) {
                    runOnUiThread {
                        setStatus("Сеть потеряна...", Color.YELLOW)
                    }
                }
            }
        })
    }

    private fun toggleConnection() {
        if (isConnected) {
            disconnect()
        } else {
            connect()
        }
    }

    private fun connect() {
        val config = prefs.getString("config", null)
        if (config == null) {
            Toast.makeText(this, "Сначала импортируйте ссылку", Toast.LENGTH_SHORT).show()
            return
        }

        // Request VPN permission
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, 100)
        } else {
            startVpn()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 100 && resultCode == Activity.RESULT_OK) {
            startVpn()
        }
    }

    private fun startVpn() {
        isConnecting = true
        setStatus("Подключение...", Color.YELLOW)
        setButtonColor(Color.YELLOW)

        job = scope.launch(Dispatchers.IO) {
            try {
                val config = prefs.getString("config", "") ?: return@launch
                val json = JSONObject(config)
                val servers = json.getJSONArray("s")
                val server = servers.getJSONObject(0)
                val host = server.getString("h")
                val port = server.getInt("p")
                val sni = server.optString("sni", host)

                // Connect with TLS
                val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                socket = factory.createSocket(host, port).apply {
                    soTimeout = 5000
                }

                withContext(Dispatchers.Main) {
                    isConnected = true
                    isConnecting = false
                    setStatus("Подключено", Color.GREEN)
                    setButtonColor(Color.GREEN)
                    btnConnect.text = "STOP"
                }

                // Ping loop
                var pingFails = 0
                while (isActive && isConnected) {
                    delay(500)
                    val start = System.currentTimeMillis()
                    try {
                        socket?.getOutputStream()?.write(0)
                        socket?.getOutputStream()?.flush()
                        val ping = System.currentTimeMillis() - start
                        pingFails = 0
                        withContext(Dispatchers.Main) {
                            tvPing.text = "Ping: ${ping}ms"
                            tvPing.setTextColor(Color.GREEN)
                        }
                    } catch (e: Exception) {
                        pingFails++
                        withContext(Dispatchers.Main) {
                            tvPing.text = "Timeout ($pingFails)"
                            tvPing.setTextColor(Color.YELLOW)
                            if (pingFails >= 3) {
                                setStatus("Переподключение...", Color.YELLOW)
                            }
                        }
                        if (pingFails >= 3) {
                            socket?.close()
                            socket = null
                            delay(1000)
                            reconnectInternal()
                        }
                    }
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    isConnecting = false
                    setStatus("Ошибка: ${e.message}", Color.RED)
                    setButtonColor(Color.RED)
                }
                delay(2000)
                if (isConnected) reconnectInternal()
            }
        }
    }

    private suspend fun reconnectInternal() {
        try {
            val config = prefs.getString("config", "") ?: return
            val json = JSONObject(config)
            val servers = json.getJSONArray("s")
            val server = servers.getJSONObject(0)
            val host = server.getString("h")
            val port = server.getInt("p")

            val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
            socket = factory.createSocket(host, port).apply {
                soTimeout = 5000
            }

            withContext(Dispatchers.Main) {
                setStatus("Подключено", Color.GREEN)
                setButtonColor(Color.GREEN)
            }
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                setStatus("Переподключение...", Color.YELLOW)
            }
        }
    }

    private fun reconnect() {
        if (!isConnected) return
        scope.launch(Dispatchers.IO) {
            reconnectInternal()
        }
    }

    private fun disconnect() {
        isConnected = false
        isConnecting = false
        job?.cancel()
        socket?.close()
        socket = null

        setStatus("Отключено", Color.GRAY)
        setButtonColor(Color.parseColor("#333355"))
        btnConnect.text = "TAP"
        tvPing.text = ""
        bytesDown = 0
        bytesUp = 0
        tvDown.text = "↓ 0 KB"
        tvUp.text = "↑ 0 KB"
    }

    private fun importFromClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val text = clipboard.primaryClip?.getItemAt(0)?.text?.toString() ?: ""
        processLink(text)
    }

    private fun processLink(link: String) {
        if (!link.startsWith("nox3://") && !link.startsWith("nox://")) {
            Toast.makeText(this, "Неверный формат ссылки", Toast.LENGTH_SHORT).show()
            return
        }

        try {
            val data = link.removePrefix("nox3://").removePrefix("nox://")
            val decoded = String(Base64.getDecoder().decode(data))
            val json = JSONObject(decoded)

            // Validate
            json.getJSONArray("s").getJSONObject(0).getString("h")

            prefs.edit().putString("config", decoded).apply()
            Toast.makeText(this, "Конфигурация сохранена", Toast.LENGTH_SHORT).show()

        } catch (e: Exception) {
            Toast.makeText(this, "Ошибка: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    private fun setStatus(text: String, color: Int) {
        tvStatus.text = text
        tvStatus.setTextColor(color)
    }

    private fun setButtonColor(color: Int) {
        val drawable = btnConnect.background as? GradientDrawable
            ?: (btnConnect.background?.mutate() as? GradientDrawable)
        drawable?.setStroke(4.dpToPx(), color)
    }

    private fun Int.dpToPx(): Int = (this * resources.displayMetrics.density).toInt()

    private fun updateUI() {
        if (prefs.getString("config", null) != null) {
            btnImport.text = "Ссылка загружена ✓"
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        job?.cancel()
        socket?.close()
    }
}
