package com.proxyconnect.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {

    private lateinit var spType: Spinner
    private lateinit var etHost: EditText
    private lateinit var etPort: EditText
    private lateinit var swAuth: Switch
    private lateinit var etUser: EditText
    private lateinit var etPass: EditText
    private lateinit var authBox: LinearLayout
    private lateinit var btnToggle: Button
    private lateinit var tvStatus: TextView
    private lateinit var tvLog: TextView

    private val logListener: (String) -> Unit = { msg ->
        runOnUiThread { appendLog(msg) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val pad = (16 * resources.displayMetrics.density).toInt()
        val root = ScrollView(this)
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        root.addView(col)

        fun label(t: String) = TextView(this).apply { text = t; col.addView(this) }
        fun field(hint: String, inputType: Int = android.text.InputType.TYPE_CLASS_TEXT): EditText =
            EditText(this).apply { this.hint = hint; this.inputType = inputType; col.addView(this) }

        label("Proxy type")
        spType = Spinner(this)
        spType.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, listOf("SOCKS5", "HTTP"))
        col.addView(spType)

        label("Host")
        etHost = field("e.g. 123.45.67.89")
        label("Port")
        etPort = field("e.g. 1080", android.text.InputType.TYPE_CLASS_NUMBER)

        swAuth = Switch(this).apply { text = "Use authentication"; col.addView(this) }
        authBox = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; col.addView(this) }
        etUser = EditText(this).apply { hint = "Username"; authBox.addView(this) }
        etPass = EditText(this).apply {
            hint = "Password"
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            authBox.addView(this)
        }
        authBox.visibility = View.GONE
        swAuth.setOnCheckedChangeListener { _, on -> authBox.visibility = if (on) View.VISIBLE else View.GONE }

        btnToggle = Button(this).apply { col.addView(this) }
        btnToggle.setOnClickListener { onToggle() }

        tvStatus = TextView(this).apply { textSize = 16f; col.addView(this) }
        tvLog = TextView(this).apply {
            typeface = android.graphics.Typeface.MONOSPACE
            textSize = 12f
            col.addView(this)
        }

        setContentView(root)

        // restore saved config
        val p = getSharedPreferences("proxy", MODE_PRIVATE)
        etHost.setText(p.getString("host", ""))
        val savedPort = p.getInt("port", 1080)
        etPort.setText(if (savedPort > 0) savedPort.toString() else "")
        spType.setSelection(if (p.getString("type", "SOCKS5") == "HTTP") 1 else 0)
        swAuth.isChecked = p.getBoolean("useAuth", false)
        etUser.setText(p.getString("user", ""))
        etPass.setText(p.getString("pass", ""))
        if (ProxyVpnService.lastLog.isNotEmpty()) tvLog.text = ProxyVpnService.lastLog + "\n"

        refreshUi()
        ProxyVpnService.addLogListener(logListener)
    }

    override fun onDestroy() {
        ProxyVpnService.removeLogListener(logListener)
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        refreshUi()
    }

    private fun onToggle() {
        if (ProxyVpnService.isRunning) {
            startService(Intent(this, ProxyVpnService::class.java).setAction(ProxyVpnService.ACTION_DISCONNECT))
            refreshUi()
            return
        }
        val host = etHost.text.toString().trim()
        val port = etPort.text.toString().trim().toIntOrNull()
        if (host.isEmpty() || port == null || port !in 1..65535) {
            Toast.makeText(this, "Enter valid host and port (1-65535)", Toast.LENGTH_SHORT).show()
            return
        }
        val useAuth = swAuth.isChecked
        val user = etUser.text.toString()
        val pass = etPass.text.toString()
        if (useAuth && user.isEmpty()) {
            Toast.makeText(this, "Enter username (or turn off auth)", Toast.LENGTH_SHORT).show()
            return
        }
        getSharedPreferences("proxy", MODE_PRIVATE).edit()
            .putString("host", host).putInt("port", port)
            .putString("type", if (spType.selectedItemPosition == 1) "HTTP" else "SOCKS5")
            .putBoolean("useAuth", useAuth).putString("user", user).putString("pass", pass)
            .apply()

        val prep = VpnService.prepare(this)
        if (prep != null) {
            pendingConnect = true
            startActivityForResult(prep, 100)
        } else {
            doConnect(host, port, useAuth, user, pass)
        }
    }

    private var pendingConnect = false

    @Deprecated("activity result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 100) {
            if (resultCode == RESULT_OK && pendingConnect) {
                pendingConnect = false
                onToggleConnectAfterPermission()
            } else {
                pendingConnect = false
                Toast.makeText(this, "VPN permission required", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun onToggleConnectAfterPermission() {
        if (ProxyVpnService.isRunning) return
        // re-read fields (validated already once); validate again lightly
        val host = etHost.text.toString().trim()
        val port = etPort.text.toString().trim().toIntOrNull() ?: return
        doConnect(host, port, swAuth.isChecked, etUser.text.toString(), etPass.text.toString())
    }

    private fun doConnect(host: String, port: Int, useAuth: Boolean, user: String, pass: String) {
        val i = Intent(this, ProxyVpnService::class.java).apply {
            action = ProxyVpnService.ACTION_CONNECT
            putExtra(ProxyVpnService.EXTRA_TYPE, if (spType.selectedItemPosition == 1) "HTTP" else "SOCKS5")
            putExtra(ProxyVpnService.EXTRA_HOST, host)
            putExtra(ProxyVpnService.EXTRA_PORT, port)
            putExtra(ProxyVpnService.EXTRA_USER, user)
            putExtra(ProxyVpnService.EXTRA_PASS, pass)
            putExtra(ProxyVpnService.EXTRA_USE_AUTH, useAuth)
        }
        startService(i)
        appendLog("Connecting…")
        refreshUi()
    }

    private fun refreshUi() {
        val running = ProxyVpnService.isRunning
        btnToggle.text = if (running) "Disconnect" else "Connect"
        tvStatus.text = if (running) "Status: CONNECTED" else "Status: disconnected"
    }

    private fun appendLog(msg: String) {
        val t = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        tvLog.append("[$t] $msg\n")
        refreshUi()
    }
}
