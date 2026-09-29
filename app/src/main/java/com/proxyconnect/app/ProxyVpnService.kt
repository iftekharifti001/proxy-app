package com.proxyconnect.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean

class ProxyVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.proxyconnect.app.CONNECT"
        const val ACTION_DISCONNECT = "com.proxyconnect.app.DISCONNECT"
        const val EXTRA_TYPE = "type"
        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_USER = "user"
        const val EXTRA_PASS = "pass"
        const val EXTRA_USE_AUTH = "useAuth"

        @Volatile var isRunning = false
        @Volatile var lastLog: String = ""
        private val listeners = mutableSetOf<(String) -> Unit>()

        fun addLogListener(l: (String) -> Unit) { synchronized(listeners) { listeners.add(l) } }
        fun removeLogListener(l: (String) -> Unit) { synchronized(listeners) { listeners.remove(l) } }
        internal fun emit(s: String) {
            lastLog = s
            Log.i("ProxyConnect", s)
            synchronized(listeners) { listeners.toList() }.forEach { try { it(s) } catch (_: Exception) {} }
        }
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var forwarder: TunForwarder? = null
    private var worker: Thread? = null
    private val stopped = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopVpn()
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val cfg = ProxyConfig(
                    type = if (intent.getStringExtra(EXTRA_TYPE) == "HTTP") ProxyType.HTTP else ProxyType.SOCKS5,
                    host = intent.getStringExtra(EXTRA_HOST).orEmpty().trim(),
                    port = intent.getIntExtra(EXTRA_PORT, 1080),
                    username = intent.getStringExtra(EXTRA_USER).orEmpty(),
                    password = intent.getStringExtra(EXTRA_PASS).orEmpty(),
                    useAuth = intent.getBooleanExtra(EXTRA_USE_AUTH, false)
                )
                startVpn(cfg)
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn(cfg: ProxyConfig) {
        if (isRunning) stopVpn()
        stopped.set(false)
        if (cfg.host.isEmpty() || cfg.port !in 1..65535) {
            emit("Invalid host/port")
            stopSelf()
            return
        }
        try {
            startForegroundWithNotification(cfg)
            val builder = Builder()
                .setSession("ProxyConnect")
                .setMtu(1500)
                .addAddress("10.8.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setBlocking(false)
            // Keep our own proxy connection outside the tunnel, else routing loops
            try { builder.addRoute(cfg.host, 32) } catch (_: Exception) {}
            tunFd = builder.establish()
            if (tunFd == null) {
                emit("VPN permission denied")
                stopSelf()
                return
            }
            val fd = tunFd!!
            val fwd = TunForwarder(
                FileInputStream(fd.fileDescriptor),
                FileOutputStream(fd.fileDescriptor),
                cfg,
                protect = { s: Socket ->
                    try { protect(s) } catch (_: Exception) { false }
                },
                log = { emit(it) }
            )
            forwarder = fwd
            isRunning = true
            emit("Connected: ${cfg.type} ${cfg.host}:${cfg.port}")
            worker = Thread({ fwd.runLoop() }, "tun-reader").also { it.start() }
            updateNotification("Active: ${cfg.type} ${cfg.host}:${cfg.port}")
        } catch (e: Exception) {
            emit("Start failed: ${e.message}")
            stopVpn()
            stopSelf()
        }
    }

    private fun stopVpn() {
        stopped.set(true)
        try { forwarder?.stop() } catch (_: Exception) {}
        try { worker?.interrupt() } catch (_: Exception) {}
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
        forwarder = null
        worker = null
        if (isRunning) emit("Disconnected")
        isRunning = false
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) {}
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    override fun onRevoke() {
        emit("VPN revoked by system")
        stopVpn()
        super.onRevoke()
    }

    private fun startForegroundWithNotification(cfg: ProxyConfig) {
        val mgr = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            mgr?.createNotificationChannel(
                NotificationChannel("vpn", "VPN status", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val n = Notification.Builder(this, "vpn")
            .setContentTitle("ProxyConnect")
            .setContentText("Connecting ${cfg.type} ${cfg.host}:${cfg.port}…")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pi)
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(1, n)
        }
    }

    private fun updateNotification(text: String) {
        val mgr = getSystemService(NotificationManager::class.java) ?: return
        val pi = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val n = if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, "vpn")
                .setContentTitle("ProxyConnect").setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_info).setContentIntent(pi).build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("ProxyConnect").setContentText(text)
                .setSmallIcon(android.R.drawable.ic_dialog_info).setContentIntent(pi).build()
        }
        mgr.notify(1, n)
    }
}
