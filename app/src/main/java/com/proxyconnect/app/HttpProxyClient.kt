package com.proxyconnect.app

import android.util.Base64
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/** Minimal HTTP proxy CONNECT client (with optional Basic auth). */
object HttpProxyClient {

    @Throws(IOException::class)
    fun connect(
        targetHost: String,
        targetPort: Int,
        proxyHost: String,
        proxyPort: Int,
        username: String?,
        password: String?,
        timeoutMs: Int = 15_000,
        onPreConnect: ((Socket) -> Unit)? = null
    ): Socket {
        val sock = Socket()
        try {
            onPreConnect?.invoke(sock)
            sock.tcpNoDelay = true
            sock.connect(InetSocketAddress(proxyHost, proxyPort), timeoutMs)
            sock.soTimeout = timeoutMs
            val out = sock.getOutputStream()
            val input = sock.getInputStream()

            val sb = StringBuilder()
            sb.append("CONNECT ").append(targetHost).append(':').append(targetPort).append(" HTTP/1.1\r\n")
            sb.append("Host: ").append(targetHost).append(':').append(targetPort).append("\r\n")
            if (!username.isNullOrEmpty()) {
                val creds = "$username:${password ?: ""}"
                val b64 = Base64.encodeToString(creds.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)
                sb.append("Proxy-Authorization: Basic ").append(b64).append("\r\n")
            }
            sb.append("Proxy-Connection: Keep-Alive\r\n")
            sb.append("Connection: Keep-Alive\r\n\r\n")
            out.write(sb.toString().toByteArray(Charsets.UTF_8))
            out.flush()

            // Read header until \r\n\r\n
            val buf = ByteArrayOutputStream()
            val one = ByteArray(1)
            var matched = 0
            val tail = byteArrayOf('\r'.code.toByte(), '\n'.code.toByte(), '\r'.code.toByte(), '\n'.code.toByte())
            while (true) {
                val r = input.read(one)
                if (r < 0) throw IOException("HTTP proxy closed connection")
                buf.write(one[0].toInt())
                if (one[0] == tail[matched]) {
                    matched++
                    if (matched == 4) break
                } else {
                    matched = if (one[0] == '\r'.code.toByte()) 1 else 0
                }
                if (buf.size() > 32 * 1024) throw IOException("HTTP proxy: header too large")
            }
            val header = buf.toString("UTF-8")
            val statusLine = header.lineSequence().firstOrNull() ?: throw IOException("HTTP proxy: empty reply")
            // e.g. HTTP/1.1 200 Connection established
            val code = statusLine.split(" ").getOrNull(1)?.toIntOrNull()
                ?: throw IOException("HTTP proxy: bad reply: $statusLine")
            if (code != 200) {
                throw IOException("HTTP proxy: $statusLine (wrong host/port or user/pass? code=$code)")
            }
            sock.soTimeout = 0
            return sock
        } catch (e: Exception) {
            try { sock.close() } catch (_: Exception) {}
            throw e as? IOException ?: IOException(e.message, e)
        }
    }
}
