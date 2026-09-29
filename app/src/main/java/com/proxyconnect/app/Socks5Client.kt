package com.proxyconnect.app

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

/** Minimal SOCKS5 CONNECT client (RFC 1928 + username/password RFC 1929). */
object Socks5Client {

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
            val out = DataOutputStream(sock.getOutputStream())
            val input = DataInputStream(sock.getInputStream())

            val useAuth = !username.isNullOrEmpty()
            if (useAuth) {
                out.write(byteArrayOf(0x05, 0x02, 0x00, 0x02)) // NO_AUTH + USERPASS
            } else {
                out.write(byteArrayOf(0x05, 0x01, 0x00))
            }
            out.flush()

            val ver = input.readUnsignedByte()
            val method = input.readUnsignedByte()
            if (ver != 0x05) throw IOException("SOCKS5: bad version $ver")
            when (method) {
                0x00 -> { /* no auth */ }
                0x02 -> {
                    if (!useAuth) throw IOException("SOCKS5: proxy requires auth")
                    val u = username!!.toByteArray(Charsets.UTF_8)
                    val p = (password ?: "").toByteArray(Charsets.UTF_8)
                    if (u.size > 255 || p.size > 255) throw IOException("SOCKS5: credentials too long")
                    out.writeByte(0x01)
                    out.writeByte(u.size)
                    out.write(u)
                    out.writeByte(p.size)
                    out.write(p)
                    out.flush()
                    val av = input.readUnsignedByte()
                    val status = input.readUnsignedByte()
                    if (av != 0x01 || status != 0x00) throw IOException("SOCKS5 auth failed (wrong user/pass?)")
                }
                0xFF -> throw IOException("SOCKS5: no acceptable auth method")
                else -> throw IOException("SOCKS5: unsupported method $method")
            }

            // CONNECT: send IPv4 bytes if target is an IP, else domain name
            // (TUN layer gives us destination IPs; remote DNS still used when possible)
            out.writeByte(0x05) // VER
            out.writeByte(0x01) // CONNECT
            out.writeByte(0x00) // RSV
            val ipv4 = parseIpv4(targetHost)
            if (ipv4 != null) {
                out.writeByte(0x01) // IPV4
                out.write(ipv4)
            } else {
                val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
                if (hostBytes.size > 255) throw IOException("Hostname too long")
                out.writeByte(0x03) // DOMAINNAME
                out.writeByte(hostBytes.size)
                out.write(hostBytes)
            }
            out.writeShort(targetPort)
            out.flush()

            val rVer = input.readUnsignedByte()
            val rep = input.readUnsignedByte()
            input.readUnsignedByte() // RSV
            val atyp = input.readUnsignedByte()
            when (atyp) {
                0x01 -> repeat(4) { input.readUnsignedByte() }
                0x03 -> { val n = input.readUnsignedByte(); repeat(n) { input.readUnsignedByte() } }
                0x04 -> repeat(16) { input.readUnsignedByte() }
                else -> throw IOException("SOCKS5: bad address type $atyp")
            }
            input.readUnsignedShort() // bound port
            if (rVer != 0x05) throw IOException("SOCKS5: bad reply version")
            if (rep != 0x00) throw IOException("SOCKS5 connect failed: ${repToMsg(rep)}")

            sock.soTimeout = 0
            return sock
        } catch (e: Exception) {
            try { sock.close() } catch (_: Exception) {}
            throw e as? IOException ?: IOException(e.message, e)
        }
    }

    private fun parseIpv4(h: String): ByteArray? {
        val parts = h.split(".")
        if (parts.size != 4) return null
        try {
            val b = ByteArray(4)
            for (i in 0..3) {
                val v = parts[i].toInt()
                if (v < 0 || v > 255) return null
                b[i] = v.toByte()
            }
            return b
        } catch (_: Exception) { return null }
    }

    private fun repToMsg(rep: Int): String = when (rep) {
        0x01 -> "general failure"
        0x02 -> "connection not allowed"
        0x03 -> "network unreachable"
        0x04 -> "host unreachable"
        0x05 -> "connection refused by destination"
        0x06 -> "TTL expired"
        0x07 -> "command not supported"
        0x08 -> "address type not supported"
        else -> "code $rep"
    }
}
