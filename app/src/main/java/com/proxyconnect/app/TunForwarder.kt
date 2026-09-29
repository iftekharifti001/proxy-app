package com.proxyconnect.app

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import kotlin.random.Random

/**
 * Userspace TCP stack: reads IPv4 packets from TUN, opens a proxied
 * socket per TCP flow (SOCKS5 or HTTP CONNECT), relays both directions
 * by crafting IP/TCP reply packets. DNS (UDP/53) is forwarded over TCP
 * through the proxy. Other UDP/ICMP is dropped.
 */
class TunForwarder(
    private val tunIn: FileInputStream,
    private val tunOut: FileOutputStream,
    private val config: ProxyConfig,
    private val protect: (Socket) -> Boolean,
    private val log: (String) -> Unit
) {
    @Volatile var running = true

    private val sessions = ConcurrentHashMap<FlowKey, TcpSession>()
    private val executor: ExecutorService = Executors.newCachedThreadPool()
    private val writeLock = Any()
    private var packetId = Random.nextInt(1, 60000)

    data class FlowKey(val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int)

    private inner class TcpSession(
        val key: FlowKey,
        var clientSeq: Int,      // next expected seq from app
        var ourSeq: Int,         // next seq we will send
        @Volatile var connected: Boolean = false,
        @Volatile var proxy: Socket? = null,
        @Volatile var closed: Boolean = false
    )

    fun runLoop() {
        val buf = ByteArray(32767)
        log("Forwarder started (${config.type} ${config.host}:${config.port}${if (config.hasAuth) " +auth" else ""})")
        try {
            while (running) {
                val n = try {
                    tunIn.read(buf)
                } catch (e: IOException) {
                    if (running) log("TUN read error: ${e.message}")
                    break
                }
                if (n <= 0) continue
                try {
                    handlePacket(buf, n)
                } catch (e: Exception) {
                    log("packet error: ${e.message}")
                }
            }
        } finally {
            stop()
        }
    }

    fun stop() {
        running = false
        executor.shutdownNow()
        sessions.values.forEach { closeQuietly(it.proxy) }
        sessions.clear()
    }

    // ---------- packet dispatch ----------

    private fun handlePacket(buf: ByteArray, len: Int) {
        if (len < 20) return
        val ver = (buf[0].toInt() ushr 4) and 0xF
        if (ver != 4) return
        val ihl = (buf[0].toInt() and 0xF) * 4
        if (len < ihl) return
        val proto = buf[9].toInt() and 0xFF
        val srcIp = readInt(buf, 12)
        val dstIp = readInt(buf, 16)
        when (proto) {
            6 -> handleTcp(buf, len, ihl, srcIp, dstIp)
            17 -> handleUdp(buf, len, ihl, srcIp, dstIp)
            else -> { /* drop ICMP etc. */ }
        }
    }

    // ---------- TCP ----------

    private fun handleTcp(buf: ByteArray, len: Int, ipOff: Int, srcIp: Int, dstIp: Int) {
        if (len < ipOff + 20) return
        val srcPort = readShort(buf, ipOff) and 0xFFFF
        val dstPort = readShort(buf, ipOff + 2) and 0xFFFF
        val seq = readInt(buf, ipOff + 4)
        val ack = readInt(buf, ipOff + 8)
        val dataOff = ((buf[ipOff + 12].toInt() ushr 4) and 0xF) * 4
        val flags = buf[ipOff + 13].toInt() and 0xFF
        val isSyn = (flags and 0x02) != 0
        val isAck = (flags and 0x10) != 0
        val isFin = (flags and 0x01) != 0
        val isRst = (flags and 0x04) != 0
        val payloadOff = ipOff + dataOff
        val payloadLen = len - payloadOff

        val key = FlowKey(srcIp, srcPort, dstIp, dstPort)
        var sess = sessions[key]

        if (isRst) {
            if (sess != null) closeSession(sess)
            return
        }

        if (sess == null) {
            if (!isSyn) {
                sendRst(dstIp, srcIp, dstPort, srcPort, seq, ack)
                return
            }
            // New connection: reply SYN-ACK immediately, connect upstream in background
            val ourSeq = Random.nextInt()
            val s = TcpSession(key, clientSeq = seq + 1, ourSeq = ourSeq)
            sessions[key] = s
            sendSynAck(dstIp, srcIp, dstPort, srcPort, ourSeq, seq + 1)
            s.ourSeq = ourSeq + 1
            executor.execute { connectUpstream(s) }
            // If SYN carried data (rare), ignore; client will retransmit after handshake
            return
        }

        if (sess.closed) return

        if (isSyn) {
            // Retransmitted SYN: resend SYN-ACK with original ourSeq-1
            sendSynAck(dstIp, srcIp, dstPort, srcPort, sess.ourSeq - 1, sess.clientSeq)
            return
        }

        if (isFin) {
            sess.clientSeq = seq + payloadLen + 1
            if (payloadLen > 0 && sess.connected) forwardToProxy(sess, buf, payloadOff, payloadLen)
            sendFinAck(sess, dstIp, srcIp, dstPort, srcPort)
            // half-close upstream output; full close when proxy EOF arrives
            try { sess.proxy?.shutdownOutput() } catch (_: Exception) {}
            return
        }

        if (payloadLen > 0) {
            if (seq != sess.clientSeq) {
                // Out-of-order or duplicate: re-ACK current state
                sendAck(sess, dstIp, srcIp, dstPort, srcPort)
                return
            }
            sess.clientSeq = seq + payloadLen
            if (sess.connected) {
                if (!forwardToProxy(sess, buf, payloadOff, payloadLen)) return
            }
            // else: handshake not done yet — ACK anyway; data will be retransmitted
            sendAck(sess, dstIp, srcIp, dstPort, srcPort)
        } else if (isAck) {
            sess.connected = sess.connected || true
            // pure ACK: nothing to do
        }
    }

    private fun connectUpstream(sess: TcpSession) {
        try {
            val dstIpStr = ipToString(sess.key.dstIp)
            val user = if (config.hasAuth) config.username else null
            val pass = if (config.hasAuth) config.password else null
            val sock = when (config.type) {
                ProxyType.SOCKS5 -> {
                    Socks5Client.connect(dstIpStr, sess.key.dstPort, config.host, config.port, user, pass,
                        onPreConnect = { protect(it) })
                }
                ProxyType.HTTP -> {
                    HttpProxyClient.connect(dstIpStr, sess.key.dstPort, config.host, config.port, user, pass,
                        onPreConnect = { protect(it) })
                }
            }
            if (sess.closed) { closeQuietly(sock); return }
            sess.proxy = sock
            sess.connected = true
            executor.execute { pumpProxyToTun(sess) }
        } catch (e: Exception) {
            log("connect ${ipToString(sess.key.dstIp)}:${sess.key.dstPort} failed: ${e.message}")
            // Send RST so the app fails fast instead of hanging
            try {
                sendRst(
                    sess.key.dstIp, sess.key.srcIp, sess.key.dstPort, sess.key.srcPort,
                    sess.clientSeq, sess.ourSeq
                )
            } catch (_: Exception) {}
            closeSession(sess)
        }
    }

    private fun forwardToProxy(sess: TcpSession, buf: ByteArray, off: Int, len: Int): Boolean {
        val p = sess.proxy
        if (p == null || sess.closed) return false
        return try {
            val out = p.getOutputStream()
            out.write(buf, off, len)
            out.flush()
            true
        } catch (e: Exception) {
            closeSession(sess)
            try {
                sendRst(sess.key.dstIp, sess.key.srcIp, sess.key.dstPort, sess.key.srcPort, sess.clientSeq, sess.ourSeq)
            } catch (_: Exception) {}
            false
        }
    }

    private fun pumpProxyToTun(sess: TcpSession) {
        val sock = sess.proxy ?: return
        val tmp = ByteArray(1400)
        try {
            val input = sock.getInputStream()
            while (running && !sess.closed) {
                val n = try { input.read(tmp) } catch (e: Exception) { -1 }
                if (n < 0) break // proxy EOF -> FIN to app
                var off = 0
                while (off < n) {
                    val chunk = minOf(n - off, 1400)
                    val pkt: ByteArray
                    synchronized(sess) {
                        if (sess.closed) return
                        pkt = buildTcpPacket(
                            sess.key.dstIp, sess.key.srcIp,
                            sess.key.dstPort, sess.key.srcPort,
                            sess.ourSeq, sess.clientSeq,
                            flags = 0x18, // PSH+ACK
                            payload = tmp, payloadOff = off, payloadLen = chunk
                        )
                        sess.ourSeq += chunk
                    }
                    writeTun(pkt)
                    off += chunk
                }
            }
        } catch (_: Exception) {
        } finally {
            if (!sess.closed) {
                // Clean FIN to the app
                try {
                    synchronized(sess) {
                        val fin = buildTcpPacket(
                            sess.key.dstIp, sess.key.srcIp,
                            sess.key.dstPort, sess.key.srcPort,
                            sess.ourSeq, sess.clientSeq, flags = 0x11, // FIN+ACK
                            payload = null, payloadOff = 0, payloadLen = 0
                        )
                        sess.ourSeq += 1
                        writeTun(fin)
                    }
                } catch (_: Exception) {}
                closeSession(sess)
            }
        }
    }

    private fun closeSession(sess: TcpSession) {
        sess.closed = true
        sessions.remove(sess.key)
        closeQuietly(sess.proxy)
        sess.proxy = null
    }

    // ---------- UDP: DNS over TCP via proxy ----------

    private fun handleUdp(buf: ByteArray, len: Int, ipOff: Int, srcIp: Int, dstIp: Int) {
        if (len < ipOff + 8) return
        val srcPort = readShort(buf, ipOff) and 0xFFFF
        val dstPort = readShort(buf, ipOff + 2) and 0xFFFF
        if (dstPort != 53) return // drop non-DNS UDP (standard for proxy apps)
        val udpLen = readShort(buf, ipOff + 4) and 0xFFFF
        val dnsOff = ipOff + 8
        val dnsLen = minOf(udpLen - 8, len - dnsOff)
        if (dnsLen <= 0) return
        val query = buf.copyOfRange(dnsOff, dnsOff + dnsLen)
        executor.execute { answerDns(srcIp, srcPort, dstIp, query) }
    }

    private fun answerDns(srcIp: Int, srcPort: Int, dnsServerIp: Int, query: ByteArray) {
        try {
            val server = ipToString(dnsServerIp)
            val user = if (config.hasAuth) config.username else null
            val pass = if (config.hasAuth) config.password else null
            val sock = when (config.type) {
                ProxyType.SOCKS5 -> Socks5Client.connect(server, 53, config.host, config.port, user, pass,
                    onPreConnect = { protect(it) })
                ProxyType.HTTP -> HttpProxyClient.connect(server, 53, config.host, config.port, user, pass,
                    onPreConnect = { protect(it) })
            }
            sock.soTimeout = 10_000
            try {
                val out = DataOutputStream(sock.getOutputStream())
                val input = DataInputStream(sock.getInputStream())
                out.writeShort(query.size)
                out.write(query)
                out.flush()
                val respLen = input.readUnsignedShort()
                if (respLen <= 0 || respLen > 4096) throw IOException("bad DNS reply len $respLen")
                val resp = ByteArray(respLen)
                input.readFully(resp)
                val udp = buildUdpPacket(dnsServerIp, srcIp, 53, srcPort, resp)
                writeTun(udp)
            } finally {
                closeQuietly(sock)
            }
        } catch (e: Exception) {
            log("DNS via proxy failed: ${e.message}")
        }
    }

    // ---------- packet builders ----------

    private fun sendSynAck(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, seq: Int, ack: Int) {
        // MSS 1460 option
        val opts = byteArrayOf(0x02, 0x04, 0x05, 0xB4)
        val pkt = buildTcpPacket(srcIp, dstIp, srcPort, dstPort, seq, ack, 0x12, null, 0, 0, opts)
        writeTun(pkt)
    }

    private fun sendAck(sess: TcpSession, srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int) {
        val pkt: ByteArray
        synchronized(sess) {
            pkt = buildTcpPacket(srcIp, dstIp, srcPort, dstPort, sess.ourSeq, sess.clientSeq, 0x10, null, 0, 0, null)
        }
        writeTun(pkt)
    }

    private fun sendFinAck(sess: TcpSession, srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int) {
        val pkt: ByteArray
        synchronized(sess) {
            pkt = buildTcpPacket(srcIp, dstIp, srcPort, dstPort, sess.ourSeq, sess.clientSeq, 0x11, null, 0, 0, null)
            sess.ourSeq += 1
        }
        writeTun(pkt)
    }

    private fun sendRst(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, seq: Int, ack: Int) {
        val pkt = buildTcpPacket(srcIp, dstIp, srcPort, dstPort, seq, ack, 0x14, null, 0, 0, null)
        writeTun(pkt)
    }

    private fun buildTcpPacket(
        srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int,
        seq: Int, ackNum: Int, flags: Int,
        payload: ByteArray?, payloadOff: Int, payloadLen: Int,
        options: ByteArray? = null
    ): ByteArray {
        val optLen = options?.size ?: 0
        val tcpLen = 20 + optLen + payloadLen
        val total = 20 + tcpLen
        val p = ByteArray(total)
        // IP header
        p[0] = 0x45
        p[1] = 0x00
        writeShort(p, 2, total)
        val id = synchronized(writeLock) { packetId = (packetId + 1) and 0xFFFF; packetId }
        writeShort(p, 4, id)
        p[6] = 0x40; p[7] = 0x00 // DF
        p[8] = 64 // TTL
        p[9] = 6  // TCP
        writeInt(p, 12, srcIp)
        writeInt(p, 16, dstIp)
        writeShort(p, 20, ipChecksum(p, 0, 20).toInt() and 0xFFFF)
        // TCP header
        val t = 20
        writeShort(p, t, srcPort)
        writeShort(p, t + 2, dstPort)
        writeInt(p, t + 4, seq)
        writeInt(p, t + 8, ackNum)
        p[t + 12] = (((20 + optLen) / 4) shl 4).toByte()
        p[t + 13] = flags.toByte()
        writeShort(p, t + 14, 65535) // window
        if (options != null) System.arraycopy(options, 0, p, t + 20, options.size)
        if (payload != null && payloadLen > 0) System.arraycopy(payload, payloadOff, p, t + 20 + optLen, payloadLen)
        val csum = tcpChecksum(p, 20, tcpLen, srcIp, dstIp)
        writeShort(p, t + 16, csum.toInt() and 0xFFFF)
        return p
    }

    private fun buildUdpPacket(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val total = 20 + udpLen
        val p = ByteArray(total)
        p[0] = 0x45; p[1] = 0x00
        writeShort(p, 2, total)
        val id = synchronized(writeLock) { packetId = (packetId + 1) and 0xFFFF; packetId }
        writeShort(p, 4, id)
        p[6] = 0x00; p[7] = 0x00
        p[8] = 64; p[9] = 17
        writeInt(p, 12, srcIp)
        writeInt(p, 16, dstIp)
        writeShort(p, 20, ipChecksum(p, 0, 20).toInt() and 0xFFFF)
        writeShort(p, 20, srcPort)
        writeShort(p, 22, dstPort)
        writeShort(p, 24, udpLen)
        writeShort(p, 26, 0) // checksum optional for IPv4; zero it
        System.arraycopy(payload, 0, p, 28, payload.size)
        return p
    }

    private fun writeTun(pkt: ByteArray) {
        synchronized(writeLock) {
            try {
                tunOut.write(pkt)
                tunOut.flush()
            } catch (e: IOException) {
                if (running) log("TUN write error: ${e.message}")
            }
        }
    }

    // ---------- helpers ----------

    private fun closeQuietly(s: Socket?) { try { s?.close() } catch (_: Exception) {} }

    private fun readShort(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)

    private fun readInt(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
                ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    private fun writeShort(b: ByteArray, o: Int, v: Int) {
        b[o] = ((v ushr 8) and 0xFF).toByte()
        b[o + 1] = (v and 0xFF).toByte()
    }

    private fun writeInt(b: ByteArray, o: Int, v: Int) {
        b[o] = ((v ushr 24) and 0xFF).toByte()
        b[o + 1] = ((v ushr 16) and 0xFF).toByte()
        b[o + 2] = ((v ushr 8) and 0xFF).toByte()
        b[o + 3] = (v and 0xFF).toByte()
    }

    private fun ipChecksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0L
        var i = off
        while (i < off + len - 1) {
            sum += (((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < off + len) sum += ((b[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    private fun tcpChecksum(pkt: ByteArray, tcpOff: Int, tcpLen: Int, srcIp: Int, dstIp: Int): Int {
        var sum = 0L
        sum += ((srcIp ushr 16) and 0xFFFF) + (srcIp and 0xFFFF)
        sum += ((dstIp ushr 16) and 0xFFFF) + (dstIp and 0xFFFF)
        sum += 6 // protocol
        sum += tcpLen
        var i = tcpOff
        val end = tcpOff + tcpLen
        while (i < end - 1) {
            if (i == tcpOff + 16) { i += 2; continue } // skip checksum field
            sum += (((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        if (i < end) sum += ((pkt[i].toInt() and 0xFF) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt().inv() and 0xFFFF
    }

    private fun ipToString(ip: Int): String =
        "${(ip ushr 24) and 0xFF}.${(ip ushr 16) and 0xFF}.${(ip ushr 8) and 0xFF}.${ip and 0xFF}"
}
