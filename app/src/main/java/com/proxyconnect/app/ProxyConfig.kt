package com.proxyconnect.app

enum class ProxyType { SOCKS5, HTTP }

data class ProxyConfig(
    val type: ProxyType = ProxyType.SOCKS5,
    val host: String = "",
    val port: Int = 1080,
    val username: String = "",
    val password: String = "",
    val useAuth: Boolean = false
) {
    val hasAuth: Boolean get() = useAuth && username.isNotEmpty()
}
