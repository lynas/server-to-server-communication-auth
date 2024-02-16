package com.lynas.server

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*
import javax.crypto.Cipher

@Component
class AuthFilter(
    private val rsaUtil: RSAUtil
): OncePerRequestFilter() {
    private val privateKey: PrivateKey = rsaUtil.loadPrivateKey(privateKeyG)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val token = request.getHeader("AUTH-TOKEN")
        if (token != null) {
            val decryptedTimeMili = rsaUtil.decrypt(Base64.getDecoder().decode(token), privateKey)
            if (isWithinOneHour(decryptedTimeMili.toLong())){
                val authentication = CustomAuthenticator().also { it.isAuthenticated = true }
                SecurityContextHolder.getContext().authentication = authentication
            }
        }
        filterChain.doFilter(request, response)
    }
}

@Component
class RSAUtil {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    fun loadPrivateKey(privateKeyPEM: String): PrivateKey {
        val clear = privateKeyPEM.lines()
            .filter { line -> !line.startsWith("-----") }
            .joinToString(separator = "")
        val keyBytes = Base64.getDecoder().decode(clear)
        val keySpec = PKCS8EncodedKeySpec(keyBytes)
        val keyFactory = KeyFactory.getInstance("RSA")
        return keyFactory.generatePrivate(keySpec)
    }

    fun decrypt(data: ByteArray, privateKey: PrivateKey): String {
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        return String(cipher.doFinal(data))
    }
}

fun isWithinOneHour(givenTimeMs: Long): Boolean {
    val curTimeMinusOneHour = LocalDateTime.now().minusHours(1).toEpochSecond(ZoneOffset.UTC)
    val curTimePlusOneHour = LocalDateTime.now().plusHours(1).toEpochSecond(ZoneOffset.UTC)
    return (givenTimeMs in (curTimeMinusOneHour + 1)..<curTimePlusOneHour)
}

const val privateKeyG = "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXAIBAAKBgQCjGRf+j5Q3fY44WCnaeNnzw/d832UuYWeVT4nmtvqMDq1GoXwg\n" +
        "bpXCSKS3VJNDQOjM7d02FFRNF3DE91qyD6gKo1yIVZPvPLsTHazLGpi9VJvTxCq8\n" +
        "rUZTKnxUqoTEm/EjiUIBFePrlCbo5w7X6Bs0pdGp1Z/zHhQN+sseCThC3QIDAQAB\n" +
        "AoGABCVlKMF5oRd+AAyts7ISyFGY/wGmztEHExKcjNLl951/5iXAxApLoE68cTSj\n" +
        "Mbh6sorxbqiBpBwOb9Nh6NjhCqmuzjuH+WToDCzWaMJde75kbIfgtYvSFtKKBQ6Y\n" +
        "q9riIYz+IDO6wyxXezuem7tKtS0nIO5/lcVs9iqVpXW8zfkCQQDtekNsFXYqp2LE\n" +
        "h8MVDKkcfSj6aJsyKO3fYSeQF8AijmLn1mprhY5Ij7lhLvkDub0gwNv0xEhDAVrx\n" +
        "p3XWptqzAkEAr9GvzwhRmRPUefA71xqo+40pW9p/cLjNYRqfo9dIJ1Up3qCSYp06\n" +
        "Fz6985z5VlR8xAUc6uubVZURJXEYdw90LwJBALKqyO0ZnITs2H9aUSiWFOmtNNZp\n" +
        "O1JavtTQSK69X73f+IPKqthobCsljuiSKaFm7eclkpct0dwvudeUETFE6ccCQG0c\n" +
        "JQ3HbNQhwUeXNZutONc7aEJPm6z5ksNDQXTtIiL+sAgwAAhg6G8KidlIPlg8AF2p\n" +
        "iqOjaXe4Fbb1s6gXmBMCQC1VZPTf36FLwmuqrCkiFZQos924XE3LX7rkrj0Sgl2U\n" +
        "Pa7fMCjN1M+SH28B0orq7mPd1B8TD64JxjM0Li7hrCM=\n" +
        "-----END RSA PRIVATE KEY-----"