package com.lynas.client

import com.fasterxml.jackson.databind.ObjectMapper
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.context.annotation.Bean
import org.springframework.http.HttpHeaders
import org.springframework.http.MediaType
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*
import javax.crypto.Cipher

@SpringBootApplication
class ClientApplication{
	@Bean
	fun restClient() = RestClient.builder().build()
}

fun main(args: Array<String>) {
	runApplication<ClientApplication>(*args)
}

@RestController
class DemoController(val restClient: RestClient) {

	@GetMapping("/demo")
	fun demo(): String? {

		val key = RSAEncryptionUtil.loadPublicKey(publicKey)
		val token = RSAEncryptionUtil.encrypt("${LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)}", key)

		val result = restClient.post()
			.uri("http://localhost:8082/verify-time")
			.header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
			.header("AUTH-TOKEN", token)
			.body(ObjectMapper().writeValueAsString(DemoObject(data = "Demo")))
			.retrieve()
			.toBodilessEntity()
			.statusCode

		return "Http Response code ${result.value()}"
	}
}

object RSAEncryptionUtil {

	fun loadPublicKey(publicKeyPEM: String): PublicKey {
		val clear = publicKeyPEM.lines()
			.filter { line -> !line.startsWith("-----") }
			.joinToString(separator = "")
		val keyBytes = Base64.getDecoder().decode(clear)
		val keySpec = X509EncodedKeySpec(keyBytes)
		val keyFactory = KeyFactory.getInstance("RSA")
		return keyFactory.generatePublic(keySpec)
	}

	fun encrypt(text: String, publicKey: PublicKey): String {
		val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
		cipher.init(Cipher.ENCRYPT_MODE, publicKey)
		val encryptedBytes = cipher.doFinal(text.toByteArray())
		return Base64.getEncoder().encodeToString(encryptedBytes)
	}
}

data class DemoObject(val data: String)

const val publicKey = "-----BEGIN PUBLIC KEY-----\n" +
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjGRf+j5Q3fY44WCnaeNnzw/d8\n" +
		"32UuYWeVT4nmtvqMDq1GoXwgbpXCSKS3VJNDQOjM7d02FFRNF3DE91qyD6gKo1yI\n" +
		"VZPvPLsTHazLGpi9VJvTxCq8rUZTKnxUqoTEm/EjiUIBFePrlCbo5w7X6Bs0pdGp\n" +
		"1Z/zHhQN+sseCThC3QIDAQAB\n" +
		"-----END PUBLIC KEY-----"