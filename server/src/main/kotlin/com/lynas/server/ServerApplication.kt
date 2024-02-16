package com.lynas.server

import jakarta.servlet.http.HttpServletRequest
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

@SpringBootApplication
class ServerApplication

fun main(args: Array<String>) {
	runApplication<ServerApplication>(*args)
}

@RestController
class TimeController {
	@PostMapping("/verify-time")
	fun verifyTime(@RequestBody data: DemoObject, httpRequest: HttpServletRequest): String {
		return "OK ${SecurityContextHolder.getContext().authentication.isAuthenticated}"
	}
}

data class DemoObject(val data: String)
