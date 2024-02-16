package com.lynas.server

import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import java.util.*

data class DtoApiSession(val manufacturerAuthorizationId: UUID, val allowedCustomers: List<UUID>)
class CustomAuthenticator : Authentication {
    private var _authorities = mutableListOf<GrantedAuthority>()
    private var _principal: DtoApiSession? = null
    private var _isAuthenticated: Boolean = false

    override fun getAuthorities(): MutableCollection<out GrantedAuthority> = this._authorities

    override fun setAuthenticated(isAuthenticated: Boolean) {
        _isAuthenticated = isAuthenticated
    }

    override fun getName(): String = ""

    override fun getCredentials(): String = ""

    override fun getPrincipal(): DtoApiSession? = _principal

    override fun isAuthenticated(): Boolean = _isAuthenticated

    override fun getDetails(): Any? = null

    @Suppress("unused")
    fun setGrantedAuthorities(authorities: MutableList<GrantedAuthority>) {
        this._authorities = authorities
    }
}
