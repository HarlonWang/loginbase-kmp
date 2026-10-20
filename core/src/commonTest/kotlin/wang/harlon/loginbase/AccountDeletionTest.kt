package wang.harlon.loginbase

import io.ktor.client.engine.mock.respond
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.TextContent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 账号删除（服务端 3.1.0）：sendAccountDeletionCode + deleteAccount */
class AccountDeletionTest {

    @Test
    fun `发删号码带 Bearer、不传邮箱`() = authTest {
        var sawBearer: String? = null
        var sawUrl: String? = null
        var sawBody: String? = null
        val (client, _) = clientWith(InMemoryTokenStore(TokenPair("a0", "r0"))) { request ->
            sawBearer = request.headers[HttpHeaders.Authorization]
            sawUrl = request.url.toString()
            sawBody = (request.body as TextContent).text
            respond("""{"cooldownSeconds":60}""", HttpStatusCode.OK, jsonHeaders())
        }
        assertEquals(60, client.sendAccountDeletionCode().cooldownSeconds)
        assertEquals("Bearer a0", sawBearer)
        assertEquals("$BASE/account/delete/code", sawUrl)
        assertFalse(sawBody!!.contains("email"), sawBody!!)
    }

    @Test
    fun `未登录直接抛 NotAuthenticated，不打服务端`() = authTest {
        var calls = 0
        val (client, _) = clientWith(InMemoryTokenStore()) {
            calls++
            respond("{}", HttpStatusCode.OK, jsonHeaders())
        }
        assertFailsWith<LoginbaseException.NotAuthenticated> { client.sendAccountDeletionCode() }
        assertFailsWith<LoginbaseException.NotAuthenticated> { client.deleteAccount("123456") }
        assertEquals(0, calls)
    }

    @Test
    fun `拒删时 reason 透出`() = authTest {
        val (client, _) = clientWith(InMemoryTokenStore(TokenPair("a0", "r0"))) {
            respond(
                """{"error":"deletion_blocked","reason":"active_subscription"}""",
                HttpStatusCode.Conflict,
                jsonHeaders(),
            )
        }
        val e = assertFailsWith<LoginbaseException.Api> { client.sendAccountDeletionCode() }
        assertEquals(AuthError.DELETION_BLOCKED, e.error)
        assertEquals("active_subscription", e.reason)
    }

    @Test
    fun `删除成功后清本地会话`() = authTest {
        val store = InMemoryTokenStore(TokenPair("a0", "r0"))
        var sawBody: String? = null
        val (client, _) = clientWith(store) { request ->
            sawBody = (request.body as TextContent).text
            respond("", HttpStatusCode.NoContent)
        }
        client.restore()
        client.deleteAccount("123456")
        assertTrue(sawBody!!.contains(""""code":"123456""""), sawBody!!)
        assertNull(store.load())
        assertIs<AuthState.SignedOut>(client.authState.value)
    }

    @Test
    fun `删除失败时保持登录态`() = authTest {
        val store = InMemoryTokenStore(TokenPair("a0", "r0"))
        val (client, _) = clientWith(store) {
            respond("""{"error":"invalid_code"}""", HttpStatusCode.BadRequest, jsonHeaders())
        }
        client.restore()
        val e = assertFailsWith<LoginbaseException.Api> { client.deleteAccount("000000") }
        assertEquals(AuthError.INVALID_CODE, e.error)
        assertNotNull(store.load())
        assertEquals(AuthState.SignedIn, client.authState.value)
    }

    @Test
    fun `access token 过期 401 时刷新后重试一次`() = authTest {
        val store = InMemoryTokenStore(TokenPair("stale", "r0"))
        val bearers = mutableListOf<String?>()
        val (client, _) = clientWith(store) { request ->
            when (request.url.encodedPath) {
                "/auth/refresh" -> respond("""{"accessToken":"a1","refreshToken":"r1"}""", HttpStatusCode.OK, jsonHeaders())
                else -> {
                    val bearer = request.headers[HttpHeaders.Authorization]
                    bearers += bearer
                    if (bearer == "Bearer stale") respond("""{"error":"Invalid token"}""", HttpStatusCode.Unauthorized, jsonHeaders())
                    else respond("""{"cooldownSeconds":60}""", HttpStatusCode.OK, jsonHeaders())
                }
            }
        }
        client.sendAccountDeletionCode()
        assertEquals(listOf<String?>("Bearer stale", "Bearer a1"), bearers)
    }
}
