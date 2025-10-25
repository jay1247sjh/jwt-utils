package sjh.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.junit.Before;
import org.junit.Test;
import org.junit.jupiter.api.DisplayName;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;


/**
 * JwtUtils 的功能测试。
 * <p>
 * 覆盖点：
 * <ul>
 *   <li>正常生成与解析 Token</li>
 *   <li>基于 issuer/audience 的校验</li>
 *   <li>读取自定义 Claim</li>
 *   <li>过期校验失败</li>
 *   <li>Header kid 的设置与读取</li>
 * </ul>
 * 使用 JUnit4 运行，Java 21 环境。
 * <p>
 * author 小瓶子
 */
public class JwtUtilsTest {

    private static RSAPrivateKey privateKey;
    private static RSAPublicKey publicKey;

    /**
     * 初始化测试所需的 RSA 密钥对。
     */
    @Before
    public void initKeys() throws Exception {
        // 生成测试用 RSA 密钥对
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        privateKey = (RSAPrivateKey) pair.getPrivate();
        publicKey = (RSAPublicKey) pair.getPublic();
    }

    /**
     * 测试：正常生成与解析 Token。
     */
    @Test
    @DisplayName("测试：正常生成与解析 Token")
    public void testGenerateAndParseToken() {
        // 附加字段
        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", 1001L);
        claims.put("role", "ADMIN");

        String token = JwtUtils.generateToken(
                privateKey,
                Duration.ofMinutes(5),
                "工程师",      // subject
                "sjh-system",  // issuer
                "sjh-client",  // audience
                claims,
                "key-1"        // kid
        );

        assertNotNull(token);
        System.out.println("生成的 Token: " + token);

        // 解析 Token
        Jws<Claims> jws = JwtUtils.parseToken(
                token, publicKey,
                "sjh-system",
                "sjh-client",
                30
        );

        Claims body = jws.getBody();
        assertEquals("工程师", body.getSubject());
        assertEquals("sjh-system", body.getIssuer());
        assertEquals("sjh-client", body.getAudience());
        assertEquals(1001L, ((Number) body.get("userId")).longValue());
        assertEquals("ADMIN", body.get("role"));
        assertNotNull(body.getId());
    }

    /**
     * 测试：校验 Token 合法性。
     */
    @Test
    @DisplayName("测试：校验 Token 合法性")
    public void testValidateToken() {
        String token = JwtUtils.generateToken(
                privateKey,
                Duration.ofMinutes(2),
                "userA",
                "sjh-system",
                "sjh-client",
                null,
                null
        );

        assertTrue(JwtUtils.validateToken(token, publicKey, "sjh-system", "sjh-client", 10));
        // 错误的issuer
        assertFalse(JwtUtils.validateToken(token, publicKey, "wrong-issuer", "sjh-client", 10));
    }

    /**
     * 测试：提取指定 Claim 字段。
     */
    @Test
    @DisplayName("测试：提取指定 Claim 字段")
    public void testGetClaim() {
        Map<String, Object> claims = Map.of("userId", 9999L);
        String token = JwtUtils.generateToken(
                privateKey,
                Duration.ofMinutes(5),
                "test",
                "issuer",
                "audience",
                claims,
                null
        );

        Object userId = JwtUtils.getClaim(token, publicKey, "userId");
        assertEquals(9999L, ((Number) userId).longValue());
    }

    /**
     * 测试：过期 Token 校验应失败。
     */
    @Test
    @DisplayName("测试：过期 Token 校验应失败")
    public void testExpiredToken() throws InterruptedException {
        String token = JwtUtils.generateToken(
                privateKey,
                Duration.ofSeconds(1),
                "expire-test",
                "issuer",
                "audience",
                null,
                null
        );

        Thread.sleep(1500); // 等待过期
        boolean valid = JwtUtils.validateToken(token, publicKey, "issuer", "audience", 0);
        assertFalse("过期的 Token 不应通过验证", valid);
    }

    /**
     * 测试：包含 kid 的 Token 头参数。
     */
    @Test
    @DisplayName("测试：包含 kid 的 Token 头参数")
    public void testKidHeader() {
        String kid = "rsa-key-2025";
        String token = JwtUtils.generateToken(
                privateKey,
                Duration.ofMinutes(5),
                "userX",
                "issuer",
                "audience",
                null,
                kid
        );

        // 获取 header
        Jws<Claims> jws = JwtUtils.parseToken(token, publicKey, "issuer", "audience", 10);
        String actualKid = jws.getHeader().getKeyId();
        assertEquals(kid, actualKid);
    }
}
