package sjh.jwt;

import io.jsonwebtoken.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

/**
 * JWT 工具类，基于 JJWT 0.11.x，提供使用 RS256 生成与解析 Token 的常用方法。
 * <p>
 * 特性：
 * <ul>
 *   <li>生成标准保留字段：iat、nbf、exp、sub、iss、aud、jti</li>
 *   <li>支持 Header 写入 kid（密钥轮换场景）</li>
 *   <li>解析时可指定 requireIssuer/requireAudience 与时钟偏移</li>
 *   <li>无状态静态方法，线程安全</li>
 * </ul>
 * <p>
 * 注意：不要在自定义 claims 中存放敏感信息的明文。
 *
 * @author 小瓶子
 * @since 2025-10-25
 */
public class JwtUtils {

    private JwtUtils() {

    }

    /**
     * 生成带标准保留字段的 JWT（RS256 签名）。
     *
     * @param privateKey       用于 RS256 签名的私钥
     * @param ttl              Token 有效期（以当前时间为基准）
     * @param subject          主体（sub）
     * @param issuer           签发方（iss）
     * @param audience         受众（aud）
     * @param additionalClaims 附加自定义 claims，使用 addClaims 合并
     * @param kid              Header 的 Key ID（可选，用于密钥轮换）
     *
     * @return 紧凑 JWT 字符串（header.payload.signature）
     *
     * @throws IllegalArgumentException 当参数非法时可能抛出
     */
    public static String generateToken(PrivateKey privateKey,
                                       Duration ttl,
                                       String subject,
                                       String issuer,
                                       String audience,
                                       Map<String, Object> additionalClaims,
                                       String kid) {
        // 获取当前时间
        Instant now = Instant.now();
        // 初始化生成对象
        JwtBuilder builder = Jwts.builder()
                // 签发时间
                .setIssuedAt(Date.from(now))
                // 生效时间
                .setNotBefore(Date.from(now))
                // 过期时间
                .setExpiration(Date.from(now.plus(ttl)))
                // 设置主体
                .setSubject(subject)
                // 设置签发人
                .setIssuer(issuer)
                // 设置
                .setAudience(audience)
                // 设置唯一id
                .setId(UUID.randomUUID().toString());
        // 添加附加信息
        if (additionalClaims != null && !additionalClaims.isEmpty()) {
            builder.addClaims(additionalClaims);
        }
        // 设置密钥对id（多对密钥对时用于辨别用哪对密钥对的公钥进行校验）
        if (kid != null && !kid.isEmpty()) {
            builder.setHeaderParam("kid", kid);
        }
        return builder.signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }

    /**
     * 验证并解析 Token。
     * <p>
     * 支持指定签发方（iss）与受众（aud）的必需值，并允许设置时钟偏移（单位：秒）。
     *
     * @param token                   待解析的紧凑 JWT 字符串
     * @param publicKey               用于验签的公钥
     * @param requiredIssuer          期望的签发方（可为 null 表示不校验）
     * @param requiredAudience        期望的受众（可为 null 表示不校验）
     * @param allowedClockSkewSeconds 允许的时钟偏移秒数（小于等于 0 表示不设置）
     *
     * @return 通过验签与校验后的 {@link Jws}（包含 {@link Claims}）
     *
     * @throws io.jsonwebtoken.JwtException 当签名不匹配、过期、结构非法或声明不满足要求时
     */
    public static Jws<Claims> parseToken(String token, PublicKey publicKey,
                                         String requiredIssuer,
                                         String requiredAudience,
                                         long allowedClockSkewSeconds) {
        // 初始化验证对象
        JwtParserBuilder parserBuilder = Jwts.parserBuilder().setSigningKey(publicKey);
        // 检查签发方
        if (requiredIssuer != null && !requiredIssuer.isEmpty()) {
            parserBuilder.requireIssuer(requiredIssuer);
        }
        // 检查接收方
        if (requiredAudience != null && !requiredAudience.isEmpty()) {
            parserBuilder.requireAudience(requiredAudience);
        }
        // 容忍时间设置
        if (allowedClockSkewSeconds > 0) {
            parserBuilder.setAllowedClockSkewSeconds(allowedClockSkewSeconds);
        }
        return parserBuilder.build().parseClaimsJws(token);
    }

    /**
     * 从 Token 中提取指定字段值（会先进行验签与基本校验）。
     *
     * @param token     紧凑 JWT 字符串
     * @param publicKey 用于验签的公钥
     * @param key       要提取的 claim 名称
     *
     * @return 对应值，可能为 {@code null}
     *
     * @throws io.jsonwebtoken.JwtException 当 Token 非法或验签失败
     */
    public static Object getClaim(String token, PublicKey publicKey, String key) {
        Claims claims = parseToken(token, publicKey, null, null, 0).getBody();
        return claims.get(key);
    }

    /**
     * 校验 Token 合法性（失败返回 false，不抛出）。
     *
     * @param token            待校验的紧凑 JWT 字符串
     * @param publicKey        用于验签的公钥
     * @param issuer           期望的签发方（可为 null）
     * @param audience         期望的受众（可为 null）
     * @param clockSkewSeconds 允许的时钟偏移秒数
     *
     * @return 合法返回 {@code true}，否则返回 {@code false}
     */
    public static boolean validateToken(String token, PublicKey publicKey,
                                        String issuer, String audience, long clockSkewSeconds) {
        try {
            parseToken(token, publicKey, issuer, audience, clockSkewSeconds);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
}
