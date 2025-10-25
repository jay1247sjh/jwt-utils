## jwt-utils

基于 JJWT 0.11.x 的轻量 Java 工具库，提供使用 RSA/RS256 生成与校验 JWT 的常用方法。

- 简洁 API：一行生成、解析 JWT
- RS256 支持：私钥签名、公钥验签
- Key 工具：从 Base64（DER）字符串恢复 RSA 私钥/公钥
- 即插即用：Java 21 + Maven

### 作者

小瓶子

### 环境要求

- Java 21
- Maven 3.9+
- 依赖：`io.jsonwebtoken:jjwt-* 0.11.5`

### 安装

该库尚未发布至中央仓库。你可以在本地安装后在其他项目中依赖：

```bash
mvn clean install -DskipTests
```

在其他项目的 `pom.xml` 中添加依赖：

```xml
<dependency>
    <groupId>sjh.jwt</groupId>
    <artifactId>jwt-utils</artifactId>
    <version>1.0.0</version>
</dependency>
```

本项目自身的关键依赖（已在 `pom.xml` 配置）：

```xml
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-api</artifactId>
    <version>0.11.5</version>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-impl</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
<dependency>
    <groupId>io.jsonwebtoken</groupId>
    <artifactId>jjwt-jackson</artifactId>
    <version>0.11.5</version>
    <scope>runtime</scope>
</dependency>
```

### 快速开始

方式一：直接生成一对 RSA 密钥用于演示

```java
KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();

Map<String, Object> claims = new HashMap<>();
claims.put("userId", 123);
claims.put("username", "engineer");

String token = JwtUtils.generateToken(
        kp.getPrivate(),
        Duration.ofHours(1),
        "engineer",          // subject
        "issuer-service",    // issuer
        "api-gateway",       // audience
        claims,               // additional claims
        null                  // kid（可选）
);
Jws<Claims> jws = JwtUtils.parseToken(
        token,
        kp.getPublic(),
        "issuer-service",
        "api-gateway",
        30                    // 允许时钟偏移秒数
);

System.out.println("token = " + token);
System.out.println("claims = " + jws.getBody());
```

方式二：从 Base64（DER）字符串恢复密钥（无 PEM 头尾）

```java
String priB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()); // PKCS#8 -> Base64
String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());  // X.509  -> Base64

PrivateKey privateKey = KeyUtils.getPrivatekey(priB64);
PublicKey publicKey   = KeyUtils.getPublickey(pubB64);

String token = JwtUtils.generateToken(
        privateKey,
        Duration.ofMinutes(30),
        "user-123",
        "issuer-service",
        "api-gateway",
        Map.of("role","admin"),
        null
);
Claims claims = JwtUtils.parseToken(token, publicKey, "issuer-service", "api-gateway", 30).getBody();
System.out.println(claims.get("role", String.class)); // admin
```

### API 说明

- `JwtUtils.generateToken(PrivateKey privateKey, Duration ttl, String subject, String issuer, String audience, Map<String,Object> additionalClaims, String kid)`
  - 用私钥（RS256）签名并生成 Token；自动设置 `iat/nbf/exp`，并写入 `sub/iss/aud/jti`。
  - 通过 `additionalClaims` 追加自定义 claims；如提供 `kid`，写入 Header 的 Key ID。

- `JwtUtils.parseToken(String token, PublicKey publicKey, String requiredIssuer, String requiredAudience, long allowedClockSkewSeconds)`
  - 使用公钥验签并解析 Token，支持要求 `iss/aud` 与设置时钟偏移；返回 `Jws<Claims>`。
  - 可能抛出 `ExpiredJwtException`、`SignatureException`、`MalformedJwtException` 等。

- `JwtUtils.getClaim(String token, PublicKey publicKey, String key)`
  - 验签成功后，从 claims 中读取指定字段；不存在时返回 null。

- `JwtUtils.validateToken(String token, PublicKey publicKey, String issuer, String audience, long clockSkewSeconds)`
  - 仅做布尔校验（不抛出），便于快速判断 Token 是否有效。

- `KeyUtils.getPrivatekey(String privateKeyStr)`
  - 从 Base64（PKCS#8 DER，无 PEM 头尾）字符串恢复私钥。

- `KeyUtils.getPublickey(String publicKeyStr)`
  - 从 Base64（X.509 DER，无 PEM 头尾）字符串恢复公钥。

### 常见问题（FAQ）

- 我有 PEM（带 `-----BEGIN ...`）格式的密钥，能直接用吗？
  - 当前 `KeyUtils` 需要“Base64(DER)”纯体字符串。如果是 PEM，请去除头尾并移除所有换行，再 Base64 解码得到 DER；或在代码中自行处理 PEM。

- 如何设置 `iss/aud/sub` 等保留字段？
  - 在 `generateToken(...)` 的参数中直接提供：`subject/issuer/audience`。

- 支持 `kid` 吗？
  - 支持。在生成时传入 `kid` 参数，库会将其写入 Header（用于密钥轮换）。

### 安全建议

- 令牌有效期尽量短（建议分钟级），并结合刷新机制。
- 不要在日志中打印完整 Token，必要时仅打印前后若干字符。
- 不要在 claims 中放入敏感隐私原文；必要时只放最小化信息或服务端会话存储敏感数据。
- 私钥需严格管控并定期轮换。

### 运行测试

```bash
mvn -Dtest=JwtUtilsTest test
```

### 许可证
本项目基于 [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) 许可开源。  
你可以自由地使用、修改和分发本项目的代码（包括商业用途），但请保留原作者署名：

> Copyright (c) 2025 小瓶子

若要了解完整条款，请阅读项目根目录下的 [LICENSE](./LICENSE) 文件。


