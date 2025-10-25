package sjh.jwt;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * RSA 密钥工具类：从 Base64（DER 编码）字符串恢复私钥/公钥。
 * <p>
 * 约定：
 * <ul>
 *   <li>私钥：PKCS#8 DER - Base64（无 PEM 头尾与换行）</li>
 *   <li>公钥：X.509 DER - Base64（无 PEM 头尾与换行）</li>
 * </ul>
 * 示例：
 * <pre>
 * KeyPair kp = KeyPairGenerator.getInstance("RSA").generateKeyPair();
 * String priB64 = Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded());
 * String pubB64 = Base64.getEncoder().encodeToString(kp.getPublic().getEncoded());
 * PrivateKey pri = KeyUtils.getPrivatekey(priB64);
 * PublicKey pub = KeyUtils.getPublickey(pubB64);
 * </pre>
 * <p>
 * 注意：如果你的密钥是 PEM 格式（包含 -----BEGIN/END----- 与换行），
 * 需要先去头去尾并移除换行，只保留 Base64 主体再传入本工具方法。
 *
 * @author 小瓶子
 * @since 2025-10-25
 */
public class KeyUtils {

    /**
     * 从 Base64（PKCS#8 DER）字符串恢复 RSA 私钥。
     *
     * @param privateKeyStr Base64（PKCS#8 DER）字符串
     *
     * @return 私钥对象
     *
     * @throws Exception 当 Base64 解码或密钥规格不合法时
     */
    public static PrivateKey getPrivatekey(String privateKeyStr) throws Exception {
        // 将Base64还原为二进制
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyStr);
        // 使用PKCS8格式进行恢复对象
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        // 使用RSA生成密钥
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /**
     * 从 Base64（X.509 DER）字符串恢复 RSA 公钥。
     *
     * @param publicKeyStr Base64（X.509 DER）字符串
     *
     * @return 公钥对象
     *
     * @throws Exception 当 Base64 解码或密钥规格不合法时
     */
    public static PublicKey getPublickey(String publicKeyStr) throws Exception {
        // 将Base64还原为二进制
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyStr);
        // 使用X509格式进行恢复对象
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        // 使用RSA生成密钥
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }
}
