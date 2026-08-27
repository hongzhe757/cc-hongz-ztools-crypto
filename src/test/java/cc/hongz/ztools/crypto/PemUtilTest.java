package cc.hongz.ztools.crypto;

import cc.hongz.ztools.core.io.FileUtil;
import cc.hongz.ztools.core.io.resource.ResourceUtil;
import cc.hongz.ztools.core.util.StrUtil;
import cc.hongz.ztools.crypto.asymmetric.KeyType;
import cc.hongz.ztools.crypto.asymmetric.RSA;
import cc.hongz.ztools.crypto.asymmetric.SM2;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

@DisplayName("Pem Util测试")
public class PemUtilTest {

    @Test
    @DisplayName("read Private Key Test测试")
    public void readPrivateKeyTest() {
        final PrivateKey privateKey = PemUtil.readPemPrivateKey(ResourceUtil.getStream("test_private_key.pem"));
        assertNotNull(privateKey);
    }

    @Test
    @DisplayName("read Public Key Test测试")
    public void readPublicKeyTest() {
        final PublicKey publicKey = PemUtil.readPemPublicKey(ResourceUtil.getStream("test_public_key.csr"));
        assertNotNull(publicKey);
    }

    @Test
    @DisplayName("read Pem Key Test测试")
    public void readPemKeyTest() {
        final PublicKey publicKey = (PublicKey) PemUtil.readPemKey(ResourceUtil.getStream("test_public_key.csr"));
        assertNotNull(publicKey);
    }

    @Test
    @DisplayName("validate Key测试")
    public void validateKey() {
        final PrivateKey privateKey = PemUtil.readPemPrivateKey(ResourceUtil.getStream("test_private_key.pem"));
        final PublicKey publicKey = PemUtil.readPemPublicKey(ResourceUtil.getStream("test_public_key.csr"));

        final RSA rsa = new RSA(privateKey, publicKey);
        final String str = "你好，Hutool";//测试字符串

        final String encryptStr = rsa.encryptBase64(str, KeyType.PublicKey);
        final String decryptStr = rsa.decryptStr(encryptStr, KeyType.PrivateKey);
        assertEquals(str, decryptStr);
    }

    @Test
    @DisplayName("read EC Private Key Test测试")
    public void readECPrivateKeyTest() {
        final PrivateKey privateKey = PemUtil.readPemPrivateKey(ResourceUtil.getStream("test_ec_sec1_private_key.pem"));
        final SM2 sm2 = new SM2(privateKey, null);
        sm2.usePlainEncoding();

        //需要签名的明文,得到明文对应的字节数组
        final byte[] dataBytes = "我是一段测试aaaa".getBytes(StandardCharsets.UTF_8);

        final byte[] sign = sm2.sign(dataBytes, null);
        // 64位签名
        assertEquals(64, sign.length);
    }

    @Test
    @Disabled
    public void readECPrivateKeyTest2() {
        // https://gitee.com/chinabugotech/hutool/issues/I37Z75
        final byte[] d = PemUtil.readPem(FileUtil.getInputStream("d:/test/keys/priv.key"));
        final byte[] publicKey = PemUtil.readPem(FileUtil.getInputStream("d:/test/keys/pub.key"));

        final SM2 sm2 = new SM2(d, publicKey);
        sm2.usePlainEncoding();

        final String content = "我是Hanley.";
        final byte[] sign = sm2.sign(StrUtil.utf8Bytes(content));
        final boolean verify = sm2.verify(StrUtil.utf8Bytes(content), sign);
        assertTrue(verify);
    }

}
