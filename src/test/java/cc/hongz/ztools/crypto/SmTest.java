package cc.hongz.ztools.crypto;

import cc.hongz.ztools.core.util.CharsetUtil;
import cc.hongz.ztools.crypto.KeyUtil;
import cc.hongz.ztools.crypto.Mode;
import cc.hongz.ztools.crypto.Padding;
import cc.hongz.ztools.crypto.SmUtil;
import cc.hongz.ztools.crypto.digest.HMac;
import cc.hongz.ztools.crypto.symmetric.SM4;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;

/**
 * SM单元测试
 *
 * @author looly
 *
 */
@DisplayName("Sm测试")
public class SmTest {

    @Test
    @DisplayName("sm3Test测试")
    public void sm3Test() {
        String digestHex = SmUtil.sm3("aaaaa");
        assertEquals("136ce3c86e4ed909b76082055a61586af20b4dab674732ebd4b599eef080c9be", digestHex);
    }

    @Test
    @DisplayName("sm4Test测试")
    public void sm4Test() {
        String content = "test中文";
        SM4 sm4 = SmUtil.sm4();

        String encryptHex = sm4.encryptHex(content);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);

        assertEquals(content, decryptStr);
    }

    @Test
    @DisplayName("sm4Test2测试")
    public void sm4Test2() {
        String content = "test中文";
        SM4 sm4 = new SM4(Mode.CTR, Padding.PKCS5Padding);
        sm4.setIv("aaaabbbb".getBytes());

        String encryptHex = sm4.encryptHex(content);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);

        assertEquals(content, decryptStr);
    }

    @Test
    @DisplayName("sm4ECBPKCS5Padding Test2测试")
    public void sm4ECBPKCS5PaddingTest2() {
        String content = "test中文";
        SM4 sm4 = new SM4(Mode.ECB, Padding.PKCS5Padding);
        assertEquals("SM4/ECB/PKCS5Padding", sm4.getCipher().getAlgorithm());

        String encryptHex = sm4.encryptHex(content);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        assertEquals(content, decryptStr);
    }

    @Test
    @DisplayName("sm4Test With Custom Key Test测试")
    public void sm4TestWithCustomKeyTest() {
        String content = "test中文";

        SecretKey key = KeyUtil.generateKey(SM4.ALGORITHM_NAME);

        SM4 sm4 = new SM4(Mode.ECB, Padding.PKCS5Padding, key);
        assertEquals("SM4/ECB/PKCS5Padding", sm4.getCipher().getAlgorithm());

        String encryptHex = sm4.encryptHex(content);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        assertEquals(content, decryptStr);
    }

    @Test
    @DisplayName("sm4Test With Custom Key Test2测试")
    public void sm4TestWithCustomKeyTest2() {
        String content = "test中文frfewrewrwerwer---------------------------------------------------";

        byte[] key = KeyUtil.generateKey(SM4.ALGORITHM_NAME, 128).getEncoded();

        SM4 sm4 = SmUtil.sm4(key);
        assertEquals("SM4", sm4.getCipher().getAlgorithm());

        String encryptHex = sm4.encryptHex(content);
        String decryptStr = sm4.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);
        assertEquals(content, decryptStr);
    }

    @Test
    @DisplayName("hmac Sm3Test测试")
    public void hmacSm3Test() {
        String content = "test中文";
        HMac hMac = SmUtil.hmacSm3("password".getBytes());
        String digest = hMac.digestHex(content);
        assertEquals("493e3f9a1896b43075fbe54658076727960d69632ac6b6ed932195857a6840c6", digest);
    }


}
