package cc.hongz.ztools.crypto.symmetric;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * TEA（Tiny Encryption Algorithm）和 XTEA算法单元测试
 */
@DisplayName("TEA测试")
public class TEATest {

    @Test
    @DisplayName("tea Test测试")
    public void teaTest() {
        String data = "测试的加密数据 by Hutool";

        // 密钥必须为128bit
        final SymmetricCrypto tea = new SymmetricCrypto("TEA", "MyPassword123456".getBytes());
        final byte[] encrypt = tea.encrypt(data);

        // 解密
        final String decryptStr = tea.decryptStr(encrypt);

        assertEquals(data, decryptStr);
    }

    @Test
    @DisplayName("xtea Test测试")
    public void xteaTest() {
        String data = "测试的加密数据 by Hutool";

        // 密钥必须为128bit
        final SymmetricCrypto tea = new SymmetricCrypto("XTEA", "MyPassword123456".getBytes());
        final byte[] encrypt = tea.encrypt(data);

        // 解密
        final String decryptStr = tea.decryptStr(encrypt);

        assertEquals(data, decryptStr);
    }

    @Test
    @DisplayName("xxtea Test测试")
    public void xxteaTest() {
        String data = "测试的加密数据 by Hutool";

        // 密钥必须为128bit
        final XXTEA tea = new XXTEA("MyPassword123456".getBytes());
        final byte[] encrypt = tea.encrypt(data);

        // 解密
        final String decryptStr = tea.decryptStr(encrypt);

        assertEquals(data, decryptStr);
    }
}
