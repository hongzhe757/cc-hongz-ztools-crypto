package cc.hongz.ztools.crypto.symmetric;

import cc.hongz.ztools.core.util.StrUtil;
import cc.hongz.ztools.crypto.Mode;
import cc.hongz.ztools.crypto.Padding;
import cc.hongz.ztools.crypto.SecureUtil;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * DES加密解密单元测试
 */
@DisplayName("Des测试")
public class DesTest {

    @Test
    @DisplayName("encrypt Decrypt Test测试")
    public void encryptDecryptTest(){
        String content = "我是一个测试的test字符串123";
        final DES des = SecureUtil.des();

        final String encryptHex = des.encryptHex(content);
        final String result = des.decryptStr(encryptHex);

        assertEquals(content, result);
    }

    @Test
    @DisplayName("encrypt Decrypt With Custom Test测试")
    public void encryptDecryptWithCustomTest(){
        String content = "我是一个测试的test字符串123";
        final DES des = new DES(
                Mode.CTS,
                Padding.PKCS5Padding,
                StrUtil.bytes("12345678"),
                StrUtil.bytes("11223344")
        );

        final String encryptHex = des.encryptHex(content);
        final String result = des.decryptStr(encryptHex);

        assertEquals(content, result);
    }
}
