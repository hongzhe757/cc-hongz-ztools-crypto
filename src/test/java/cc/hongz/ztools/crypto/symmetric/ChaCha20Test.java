package cc.hongz.ztools.crypto.symmetric;

import cc.hongz.ztools.core.util.CharsetUtil;
import cc.hongz.ztools.core.util.RandomUtil;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * 见：https://stackoverflow.com/questions/32672241/using-bouncycastles-chacha-for-file-encryption
 */
@DisplayName("Cha Cha20测试")
public class ChaCha20Test {

    @Test
    @DisplayName("encrypt And Decrypt Test测试")
    public void encryptAndDecryptTest() {
        // 32 for 256 bit key or 16 for 128 bit
        byte[] key = RandomUtil.randomBytes(32);
        // 64 bit IV required by ChaCha20
        byte[] iv = RandomUtil.randomBytes(12);

        final ChaCha20 chacha = new ChaCha20(key, iv);

        String content = "test中文";
        // 加密为16进制表示
        String encryptHex = chacha.encryptHex(content);
        // 解密为字符串
        String decryptStr = chacha.decryptStr(encryptHex, CharsetUtil.CHARSET_UTF_8);

        assertEquals(content, decryptStr);
    }
}
