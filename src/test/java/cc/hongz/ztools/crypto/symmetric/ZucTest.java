package cc.hongz.ztools.crypto.symmetric;

import cc.hongz.ztools.core.util.CharsetUtil;
import cc.hongz.ztools.core.util.RandomUtil;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Zuc测试")
public class ZucTest {

    @Test
    @DisplayName("zuc128Test测试")
    public void zuc128Test(){
        final byte[] secretKey = ZUC.generateKey(ZUC.ZUCAlgorithm.ZUC_128);
        byte[] iv = RandomUtil.randomBytes(16);
        final ZUC zuc = new ZUC(ZUC.ZUCAlgorithm.ZUC_128, secretKey, iv);

        String msg = RandomUtil.randomString(500);
        byte[] crypt2 = zuc.encrypt(msg);
        String msg2 = zuc.decryptStr(crypt2, CharsetUtil.CHARSET_UTF_8);
        assertEquals(msg, msg2);
    }

    @Test
    @DisplayName("zuc256Test测试")
    public void zuc256Test(){
        final byte[] secretKey = ZUC.generateKey(ZUC.ZUCAlgorithm.ZUC_256);
        byte[] iv = RandomUtil.randomBytes(25);
        final ZUC zuc = new ZUC(ZUC.ZUCAlgorithm.ZUC_256, secretKey, iv);

        String msg = RandomUtil.randomString(500);
        byte[] crypt2 = zuc.encrypt(msg);
        String msg2 = zuc.decryptStr(crypt2, CharsetUtil.CHARSET_UTF_8);
        assertEquals(msg, msg2);
    }
}
