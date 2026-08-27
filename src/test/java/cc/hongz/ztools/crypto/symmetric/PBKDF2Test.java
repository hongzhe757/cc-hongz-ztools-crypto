package cc.hongz.ztools.crypto.symmetric;

import cc.hongz.ztools.core.util.RandomUtil;
import cc.hongz.ztools.crypto.SecureUtil;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PBKDF2测试")
public class PBKDF2Test {

    @Test
    @DisplayName("encrypt Test测试")
    public void encryptTest(){
        final String s = SecureUtil.pbkdf2("123456".toCharArray(), RandomUtil.randomBytes(16));
        assertEquals(128, s.length());
    }
}
