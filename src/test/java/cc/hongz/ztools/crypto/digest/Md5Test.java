package cc.hongz.ztools.crypto.digest;

import cc.hongz.ztools.core.io.IoUtil;
import cc.hongz.ztools.core.thread.ConcurrencyTester;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * MD5 单元测试
 *
 * @author Looly
 *
 */
@DisplayName("Md5测试")
public class Md5Test {

    @Test
    @DisplayName("md5To16Test测试")
    public void md5To16Test() {
        String hex16 = new MD5().digestHex16("中国");
        assertEquals(16, hex16.length());
        assertEquals("cb143acd6c929826", hex16);
    }

    @Test
    @DisplayName("md5Thread Safe Test测试")
    public void md5ThreadSafeTest() {
        final String text = "Hutool md5 test str";
        final ConcurrencyTester tester = new ConcurrencyTester(1000);
        tester.test(()->{
            final String digest = new MD5().digestHex(text);
            assertEquals("8060075dd8df47bac3247438e940a728", digest);
        });
        IoUtil.close(tester);
    }

    @Test
    @DisplayName("md5Hex To16Short Input Test测试")
    public void md5HexTo16ShortInputTest() {
        assertThrows(IllegalArgumentException.class, () -> DigestUtil.md5HexTo16("short"));
    }
}
