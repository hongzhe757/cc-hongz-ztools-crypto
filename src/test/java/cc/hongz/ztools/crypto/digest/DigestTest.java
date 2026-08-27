package cc.hongz.ztools.crypto.digest;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import cc.hongz.ztools.core.io.IoUtil;
import cc.hongz.ztools.core.util.CharsetUtil;

/**
 * 摘要算法单元测试
 * @author Looly
 *
 */
@DisplayName("Digest测试")
public class DigestTest {

    @Test
    @DisplayName("digester Test测试")
    public void digesterTest(){
        String testStr = "test中文";

        Digester md5 = new Digester(DigestAlgorithm.MD5);
        String digestHex = md5.digestHex(testStr);
        assertEquals("5393554e94bf0eb6436f240a4fd71282", digestHex);
    }

    @Test
    @DisplayName("md5Test测试")
    public void md5Test(){
        String testStr = "test中文";

        String md5Hex1 = DigestUtil.md5Hex(testStr);
        assertEquals("5393554e94bf0eb6436f240a4fd71282", md5Hex1);

        String md5Hex2 = DigestUtil.md5Hex(IoUtil.toStream(testStr, CharsetUtil.CHARSET_UTF_8));
        assertEquals("5393554e94bf0eb6436f240a4fd71282", md5Hex2);
    }

    @Test
    @DisplayName("md5With Salt Test测试")
    public void md5WithSaltTest(){
        String testStr = "test中文";

        Digester md5 = new Digester(DigestAlgorithm.MD5);

        //加盐
        md5.setSalt("saltTest".getBytes());
        String md5Hex1 = md5.digestHex(testStr);
        assertEquals("762f7335200299dfa09bebbb601a5bc6", md5Hex1);
        String md5Hex2 = md5.digestHex(IoUtil.toUtf8Stream(testStr));
        assertEquals("762f7335200299dfa09bebbb601a5bc6", md5Hex2);

        //重复2次
        md5.setDigestCount(2);
        String md5Hex3 = md5.digestHex(testStr);
        assertEquals("2b0616296f6755d25efc07f90afe9684", md5Hex3);
        String md5Hex4 = md5.digestHex(IoUtil.toUtf8Stream(testStr));
        assertEquals("2b0616296f6755d25efc07f90afe9684", md5Hex4);
    }

    @Test
    @DisplayName("sha1Test测试")
    public void sha1Test(){
        String testStr = "test中文";

        String sha1Hex1 = DigestUtil.sha1Hex(testStr);
        assertEquals("ecabf586cef0d3b11c56549433ad50b81110a836", sha1Hex1);

        String sha1Hex2 = DigestUtil.sha1Hex(IoUtil.toStream(testStr, CharsetUtil.CHARSET_UTF_8));
        assertEquals("ecabf586cef0d3b11c56549433ad50b81110a836", sha1Hex2);
    }

    @Test
    @DisplayName("hash256Test测试")
    public void hash256Test() {
        String testStr = "Test中文";
        String hex = DigestUtil.sha256Hex(testStr);
        assertEquals(64, hex.length());
    }
}
