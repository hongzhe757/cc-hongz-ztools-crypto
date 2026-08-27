package cc.hongz.ztools.crypto.digest;

import cc.hongz.ztools.core.io.IoUtil;
import cc.hongz.ztools.core.util.CharsetUtil;
import cc.hongz.ztools.crypto.KeyUtil;
import cc.hongz.ztools.crypto.SecureUtil;
import cc.hongz.ztools.crypto.symmetric.ZUC;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.IvParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Hmac单元测试
 * @author Looly
 *
 */
@DisplayName("Hmac测试")
public class HmacTest {

    @Test
    @DisplayName("hmac Test测试")
    public void hmacTest(){
        String testStr = "test中文";

        byte[] key = "password".getBytes();
        HMac mac = new HMac(HmacAlgorithm.HmacMD5, key);

        String macHex1 = mac.digestHex(testStr);
        assertEquals("b977f4b13f93f549e06140971bded384", macHex1);

        String macHex2 = mac.digestHex(IoUtil.toStream(testStr, CharsetUtil.CHARSET_UTF_8));
        assertEquals("b977f4b13f93f549e06140971bded384", macHex2);
    }

    @Test
    @DisplayName("hmac Md5Test测试")
    public void hmacMd5Test(){
        String testStr = "test中文";

        HMac mac = SecureUtil.hmacMd5("password");

        String macHex1 = mac.digestHex(testStr);
        assertEquals("b977f4b13f93f549e06140971bded384", macHex1);

        String macHex2 = mac.digestHex(IoUtil.toStream(testStr, CharsetUtil.CHARSET_UTF_8));
        assertEquals("b977f4b13f93f549e06140971bded384", macHex2);
    }

    @Test
    @DisplayName("hmac Sha1Test测试")
    public void hmacSha1Test(){
        HMac mac = SecureUtil.hmacSha1("password");

        String testStr = "test中文";
        String macHex1 = mac.digestHex(testStr);
        assertEquals("1dd68d2f119d5640f0d416e99d3f42408b88d511", macHex1);

        String macHex2 = mac.digestHex(IoUtil.toStream(testStr, CharsetUtil.CHARSET_UTF_8));
        assertEquals("1dd68d2f119d5640f0d416e99d3f42408b88d511", macHex2);
    }

    @Test
    @DisplayName("zuc128Mac Test测试")
    public void zuc128MacTest(){
        byte[] iv = new byte[16];
        final byte[] key = new byte[16];
        HMac mac = new HMac("ZUC-128",
                KeyUtil.generateKey(ZUC.ZUCAlgorithm.ZUC_128.getValue(), key),
                new IvParameterSpec(iv));

        String testStr = "test中文";
        String macHex1 = mac.digestHex(testStr);
        assertEquals("1e0b9455", macHex1);
    }

    @Test
    @DisplayName("zuc256Mac Test测试")
    public void zuc256MacTest(){
        final byte[] key = new byte[32];
        byte[] iv = new byte[25];
        HMac mac = new HMac("ZUC-256",
                KeyUtil.generateKey(ZUC.ZUCAlgorithm.ZUC_128.getValue(), key),
                new IvParameterSpec(iv));

        String testStr = "test中文";
        String macHex1 = mac.digestHex(testStr);
        assertEquals("d9ad618357c1bfb1d9d1200a763d5eaa", macHex1);
    }

    @Test
    @DisplayName("sm4CMAC Test测试")
    public void sm4CMACTest(){
        // https://github.com/chinabugotech/hutool/issues/2206
        final byte[] key = new byte[16];
        HMac mac = new HMac(HmacAlgorithm.SM4CMAC,
                KeyUtil.generateKey("SM4", key));

        // 原文
        String testStr = "test中文";

        String macHex1 = mac.digestHex(testStr);
        assertEquals("58a0d231315664af51b858a174eabc21", macHex1);
    }
}
