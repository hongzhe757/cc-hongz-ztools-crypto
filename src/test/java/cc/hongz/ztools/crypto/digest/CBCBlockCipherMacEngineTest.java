package cc.hongz.ztools.crypto.digest;

import cc.hongz.ztools.crypto.KeyUtil;
import cc.hongz.ztools.crypto.digest.mac.Mac;
import cc.hongz.ztools.crypto.digest.mac.SM4MacEngine;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("CBC Block Cipher Mac Engine测试")
public class CBCBlockCipherMacEngineTest {

    @Test
    @DisplayName("SM4CMAC Test测试")
    public void SM4CMACTest(){
        // https://github.com/chinabugotech/hutool/issues/2206
        final byte[] key = new byte[16];
        final CipherParameters parameter = new KeyParameter(KeyUtil.generateKey("SM4", key).getEncoded());
        Mac mac = new Mac(new SM4MacEngine(parameter));

        // 原文
        String testStr = "test中文";

        String macHex1 = mac.digestHex(testStr);
        assertEquals("3212e848db7f816a4bd591ad9948debf", macHex1);
    }

    @Test
    @DisplayName("SM4CMAC With IV Test测试")
    public void SM4CMACWithIVTest(){
        // https://github.com/chinabugotech/hutool/issues/2206
        final byte[] key = new byte[16];
        final byte[] iv = new byte[16];
        CipherParameters parameter = new KeyParameter(KeyUtil.generateKey("SM4", key).getEncoded());
        parameter = new ParametersWithIV(parameter, iv);
        Mac mac = new Mac(new SM4MacEngine(parameter));

        // 原文
        String testStr = "test中文";

        String macHex1 = mac.digestHex(testStr);
        assertEquals("3212e848db7f816a4bd591ad9948debf", macHex1);
    }
}
