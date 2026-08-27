package cc.hongz.ztools.crypto.symmetric.fpe;

import cc.hongz.ztools.core.util.RandomUtil;
import org.bouncycastle.crypto.util.BasicAlphabetMapper;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("FPE测试")
public class FPETest {

    @Test
    @DisplayName("ff1Test测试")
    public void ff1Test(){
        // 映射字符表，规定了明文和密文的字符范围
        BasicAlphabetMapper numberMapper = new BasicAlphabetMapper("A0123456789");
        // 初始化 aes 密钥
        byte[] keyBytes = RandomUtil.randomBytes(16);

        final FPE fpe = new FPE(FPE.FPEMode.FF1, keyBytes, numberMapper, null);

        // 原始数据
        String phone = RandomUtil.randomString("A0123456789", 13);
        final String encrypt = fpe.encrypt(phone);
        // 加密后与原密文长度一致
        assertEquals(phone.length(), encrypt.length());

        final String decrypt = fpe.decrypt(encrypt);
        assertEquals(phone, decrypt);
    }

    @Test
    @DisplayName("ff3Test测试")
    public void ff3Test(){
        // 映射字符表，规定了明文和密文的字符范围
        BasicAlphabetMapper numberMapper = new BasicAlphabetMapper("A0123456789");
        // 初始化 aes 密钥
        byte[] keyBytes = RandomUtil.randomBytes(16);

        final FPE fpe = new FPE(FPE.FPEMode.FF3_1, keyBytes, numberMapper, null);

        // 原始数据
        String phone = RandomUtil.randomString("A0123456789", 13);
        final String encrypt = fpe.encrypt(phone);
        // 加密后与原密文长度一致
        assertEquals(phone.length(), encrypt.length());

        final String decrypt = fpe.decrypt(encrypt);
        assertEquals(phone, decrypt);
    }
}
