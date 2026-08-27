package cc.hongz.ztools.crypto.symmetric;

import cc.hongz.ztools.core.util.RandomUtil;
import cc.hongz.ztools.crypto.KeyUtil;

import javax.crypto.spec.IvParameterSpec;

/**
 * ChaCha20算法实现。 <br>
 * ChaCha系列流密码，作为salsa密码的改良版，具有更强的抵抗密码分析攻击的特性，“20”表示该算法有20轮的加密计算。
 *
 * @author looly
 * @since 5.7.12
 */
@SuppressWarnings("checkstyle:MagicNumber")
public class ChaCha20 extends SymmetricCrypto {
    private static final long serialVersionUID = 1L;

    /** ALGORITHM_NAME。 */
    public static final String ALGORITHM_NAME = "ChaCha20";

    /**
     * 构造。
     *
     * @param key 密钥
     * @param iv  加盐，12bytes（64bit）
     */
    public ChaCha20(final byte[] key, final byte[] iv) {
        super(ALGORITHM_NAME,
                KeyUtil.generateKey(ALGORITHM_NAME, key),
                generateIvParam(iv));
    }

    /**
     * 生成加盐参数。
     *
     * @param iv 加盐
     * @return {@link IvParameterSpec}
     */
    private static IvParameterSpec generateIvParam(final byte[] iv) {
        byte[] resolvedIv = iv;
        if (null == resolvedIv) {
            resolvedIv = RandomUtil.randomBytes(12);
        }
        return new IvParameterSpec(resolvedIv);
    }
}
