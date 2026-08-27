package cc.hongz.ztools.crypto;

import cc.hongz.ztools.core.util.StrUtil;

/**
 * 密码学相关运行时异常。
 *
 * @author Looly
 */
public class CryptoException extends RuntimeException {

    private static final long serialVersionUID = 8068509879445395353L;

    /**
     * 构造.
     *
     * @param e 原因
     */
    public CryptoException(final Throwable e) {
        super(e == null ? null : e.getMessage(), e);
    }

    /**
     * 构造.
     *
     * @param message 消息
     */
    public CryptoException(final String message) {
        super(message);
    }

    /**
     * 构造（带模板参数）.
     *
     * @param messageTemplate 消息模板
     * @param params          参数
     */
    public CryptoException(final String messageTemplate, final Object... params) {
        super(StrUtil.format(messageTemplate, params));
    }

    /**
     * 构造.
     *
     * @param message   消息
     * @param throwable 原因
     */
    public CryptoException(final String message, final Throwable throwable) {
        super(message, throwable);
    }
}
