package cc.hongz.ztools.crypto;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * {@link CryptoException} 单元测试.
 *
 * @author hongzhe.qin
 */
class CryptoExceptionTest {

    /**
     * 验证模板消息构造.
     */
    @Test
    void messageTemplate() {
        final CryptoException ex = new CryptoException("Unsupported ASN1 encoding: {}", "FOO");
        assertEquals("Unsupported ASN1 encoding: FOO", ex.getMessage());
    }

    /**
     * 验证 Throwable 构造保留 cause.
     */
    @Test
    void wrapsThrowable() {
        final IllegalStateException cause = new IllegalStateException("inner");
        final CryptoException ex = new CryptoException(cause);
        assertSame(cause, ex.getCause());
    }
}
