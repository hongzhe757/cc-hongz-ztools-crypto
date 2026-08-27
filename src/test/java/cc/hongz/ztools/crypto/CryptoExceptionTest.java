package cc.hongz.ztools.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * {@link CryptoException} 单元测试。
 *
 * @author hongzhe.qin
 */
@DisplayName("密码学异常测试")
class CryptoExceptionTest {

    /**
     * 验证模板消息构造。
     */
    @Test
    @DisplayName("模板消息构造测试")
    void messageTemplate() {
        final CryptoException ex = new CryptoException("Unsupported ASN1 encoding: {}", "FOO");
        assertEquals("Unsupported ASN1 encoding: FOO", ex.getMessage());
    }

    /**
     * 验证 Throwable 构造保留 cause。
     */
    @Test
    @DisplayName("保留 cause 测试")
    void wrapsThrowable() {
        final IllegalStateException cause = new IllegalStateException("inner");
        final CryptoException ex = new CryptoException(cause);
        assertSame(cause, ex.getCause());
    }
}
