package cc.hongz.ztools.crypto;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link ASN1Util} 单元测试.
 *
 * @author hongzhe.qin
 */
class ASN1UtilTest {

    /**
     * 验证 {@link ASN1Util#encodeDer(ASN1Encodable[])} 与 {@link ASN1Util#decode(java.io.InputStream)} 往返.
     */
    @Test
    void encodeDerAndDecodeRoundTrip() throws Exception {
        final byte[] der = ASN1Util.encodeDer(new ASN1Integer(42L));
        assertNotNull(der);
        assertTrue(der.length > 0);

        final ASN1Object decoded = ASN1Util.decode(new ByteArrayInputStream(der));
        assertInstanceOf(ASN1Sequence.class, decoded);
        final ASN1Sequence seq = (ASN1Sequence) decoded;
        assertEquals(1, seq.size());
        assertEquals(42L, ((ASN1Integer) seq.getObjectAt(0)).getValue().longValue());
    }

    /**
     * 验证 DER 序列多元素编码.
     */
    @Test
    void encodeDerMultipleElements() throws Exception {
        final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier("1.2.840.113549.1.1.1");
        final byte[] der = ASN1Util.encodeDer(oid, new DEROctetString(new byte[]{1, 2, 3}));
        final ASN1Sequence seq = (ASN1Sequence) ASN1Util.decode(new ByteArrayInputStream(der));
        assertEquals(2, seq.size());
        assertEquals(oid, seq.getObjectAt(0));
    }

    /**
     * 验证 BER、DL 编码可写出非空字节.
     */
    @Test
    void encodeBerAndDl() {
        final ASN1Integer value = new ASN1Integer(1L);
        assertTrue(ASN1Util.encode(ASN1Encoding.BER, value).length > 0);
        assertTrue(ASN1Util.encode(ASN1Encoding.DL, value).length > 0);
    }

    /**
     * 验证 {@link ASN1Util#encodeTo(String, java.io.OutputStream, ASN1Encodable[])} 写入流.
     */
    @Test
    void encodeToOutputStream() throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        ASN1Util.encodeTo(ASN1Encoding.DER, out, new ASN1Integer(7L));
        final ASN1Object decoded = ASN1Util.decode(new ByteArrayInputStream(out.toByteArray()));
        assertInstanceOf(ASN1Sequence.class, decoded);
    }

    /**
     * 验证 {@link ASN1Util#getDumpStr(java.io.InputStream)} 返回非空调试字符串.
     */
    @Test
    void getDumpStrNonEmpty() {
        final byte[] der = ASN1Util.encodeDer(new ASN1Integer(99L));
        final String dump = ASN1Util.getDumpStr(new ByteArrayInputStream(der));
        assertNotNull(dump);
        assertFalse(dump.isBlank());
    }

    /**
     * 验证不支持的编码格式抛出 {@link CryptoException}.
     */
    @Test
    void unsupportedEncodingThrows() {
        assertThrows(CryptoException.class,
                () -> ASN1Util.encode("UNKNOWN", new ASN1Integer(0L)));
    }
}
