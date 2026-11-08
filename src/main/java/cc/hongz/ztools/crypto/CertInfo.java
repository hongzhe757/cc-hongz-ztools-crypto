package cc.hongz.ztools.crypto;

import java.math.BigInteger;
import java.util.Date;

/**
 * 证书摘要信息（便于展示 / API 返回）。
 *
 * @author hongz
 * @since 1.0.0
 */
public final class CertInfo {

    private final String subject;
    private final String issuer;
    private final BigInteger serialNumber;
    private final Date notBefore;
    private final Date notAfter;
    private final String sigAlgName;
    private final String publicKeyAlgorithm;
    private final boolean selfSigned;

    CertInfo(final String subject, final String issuer, final BigInteger serialNumber, final Date notBefore,
             final Date notAfter, final String sigAlgName, final String publicKeyAlgorithm, final boolean selfSigned) {
        this.subject = subject;
        this.issuer = issuer;
        this.serialNumber = serialNumber;
        this.notBefore = notBefore;
        this.notAfter = notAfter;
        this.sigAlgName = sigAlgName;
        this.publicKeyAlgorithm = publicKeyAlgorithm;
        this.selfSigned = selfSigned;
    }

    /**
     * @return subject DN
     */
    public String getSubject() {
        return this.subject;
    }

    /**
     * @return issuer DN
     */
    public String getIssuer() {
        return this.issuer;
    }

    /**
     * @return 序列号
     */
    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    /**
     * @return 生效时间
     */
    public Date getNotBefore() {
        return this.notBefore == null ? null : new Date(this.notBefore.getTime());
    }

    /**
     * @return 失效时间
     */
    public Date getNotAfter() {
        return this.notAfter == null ? null : new Date(this.notAfter.getTime());
    }

    /**
     * @return 签名算法名
     */
    public String getSigAlgName() {
        return this.sigAlgName;
    }

    /**
     * @return 公钥算法
     */
    public String getPublicKeyAlgorithm() {
        return this.publicKeyAlgorithm;
    }

    /**
     * @return 是否自签（issuer 与 subject 相同且验签通过）
     */
    public boolean isSelfSigned() {
        return this.selfSigned;
    }
}
