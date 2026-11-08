package cc.hongz.ztools.crypto;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.security.KeyPair;
import java.security.cert.X509Certificate;

/**
 * 一次证书生成的内存产物。
 *
 * @author hongz
 * @since 1.0.0
 */
public final class CertBundle {

    private final KeyPair keyPair;
    private final X509Certificate certificate;
    private final PKCS10CertificationRequest csr;
    private final String publicKeyPem;
    private final String privateKeyPem;
    private final String keyPairPem;
    private final String certificatePem;
    private final byte[] certificateDer;
    private final String csrPem;

    CertBundle(final KeyPair keyPair, final X509Certificate certificate, final PKCS10CertificationRequest csr,
               final String publicKeyPem, final String privateKeyPem, final String keyPairPem,
               final String certificatePem, final byte[] certificateDer, final String csrPem) {
        this.keyPair = keyPair;
        this.certificate = certificate;
        this.csr = csr;
        this.publicKeyPem = publicKeyPem;
        this.privateKeyPem = privateKeyPem;
        this.keyPairPem = keyPairPem;
        this.certificatePem = certificatePem;
        this.certificateDer = certificateDer;
        this.csrPem = csrPem;
    }

    /**
     * @return 密钥对
     */
    public KeyPair getKeyPair() {
        return this.keyPair;
    }

    /**
     * @return 自签 X509 证书
     */
    public X509Certificate getCertificate() {
        return this.certificate;
    }

    /**
     * @return PKCS#10 CSR，未请求时可能为 null
     */
    public PKCS10CertificationRequest getCsr() {
        return this.csr;
    }

    /**
     * @return PEM 公钥
     */
    public String getPublicKeyPem() {
        return this.publicKeyPem;
    }

    /**
     * @return PEM 私钥
     */
    public String getPrivateKeyPem() {
        return this.privateKeyPem;
    }

    /**
     * @return PEM 公私钥拼接
     */
    public String getKeyPairPem() {
        return this.keyPairPem;
    }

    /**
     * @return PEM 证书（BEGIN CERTIFICATE）
     */
    public String getCertificatePem() {
        return this.certificatePem;
    }

    /**
     * @return DER 证书字节
     */
    public byte[] getCertificateDer() {
        return this.certificateDer == null ? null : this.certificateDer.clone();
    }

    /**
     * @return PEM CSR
     */
    public String getCsrPem() {
        return this.csrPem;
    }
}
