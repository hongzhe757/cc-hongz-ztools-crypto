package cc.hongz.ztools.crypto;

import cc.hongz.ztools.core.io.FileUtil;
import cc.hongz.ztools.core.util.StrUtil;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 证书业务工具：在 {@link KeyUtil}/{@link PemUtil} 之上提供一站式生成、落盘、解析与自签校验。 <br>
 * 承接原 {@code hongz-cert}（wheels）中的 PEM / CRT / CER / PFX 生成场景，去掉对 Spring / Hutool 配置的耦合。
 *
 * @author hongz
 * @since 1.0.0
 */
public final class CertUtil {

    private static final String PEM_PUBLIC = "PUBLIC KEY";
    private static final String PEM_PRIVATE = "PRIVATE KEY";
    private static final String PEM_CERTIFICATE = "CERTIFICATE";
    private static final String PEM_CSR = "CERTIFICATE REQUEST";

    private CertUtil() {
    }

    /**
     * 按选项生成内存产物（密钥对 + 自签证书 + 可选 CSR / PEM 文本）。
     *
     * @param options 生成选项，不可为 null
     * @return {@link CertBundle}
     */
    public static CertBundle generate(final CertOptions options) {
        Objects.requireNonNull(options, "options");
        final KeyPair keyPair = options.getKeyPair() != null ? options.getKeyPair()
                : KeyUtil.generateKeyPair("RSA", options.getKeySize());
        final X500Name subject = KeyUtil.generateX500Name(options.getCn(), options.getO(), options.getOu(),
                options.getL(), options.getSt(), options.getC());
        final Date notBefore = new Date();
        final Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(Math.max(1, options.getValidityDays())));
        final X509Certificate certificate = KeyUtil.generateX509Certificate(subject, subject,
                KeyUtil.generateRandomSerialNumber(), notBefore, notAfter, keyPair.getPrivate(), keyPair.getPublic(),
                options.getSignatureAlgorithm());

        final String publicKeyPem = PemUtil.toPem(PEM_PUBLIC, keyPair.getPublic().getEncoded());
        final String privateKeyPem = PemUtil.toPem(PEM_PRIVATE, keyPair.getPrivate().getEncoded());
        final String keyPairPem = publicKeyPem + privateKeyPem;
        final String certificatePem;
        final byte[] certificateDer;
        try {
            certificateDer = certificate.getEncoded();
            certificatePem = PemUtil.toPem(PEM_CERTIFICATE, certificateDer);
        } catch (CertificateEncodingException e) {
            throw new CryptoException(e);
        }

        PKCS10CertificationRequest csr = null;
        String csrPem = null;
        if (options.getFormats().contains(CertOptions.Format.CSR)) {
            csr = KeyUtil.generateCsr(subject, keyPair.getPublic(), keyPair.getPrivate(), options.getSignatureAlgorithm());
            try {
                csrPem = PemUtil.toPem(PEM_CSR, csr.getEncoded());
            } catch (IOException e) {
                throw new CryptoException(e);
            }
        }

        return new CertBundle(keyPair, certificate, csr, publicKeyPem, privateKeyPem, keyPairPem, certificatePem,
                certificateDer, csrPem);
    }

    /**
     * 生成并按格式写出到目录，返回格式 → 文件映射。 <br>
     * 目录不存在时自动创建。
     *
     * @param options 生成选项
     * @param outDir  输出目录
     * @return 已写出的文件
     */
    public static Map<CertOptions.Format, File> write(final CertOptions options, final File outDir) {
        Objects.requireNonNull(outDir, "outDir");
        FileUtil.mkdir(outDir);
        final CertBundle bundle = generate(options);
        final String prefix = StrUtil.isBlank(options.getFilePrefix()) ? "hongz" : options.getFilePrefix();
        final Map<CertOptions.Format, File> files = new EnumMap<>(CertOptions.Format.class);

        for (final CertOptions.Format format : options.getFormats()) {
            switch (format) {
                case PUBLIC_PEM -> {
                    final File file = new File(outDir, prefix + "PublicKey.pem");
                    FileUtil.writeString(bundle.getPublicKeyPem(), file, StandardCharsets.UTF_8);
                    files.put(format, file);
                }
                case PRIVATE_PEM -> {
                    final File file = new File(outDir, prefix + "PrivateKey.pem");
                    FileUtil.writeString(bundle.getPrivateKeyPem(), file, StandardCharsets.UTF_8);
                    files.put(format, file);
                }
                case KEY_PAIR_PEM -> {
                    final File file = new File(outDir, prefix + "PairKey.pem");
                    FileUtil.writeString(bundle.getKeyPairPem(), file, StandardCharsets.UTF_8);
                    files.put(format, file);
                }
                case CRT -> {
                    final File file = new File(outDir, prefix + "Crt.crt");
                    FileUtil.writeString(bundle.getCertificatePem(), file, StandardCharsets.UTF_8);
                    files.put(format, file);
                }
                case CER -> {
                    final File file = new File(outDir, prefix + "Cer.cer");
                    FileUtil.writeBytes(bundle.getCertificateDer(), file);
                    files.put(format, file);
                }
                case PFX -> {
                    final File file = new File(outDir, prefix + "Pfx.pfx");
                    KeyUtil.writePKCS12KeyStore(file, bundle.getCertificate(), bundle.getKeyPair().getPrivate(),
                            options.getAlias(), options.getPassword().toCharArray());
                    files.put(format, file);
                }
                case CSR -> {
                    final File file = new File(outDir, prefix + "Csr.csr");
                    FileUtil.writeString(bundle.getCsrPem(), file, StandardCharsets.UTF_8);
                    files.put(format, file);
                }
                default -> throw new CryptoException("unsupported format: " + format);
            }
        }
        return Collections.unmodifiableMap(files);
    }

    /**
     * 从文件读取 X509 证书（支持 PEM .crt / DER .cer，以及 PKCS12 时请用 {@link KeyUtil#readPKCS12KeyStore}）。
     *
     * @param certFile 证书文件
     * @return {@link X509Certificate}
     */
    public static X509Certificate readCertificate(final File certFile) {
        Objects.requireNonNull(certFile, "certFile");
        final byte[] bytes = FileUtil.readBytes(certFile);
        try {
            return (X509Certificate) KeyUtil.getCertificateFactory(KeyUtil.CERT_TYPE_X509)
                    .generateCertificate(new ByteArrayInputStream(bytes));
        } catch (CertificateException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 解析证书摘要信息，并尝试判断是否自签。
     *
     * @param certificate 证书
     * @return {@link CertInfo}
     */
    public static CertInfo inspect(final X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        boolean selfSigned = false;
        if (certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
            try {
                certificate.verify(certificate.getPublicKey());
                selfSigned = true;
            } catch (Exception ignored) {
                selfSigned = false;
            }
        }
        final PublicKey publicKey = certificate.getPublicKey();
        return new CertInfo(certificate.getSubjectX500Principal().getName(),
                certificate.getIssuerX500Principal().getName(), certificate.getSerialNumber(),
                certificate.getNotBefore(), certificate.getNotAfter(), certificate.getSigAlgName(),
                publicKey == null ? null : publicKey.getAlgorithm(), selfSigned);
    }

    /**
     * 读取文件并解析摘要。
     *
     * @param certFile 证书文件
     * @return {@link CertInfo}
     */
    public static CertInfo inspect(final File certFile) {
        return inspect(readCertificate(certFile));
    }

    /**
     * 校验当前时间在有效期内，且证书为自签（issuer=subject 且验签通过）。
     *
     * @param certificate 证书
     */
    public static void verifySelfSigned(final X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        try {
            certificate.checkValidity();
            if (false == certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())) {
                throw new CryptoException("certificate is not self-signed: subject != issuer");
            }
            certificate.verify(certificate.getPublicKey());
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
