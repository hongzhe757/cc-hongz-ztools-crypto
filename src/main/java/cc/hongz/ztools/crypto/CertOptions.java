package cc.hongz.ztools.crypto;

import java.security.KeyPair;
import java.util.Collections;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;

/**
 * 证书生成选项。 <br>
 * 底层密钥 / X509 / PKCS12 能力复用 {@link KeyUtil}、{@link PemUtil}，本类只描述业务参数。
 *
 * @author hongz
 * @since 1.0.0
 */
public final class CertOptions {

    /**
     * 可写出的产物格式。
     */
    public enum Format {
        /** PEM 公钥（.pem） */
        PUBLIC_PEM,
        /** PEM 私钥（.pem） */
        PRIVATE_PEM,
        /** PEM 公私钥合一（.pem） */
        KEY_PAIR_PEM,
        /** PEM 证书（.crt） */
        CRT,
        /** DER 证书（.cer） */
        CER,
        /** PKCS#12 密钥库（.pfx） */
        PFX,
        /** PEM 证书签名请求（.csr） */
        CSR
    }

    private String cn = "hongz";
    private String o = "Laser";
    private String ou = "R&D";
    private String l = "BeiJing";
    private String st = "BeiJing";
    private String c = "CN";
    private int keySize = 2048;
    private int validityDays = 365;
    private String password = "12345678";
    private String alias = "hongz";
    private String signatureAlgorithm = KeyUtil.SIGN_ALGORITHM_SHA256_WITH_RSA;
    private String filePrefix = "hongz";
    private KeyPair keyPair;
    private Set<Format> formats = EnumSet.of(Format.PUBLIC_PEM, Format.PRIVATE_PEM, Format.KEY_PAIR_PEM, Format.CRT,
            Format.CER, Format.PFX, Format.CSR);

    /**
     * @return 新建默认选项
     */
    public static CertOptions create() {
        return new CertOptions();
    }

    /**
     * @param cn 通用名
     * @return this
     */
    public CertOptions cn(final String cn) {
        this.cn = cn;
        return this;
    }

    /**
     * @param o 组织
     * @return this
     */
    public CertOptions o(final String o) {
        this.o = o;
        return this;
    }

    /**
     * @param ou 组织单位
     * @return this
     */
    public CertOptions ou(final String ou) {
        this.ou = ou;
        return this;
    }

    /**
     * @param l 城市
     * @return this
     */
    public CertOptions l(final String l) {
        this.l = l;
        return this;
    }

    /**
     * @param st 省/州
     * @return this
     */
    public CertOptions st(final String st) {
        this.st = st;
        return this;
    }

    /**
     * @param c 国家代码
     * @return this
     */
    public CertOptions c(final String c) {
        this.c = c;
        return this;
    }

    /**
     * @param keySize RSA 密钥长度
     * @return this
     */
    public CertOptions keySize(final int keySize) {
        this.keySize = keySize;
        return this;
    }

    /**
     * @param validityDays 有效天数
     * @return this
     */
    public CertOptions validityDays(final int validityDays) {
        this.validityDays = validityDays;
        return this;
    }

    /**
     * @param password PKCS12 密码
     * @return this
     */
    public CertOptions password(final String password) {
        this.password = password;
        return this;
    }

    /**
     * @param alias PKCS12 别名
     * @return this
     */
    public CertOptions alias(final String alias) {
        this.alias = alias;
        return this;
    }

    /**
     * @param signatureAlgorithm 签名算法
     * @return this
     */
    public CertOptions signatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        return this;
    }

    /**
     * @param filePrefix 输出文件名前缀
     * @return this
     */
    public CertOptions filePrefix(final String filePrefix) {
        this.filePrefix = filePrefix;
        return this;
    }

    /**
     * 复用已有密钥对；为空则自动生成。
     *
     * @param keyPair 密钥对
     * @return this
     */
    public CertOptions keyPair(final KeyPair keyPair) {
        this.keyPair = keyPair;
        return this;
    }

    /**
     * @param formats 需要生成的格式集合
     * @return this
     */
    public CertOptions formats(final Format... formats) {
        Objects.requireNonNull(formats, "formats");
        this.formats = EnumSet.noneOf(Format.class);
        Collections.addAll(this.formats, formats);
        return this;
    }

    String getCn() {
        return this.cn;
    }

    String getO() {
        return this.o;
    }

    String getOu() {
        return this.ou;
    }

    String getL() {
        return this.l;
    }

    String getSt() {
        return this.st;
    }

    String getC() {
        return this.c;
    }

    int getKeySize() {
        return this.keySize;
    }

    int getValidityDays() {
        return this.validityDays;
    }

    String getPassword() {
        return this.password;
    }

    String getAlias() {
        return this.alias;
    }

    String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    String getFilePrefix() {
        return this.filePrefix;
    }

    KeyPair getKeyPair() {
        return this.keyPair;
    }

    Set<Format> getFormats() {
        return Collections.unmodifiableSet(this.formats);
    }
}
