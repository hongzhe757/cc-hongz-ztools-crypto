package cc.hongz.ztools.crypto;

import cc.hongz.ztools.core.codec.Base64;
import cc.hongz.ztools.core.io.FileUtil;
import cc.hongz.ztools.core.io.IoUtil;
import cc.hongz.ztools.core.lang.Assert;
import cc.hongz.ztools.core.util.ArrayUtil;
import cc.hongz.ztools.core.util.CharUtil;
import cc.hongz.ztools.core.util.RandomUtil;
import cc.hongz.ztools.core.util.StrUtil;
import cc.hongz.ztools.crypto.asymmetric.AsymmetricAlgorithm;
import cc.hongz.ztools.crypto.symmetric.SymmetricAlgorithm;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.Key;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * 密钥工具类。
 *
 * <p>
 * 包括:
 * <pre>
 * 1、生成密钥（单密钥、密钥对）
 * 2、读取密钥文件
 * </pre>
 *
 * @author looly, Gsealy
 * @since 4.4.1
 */
@SuppressWarnings("checkstyle:MagicNumber")
public final class KeyUtil {

    /**
     * 私有构造，禁止实例化。
     */
    private KeyUtil() {
    }

    /**
     * Java密钥库(Java Key Store，JKS)KEY_STORE。
     */
    public static final String KEY_TYPE_JKS = "JKS";
    /**
     * jceks。
     */
    public static final String KEY_TYPE_JCEKS = "jceks";
    /**
     * PKCS12是公钥加密标准，它规定了可包含所有私钥、公钥和证书。其以二进制格式存储，也称为 PFX 文件。
     */
    public static final String KEY_TYPE_PKCS12 = "pkcs12";
    /**
     * Certification类型：X.509。
     */
    public static final String CERT_TYPE_X509 = "X.509";
    /**
     * 默认签名算法：SHA256withRSA。
     */
    public static final String SIGN_ALGORITHM_SHA256_WITH_RSA = "SHA256withRSA";
    /**
     * 生成随机证书序列号时使用的位数。
     */
    private static final int SERIAL_NUMBER_BITS = 128;

    /**
     * 默认密钥字节数
     *
     * <pre>
     * RSA/DSA
     * Default Keysize 1024
     * Keysize must be a multiple of 64, ranging from 512 to 1024 (inclusive).
     * </pre>
     */
    public static final int DEFAULT_KEY_SIZE = 1024;

    /**
     * SM2默认曲线。
     *
     * <pre>
     * Default SM2 curve
     * </pre>
     */
    public static final String SM2_DEFAULT_CURVE = SmUtil.SM2_CURVE_NAME;

    /**
     * 生成 {@link SecretKey}，仅用于对称加密和摘要算法密钥生成。
     *
     * @param algorithm 算法，支持PBE算法
     * @return {@link SecretKey}
     */
    public static SecretKey generateKey(final String algorithm) {
        return generateKey(algorithm, -1);
    }

    /**
     * 生成 {@link SecretKey}，仅用于对称加密和摘要算法密钥生成<br>
     * 当指定keySize&lt;0时，AES默认长度为128，其它算法不指定。
     *
     * @param algorithm 算法，支持PBE算法
     * @param keySize   密钥长度，&lt;0表示不设定密钥长度，即使用默认长度
     * @return {@link SecretKey}
     * @since 3.1.2
     */
    public static SecretKey generateKey(final String algorithm, final int keySize) {
        return generateKey(algorithm, keySize, null);
    }

    /**
     * 生成 {@link SecretKey}，仅用于对称加密和摘要算法密钥生成<br>
     * 当指定keySize&lt;0时，AES默认长度为128，其它算法不指定。
     *
     * @param algorithm 算法，支持PBE算法
     * @param keySize   密钥长度，&lt;0表示不设定密钥长度，即使用默认长度
     * @param random    随机数生成器，null表示默认
     * @return {@link SecretKey}
     * @since 5.5.2
     */
    public static SecretKey generateKey(final String algorithm, final int keySize, final SecureRandom random) {
        String resolvedAlgorithm = getMainAlgorithm(algorithm);

        final KeyGenerator keyGenerator = getKeyGenerator(resolvedAlgorithm);
        int resolvedKeySize = keySize;
        if (resolvedKeySize <= 0 && SymmetricAlgorithm.AES.getValue().equals(resolvedAlgorithm)) {
            // 对于AES的密钥，除非指定，否则强制使用128位
            resolvedKeySize = 128;
        }

        if (resolvedKeySize > 0) {
            if (null == random) {
                keyGenerator.init(resolvedKeySize);
            } else {
                keyGenerator.init(resolvedKeySize, random);
            }
        }
        return keyGenerator.generateKey();
    }

    /**
     * 生成 {@link SecretKey}，仅用于对称加密和摘要算法密钥生成。
     *
     * @param algorithm 算法
     * @param key       密钥，如果为{@code null} 自动生成随机密钥
     * @return {@link SecretKey}
     */
    public static SecretKey generateKey(final String algorithm, final byte[] key) {
        Assert.notBlank(algorithm, "Algorithm is blank!");
        SecretKey secretKey;
        if (algorithm.startsWith("PBE")) {
            // PBE密钥
            secretKey = generatePBEKey(algorithm, (null == key) ? null : StrUtil.utf8Str(key).toCharArray());
        } else if (algorithm.startsWith("DES")) {
            // DES密钥
            secretKey = generateDESKey(algorithm, key);
        } else {
            // 其它算法密钥
            secretKey = (null == key) ? generateKey(algorithm) : new SecretKeySpec(key, algorithm);
        }
        return secretKey;
    }

    /**
     * 生成 {@link SecretKey}。
     *
     * @param algorithm DES算法，包括DES、DESede等
     * @param key       密钥
     * @return {@link SecretKey}
     */
    public static SecretKey generateDESKey(final String algorithm, final byte[] key) {
        if (StrUtil.isBlank(algorithm) || false == algorithm.startsWith("DES")) {
            throw new CryptoException("Algorithm [{}] is not a DES algorithm!", algorithm);
        }

        SecretKey secretKey;
        if (null == key) {
            secretKey = generateKey(algorithm);
        } else {
            KeySpec keySpec;
            try {
                if (algorithm.startsWith("DESede")) {
                    // DESede兼容
                    keySpec = new DESedeKeySpec(key);
                } else {
                    keySpec = new DESKeySpec(key);
                }
            } catch (InvalidKeyException e) {
                throw new CryptoException(e);
            }
            secretKey = generateKey(algorithm, keySpec);
        }
        return secretKey;
    }

    /**
     * 生成PBE {@link SecretKey}。
     *
     * @param algorithm PBE算法，包括：PBEWithMD5AndDES、PBEWithSHA1AndDESede、PBEWithSHA1AndRC2_40等
     * @param key       密钥
     * @return {@link SecretKey}
     */
    public static SecretKey generatePBEKey(final String algorithm, final char[] key) {
        if (StrUtil.isBlank(algorithm) || false == algorithm.startsWith("PBE")) {
            throw new CryptoException("Algorithm [{}] is not a PBE algorithm!", algorithm);
        }

        char[] resolvedKey = key;
        if (null == resolvedKey) {
            resolvedKey = RandomUtil.randomString(32).toCharArray();
        }
        PBEKeySpec keySpec = new PBEKeySpec(resolvedKey);
        return generateKey(algorithm, keySpec);
    }

    /**
     * 生成 {@link SecretKey}，仅用于对称加密和摘要算法。
     *
     * @param algorithm 算法
     * @param keySpec   {@link KeySpec}
     * @return {@link SecretKey}
     */
    public static SecretKey generateKey(final String algorithm, final KeySpec keySpec) {
        final SecretKeyFactory keyFactory = getSecretKeyFactory(algorithm);
        try {
            return keyFactory.generateSecret(keySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 生成RSA私钥，仅用于非对称加密。
     * 算法见：<a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory">...</a>
     *
     * @param key 密钥，支持XML和Base64两种格式，XML为C#生成格式，见{@link SpecUtil#xmlToRSAPrivateCrtKeySpec(String)}
     * @return RSA私钥 {@link PrivateKey}
     * @since 7.0.0
     */
    public static PrivateKey generateRSAPrivateKey(final String key) {
        Assert.notBlank(key, "Key is blank!");
        String resolvedKey = StrUtil.trim(key);
        if (StrUtil.startWith(resolvedKey, '<')) {
            return generateRSAPrivateKey(SpecUtil.xmlToRSAPrivateCrtKeySpec(resolvedKey));
        }

        return generatePrivateKey(AsymmetricAlgorithm.RSA.getValue(), Base64.decode(resolvedKey));
    }

    /**
     * 生成RSA私钥，仅用于非对称加密。 <br>
     * 采用PKCS#8规范，此规范定义了私钥信息语法和加密私钥语法<br>
     * 算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
     *
     * @param key 密钥，必须为DER编码存储
     * @return RSA私钥 {@link PrivateKey}
     * @since 4.5.2
     */
    public static PrivateKey generateRSAPrivateKey(final byte[] key) {
        return generatePrivateKey(AsymmetricAlgorithm.RSA.getValue(), key);
    }

    /**
     * 生成RSA私钥，仅用于非对称加密。 <br>
     * 算法见：<a href="https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory">...</a>
     *
     * @param keySpec {@link KeySpec}
     * @return RSA私钥 {@link PrivateKey}
     * @since 5.8.41
     */
    public static PrivateKey generateRSAPrivateKey(final KeySpec keySpec) {
        return generatePrivateKey(AsymmetricAlgorithm.RSA.getValue(), keySpec);
    }

    /**
     * 生成私钥，仅用于非对称加密。 <br>
     * 采用PKCS#8规范，此规范定义了私钥信息语法和加密私钥语法<br>
     * 算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
     *
     * @param algorithm 算法，如RSA、EC、SM2等
     * @param key       密钥，PKCS#8格式
     * @return 私钥 {@link PrivateKey}
     */
    public static PrivateKey generatePrivateKey(final String algorithm, final byte[] key) {
        if (null == key) {
            return null;
        }
        return generatePrivateKey(algorithm, new PKCS8EncodedKeySpec(key));
    }

    /**
     * 生成私钥，仅用于非对称加密。 <br>
     * 算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
     *
     * @param algorithm 算法，如RSA、EC、SM2等
     * @param keySpec   {@link KeySpec}
     * @return 私钥 {@link PrivateKey}
     * @since 3.1.1
     */
    public static PrivateKey generatePrivateKey(final String algorithm, final KeySpec keySpec) {
        if (null == keySpec) {
            return null;
        }
        String resolvedAlgorithm = getAlgorithmAfterWith(algorithm);
        try {
            return getKeyFactory(resolvedAlgorithm).generatePrivate(keySpec);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 生成私钥，仅用于非对称加密。
     *
     * @param keyStore {@link KeyStore}
     * @param alias    别名
     * @param password 密码
     * @return 私钥 {@link PrivateKey}
     */
    public static PrivateKey generatePrivateKey(final KeyStore keyStore, final String alias, final char[] password) {
        try {
            return (PrivateKey) keyStore.getKey(alias, password);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 生成RSA公钥，仅用于非对称加密。 <br>
     * 采用X509证书规范<br>
     * 算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
     *
     * @param key 密钥，必须为DER编码存储
     * @return 公钥 {@link PublicKey}
     * @since 4.5.2
     */
    public static PublicKey generateRSAPublicKey(final byte[] key) {
        return generatePublicKey(AsymmetricAlgorithm.RSA.getValue(), key);
    }

    /**
     * 生成公钥，仅用于非对称加密。 <br>
     * 采用X509证书规范<br>
     * 算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
     *
     * @param algorithm 算法
     * @param key       密钥，必须为DER编码存储
     * @return 公钥 {@link PublicKey}
     */
    public static PublicKey generatePublicKey(final String algorithm, final byte[] key) {
        if (null == key) {
            return null;
        }
        return generatePublicKey(algorithm, new X509EncodedKeySpec(key));
    }

    /**
     * 生成公钥，仅用于非对称加密。 <br>
     * 算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory
     *
     * @param algorithm 算法
     * @param keySpec   {@link KeySpec}
     * @return 公钥 {@link PublicKey}
     * @since 3.1.1
     */
    public static PublicKey generatePublicKey(final String algorithm, final KeySpec keySpec) {
        if (null == keySpec) {
            return null;
        }
        String resolvedAlgorithm = getAlgorithmAfterWith(algorithm);
        try {
            return getKeyFactory(resolvedAlgorithm).generatePublic(keySpec);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 生成用于非对称加密的公钥和私钥，仅用于非对称加密。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyPair}
     */
    public static KeyPair generateKeyPair(final String algorithm) {
        int keySize = DEFAULT_KEY_SIZE;
        if ("ECIES".equalsIgnoreCase(algorithm)) {
            // ECIES算法对KEY的长度有要求，此处默认256
            keySize = 256;
        }

        return generateKeyPair(algorithm, keySize);
    }

    /**
     * 生成用于非对称加密的公钥和私钥。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @param algorithm 非对称加密算法
     * @param keySize   密钥模（modulus ）长度
     * @return {@link KeyPair}
     */
    public static KeyPair generateKeyPair(final String algorithm, final int keySize) {
        return generateKeyPair(algorithm, keySize, null);
    }

    /**
     * 生成用于非对称加密的公钥和私钥。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @param algorithm 非对称加密算法
     * @param keySize   密钥模（modulus ）长度
     * @param seed      种子
     * @return {@link KeyPair}
     */
    public static KeyPair generateKeyPair(final String algorithm, final int keySize, final byte[] seed) {
        // SM2算法需要单独定义其曲线生成
        if ("SM2".equalsIgnoreCase(algorithm)) {
            final ECGenParameterSpec sm2p256v1 = new ECGenParameterSpec(SM2_DEFAULT_CURVE);
            return generateKeyPair(algorithm, keySize, seed, sm2p256v1);
        }

        return generateKeyPair(algorithm, keySize, seed, (AlgorithmParameterSpec[]) null);
    }

    /**
     * 生成用于非对称加密的公钥和私钥。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @param algorithm 非对称加密算法
     * @param params    {@link AlgorithmParameterSpec}
     * @return {@link KeyPair}
     * @since 4.3.3
     */
    public static KeyPair generateKeyPair(final String algorithm, final AlgorithmParameterSpec params) {
        return generateKeyPair(algorithm, null, params);
    }

    /**
     * 生成用于非对称加密的公钥和私钥。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * @param algorithm 非对称加密算法
     * @param param     {@link AlgorithmParameterSpec}
     * @param seed      种子
     * @return {@link KeyPair}
     * @since 4.3.3
     */
    public static KeyPair generateKeyPair(
                final String algorithm,
                final byte[] seed,
                final AlgorithmParameterSpec param
        ) {
        return generateKeyPair(algorithm, DEFAULT_KEY_SIZE, seed, param);
    }

    /**
     * 生成用于非对称加密的公钥和私钥。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * <p>
     * 对于非对称加密算法，密钥长度有严格限制，具体如下：
     *
     * <p>
     * <b>RSA：</b>
     * <pre>
     * RS256、PS256：2048 bits
     * RS384、PS384：3072 bits
     * RS512、RS512：4096 bits
     * </pre>
     *
     * <p>
     * <b>EC（Elliptic Curve）：</b>
     * <pre>
     * EC256：256 bits
     * EC384：384 bits
     * EC512：512 bits
     * </pre>
     *
     * @param algorithm 非对称加密算法
     * @param keySize   密钥模（modulus ）长度（单位bit）
     * @param seed      种子
     * @param params    {@link AlgorithmParameterSpec}
     * @return {@link KeyPair}
     * @since 4.3.3
     */
    public static KeyPair generateKeyPair(
                final String algorithm,
                final int keySize,
                final byte[] seed,
                final AlgorithmParameterSpec... params
        ) {
        return generateKeyPair(algorithm, keySize, RandomUtil.createSecureRandom(seed), params);
    }

    /**
     * 生成用于非对称加密的公钥和私钥。 <br>
     * 密钥对生成算法见：https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator
     *
     * <p>
     * 对于非对称加密算法，密钥长度有严格限制，具体如下：
     *
     * <p>
     * <b>RSA：</b>
     * <pre>
     * RS256、PS256：2048 bits
     * RS384、PS384：3072 bits
     * RS512、RS512：4096 bits
     * </pre>
     *
     * <p>
     * <b>EC（Elliptic Curve）：</b>
     * <pre>
     * EC256：256 bits
     * EC384：384 bits
     * EC512：512 bits
     * </pre>
     *
     * @param algorithm 非对称加密算法
     * @param keySize   密钥模（modulus ）长度（单位bit）
     * @param random    {@link SecureRandom} 对象，创建时可选传入seed
     * @param params    {@link AlgorithmParameterSpec}
     * @return {@link KeyPair}
     * @since 4.6.5
     */
    public static KeyPair generateKeyPair(
                final String algorithm,
                final int keySize,
                final SecureRandom random,
                final AlgorithmParameterSpec... params
        ) {
        String resolvedAlgorithm = getAlgorithmAfterWith(algorithm);
        final KeyPairGenerator keyPairGen = getKeyPairGenerator(resolvedAlgorithm);

        // 密钥模（modulus ）长度初始化定义
        int resolvedKeySize = keySize;
        if (resolvedKeySize > 0) {
            // key长度适配修正
            if ("EC".equalsIgnoreCase(resolvedAlgorithm) && resolvedKeySize > 256) {
                // 对于EC（EllipticCurve）算法，密钥长度有限制，在此使用默认256
                resolvedKeySize = 256;
            }
            if (null != random) {
                keyPairGen.initialize(resolvedKeySize, random);
            } else {
                keyPairGen.initialize(resolvedKeySize);
            }
        }

        // 自定义初始化参数
        if (ArrayUtil.isNotEmpty(params)) {
            for (AlgorithmParameterSpec param : params) {
                if (null == param) {
                    continue;
                }
                try {
                    if (null != random) {
                        keyPairGen.initialize(param, random);
                    } else {
                        keyPairGen.initialize(param);
                    }
                } catch (InvalidAlgorithmParameterException e) {
                    throw new CryptoException(e);
                }
            }
        }
        return keyPairGen.generateKeyPair();
    }

    /**
     * 获取{@link KeyPairGenerator}。
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyPairGenerator}
     * @since 4.4.3
     */
    public static KeyPairGenerator getKeyPairGenerator(final String algorithm) {
        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();

        KeyPairGenerator keyPairGen;
        try {
            keyPairGen = (null == provider) //
                    ? KeyPairGenerator.getInstance(getMainAlgorithm(algorithm)) //
                    : KeyPairGenerator.getInstance(getMainAlgorithm(algorithm), provider); //
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
        return keyPairGen;
    }

    /**
     * 获取{@link KeyFactory}。
     *
     * @param algorithm 非对称加密算法
     * @return {@link KeyFactory}
     * @since 4.4.4
     */
    public static KeyFactory getKeyFactory(final String algorithm) {
        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();

        KeyFactory keyFactory;
        try {
            keyFactory = (null == provider) //
                    ? KeyFactory.getInstance(getMainAlgorithm(algorithm)) //
                    : KeyFactory.getInstance(getMainAlgorithm(algorithm), provider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
        return keyFactory;
    }

    /**
     * 获取{@link SecretKeyFactory}。
     *
     * @param algorithm 对称加密算法
     * @return {@link KeyFactory}
     * @since 4.5.2
     */
    public static SecretKeyFactory getSecretKeyFactory(final String algorithm) {
        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();

        SecretKeyFactory keyFactory;
        try {
            keyFactory = (null == provider) //
                    ? SecretKeyFactory.getInstance(getMainAlgorithm(algorithm)) //
                    : SecretKeyFactory.getInstance(getMainAlgorithm(algorithm), provider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
        return keyFactory;
    }

    /**
     * 获取{@link KeyGenerator}。
     *
     * @param algorithm 对称加密算法
     * @return {@link KeyGenerator}
     * @since 4.5.2
     */
    public static KeyGenerator getKeyGenerator(final String algorithm) {
        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();

        KeyGenerator generator;
        try {
            generator = (null == provider) //
                    ? KeyGenerator.getInstance(getMainAlgorithm(algorithm)) //
                    : KeyGenerator.getInstance(getMainAlgorithm(algorithm), provider);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
        return generator;
    }

    /**
     * 获取主体算法名，例如RSA/ECB/PKCS1Padding的主体算法是RSA。
     *
     * @param algorithm XXXwithXXX算法
     * @return 主体算法名
     * @since 4.5.2
     */
    public static String getMainAlgorithm(final String algorithm) {
        Assert.notBlank(algorithm, "Algorithm must be not blank!");
        final int slashIndex = algorithm.indexOf(CharUtil.SLASH);
        if (slashIndex > 0) {
            return algorithm.substring(0, slashIndex);
        }
        return algorithm;
    }

    /**
     * 获取用于密钥生成的算法。 <br>
     * 获取XXXwithXXX算法的后半部分算法，如果为ECDSA或SM2，返回算法为EC
     *
     * @param algorithm XXXwithXXX算法
     * @return 算法
     */
    public static String getAlgorithmAfterWith(final String algorithm) {
        Assert.notNull(algorithm, "algorithm must be not null !");

        if (StrUtil.startWithIgnoreCase(algorithm, "ECIESWith")) {
            return "EC";
        }

        String resolvedAlgorithm = getMainAlgorithm(algorithm);
        int indexOfWith = StrUtil.lastIndexOfIgnoreCase(resolvedAlgorithm, "with");
        if (indexOfWith > 0) {
            resolvedAlgorithm = StrUtil.subSuf(resolvedAlgorithm, indexOfWith + "with".length());
        }
        if ("ECDSA".equalsIgnoreCase(resolvedAlgorithm)
                || "SM2".equalsIgnoreCase(resolvedAlgorithm)
                || "ECIES".equalsIgnoreCase(resolvedAlgorithm)
        ) {
            resolvedAlgorithm = "EC";
        }
        return resolvedAlgorithm;
    }

    /**
     * 读取密钥库(Java Key Store，JKS) KeyStore文件。 <br>
     * KeyStore文件用于数字证书的密钥对保存<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param keyFile  证书文件
     * @param password 密码
     * @return {@link KeyStore}
     * @since 5.0.0
     */
    public static KeyStore readJKSKeyStore(final File keyFile, final char[] password) {
        return readKeyStore(KEY_TYPE_JKS, keyFile, password);
    }

    /**
     * 读取密钥库(Java Key Store，JKS) KeyStore文件。 <br>
     * KeyStore文件用于数字证书的密钥对保存<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param in       {@link InputStream} 如果想从文件读取.keystore文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @param password 密码
     * @return {@link KeyStore}
     */
    public static KeyStore readJKSKeyStore(final InputStream in, final char[] password) {
        return readKeyStore(KEY_TYPE_JKS, in, password);
    }

    /**
     * 读取PKCS12 KeyStore文件。 <br>
     * KeyStore文件用于数字证书的密钥对保存
     *
     * @param keyFile  证书文件
     * @param password 密码
     * @return {@link KeyStore}
     * @since 5.0.0
     */
    public static KeyStore readPKCS12KeyStore(final File keyFile, final char[] password) {
        return readKeyStore(KEY_TYPE_PKCS12, keyFile, password);
    }

    /**
     * 读取PKCS12 KeyStore文件。 <br>
     * KeyStore文件用于数字证书的密钥对保存
     *
     * @param in       {@link InputStream} 如果想从文件读取.keystore文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @param password 密码
     * @return {@link KeyStore}
     * @since 5.0.0
     */
    public static KeyStore readPKCS12KeyStore(final InputStream in, final char[] password) {
        return readKeyStore(KEY_TYPE_PKCS12, in, password);
    }

    /**
     * 读取KeyStore文件。 <br>
     * KeyStore文件用于数字证书的密钥对保存<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param type     类型
     * @param keyFile  证书文件
     * @param password 密码，null表示无密码
     * @return {@link KeyStore}
     * @since 5.0.0
     */
    public static KeyStore readKeyStore(final String type, final File keyFile, final char[] password) {
        InputStream in = null;
        try {
            in = FileUtil.getInputStream(keyFile);
            return readKeyStore(type, in, password);
        } finally {
            IoUtil.close(in);
        }
    }

    /**
     * 读取KeyStore文件。 <br>
     * KeyStore文件用于数字证书的密钥对保存<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param type     类型
     * @param in       {@link InputStream} 如果想从文件读取.keystore文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @param password 密码，null表示无密码
     * @return {@link KeyStore}
     */
    public static KeyStore readKeyStore(final String type, final InputStream in, final char[] password) {
        final KeyStore keyStore = getKeyStore(type);
        try {
            keyStore.load(in, password);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return keyStore;
    }

    /**
     * 获取{@link KeyStore}对象。
     *
     * @param type 类型
     * @return {@link KeyStore}
     */
    public static KeyStore getKeyStore(final String type) {
        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();
        try {
            return null == provider ? KeyStore.getInstance(type) : KeyStore.getInstance(type, provider);
        } catch (final KeyStoreException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 从KeyStore中获取私钥公钥。
     *
     * @param type     类型
     * @param in       {@link InputStream} 如果想从文件读取.keystore文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @param password 密码
     * @param alias    别名
     * @return {@link KeyPair}
     * @since 4.4.1
     */
    public static KeyPair getKeyPair(
                final String type,
                final InputStream in,
                final char[] password,
                final String alias
        ) {
        final KeyStore keyStore = readKeyStore(type, in, password);
        return getKeyPair(keyStore, password, alias);
    }

    /**
     * 从KeyStore中获取私钥公钥。
     *
     * @param keyStore {@link KeyStore}
     * @param password 密码
     * @param alias    别名
     * @return {@link KeyPair}
     * @since 4.4.1
     */
    public static KeyPair getKeyPair(final KeyStore keyStore, final char[] password, final String alias) {
        PublicKey publicKey;
        PrivateKey privateKey;
        try {
            publicKey = keyStore.getCertificate(alias).getPublicKey();
            privateKey = (PrivateKey) keyStore.getKey(alias, password);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * 读取X.509 Certification文件。 <br>
     * Certification为证书文件<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param in       {@link InputStream} 如果想从文件读取.cer文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @param password 密码
     * @param alias    别名
     * @return {@link KeyStore}
     * @since 4.4.1
     */
    public static Certificate readX509Certificate(final InputStream in, final char[] password, final String alias) {
        return readCertificate(CERT_TYPE_X509, in, password, alias);
    }

    /**
     * 读取X.509 Certification文件中的公钥。 <br>
     * Certification为证书文件<br>
     * see: https://www.cnblogs.com/yinliang/p/10115519.html
     *
     * @param in {@link InputStream} 如果想从文件读取.cer文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @return {@link KeyStore}
     * @since 4.5.2
     */
    public static PublicKey readPublicKeyFromCert(final InputStream in) {
        final Certificate certificate = readX509Certificate(in);
        if (null != certificate) {
            return certificate.getPublicKey();
        }
        return null;
    }

    /**
     * 读取X.509 Certification文件。 <br>
     * Certification为证书文件<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param in {@link InputStream} 如果想从文件读取.cer文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @return {@link KeyStore}
     * @since 4.4.1
     */
    public static Certificate readX509Certificate(final InputStream in) {
        return readCertificate(CERT_TYPE_X509, in);
    }

    /**
     * 读取Certification文件。 <br>
     * Certification为证书文件<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param type     类型，例如X.509
     * @param in       {@link InputStream} 如果想从文件读取.cer文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @param password 密码
     * @param alias    别名
     * @return {@link KeyStore}
     * @since 4.4.1
     */
    public static Certificate readCertificate(
                final String type,
                final InputStream in,
                final char[] password,
                final String alias
        ) {
        final KeyStore keyStore = readKeyStore(type, in, password);
        try {
            return keyStore.getCertificate(alias);
        } catch (KeyStoreException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 读取Certification文件。 <br>
     * Certification为证书文件<br>
     * see: http://snowolf.iteye.com/blog/391931
     *
     * @param type 类型，例如X.509
     * @param in   {@link InputStream} 如果想从文件读取.cer文件，使用 {@link FileUtil#getInputStream(java.io.File)} 读取
     * @return {@link Certificate}
     */
    public static Certificate readCertificate(final String type, final InputStream in) {
        try {
            return getCertificateFactory(type).generateCertificate(in);
        } catch (CertificateException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 获得 Certification。
     *
     * @param keyStore {@link KeyStore}
     * @param alias    别名
     * @return {@link Certificate}
     */
    public static Certificate getCertificate(final KeyStore keyStore, final String alias) {
        try {
            return keyStore.getCertificate(alias);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 获取{@link CertificateFactory}。
     *
     * @param type 类型，例如X.509
     * @return {@link KeyPairGenerator}
     * @since 4.5.0
     */
    public static CertificateFactory getCertificateFactory(final String type) {
        final Provider provider = GlobalBouncyCastleProvider.INSTANCE.getProvider();

        CertificateFactory factory;
        try {
            factory = (
                        null == provider) ? CertificateFactory.getInstance(type) : CertificateFactory.getInstance(type,
                        provider
                );
        } catch (CertificateException e) {
            throw new CryptoException(e);
        }
        return factory;
    }

    /**
     * 编码压缩EC公钥（基于BouncyCastle）。 <br>
     * 见：https://www.cnblogs.com/xinzhao/p/8963724.html
     *
     * @param publicKey {@link PublicKey}，必须为org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey
     * @return 压缩得到的X
     * @since 4.4.4
     */
    public static byte[] encodeECPublicKey(final PublicKey publicKey) {
        return BCUtil.encodeECPublicKey(publicKey);
    }

    /**
     * 解码恢复EC压缩公钥,支持Base64和Hex编码,（基于BouncyCastle）。 <br>
     * 见：https://www.cnblogs.com/xinzhao/p/8963724.html
     *
     * @param encode    压缩公钥
     * @param curveName EC曲线名
     * @return 公钥
     * @since 4.4.4
     */
    public static PublicKey decodeECPoint(final String encode, final String curveName) {
        return BCUtil.decodeECPoint(encode, curveName);
    }

    /**
     * 解码恢复EC压缩公钥,支持Base64和Hex编码,（基于BouncyCastle）。 <br>
     * 见：https://www.cnblogs.com/xinzhao/p/8963724.html
     *
     * @param encodeByte 压缩公钥
     * @param curveName  EC曲线名
     * @return 公钥
     * @since 4.4.4
     */
    public static PublicKey decodeECPoint(final byte[] encodeByte, final String curveName) {
        return BCUtil.decodeECPoint(encodeByte, curveName);
    }

    /**
     * 通过RSA私钥生成RSA公钥。
     *
     * @param privateKey RSA私钥
     * @return RSA公钥，null表示私钥不被支持
     * @since 5.3.6
     */
    public static PublicKey getRSAPublicKey(final PrivateKey privateKey) {
        if (privateKey instanceof RSAPrivateCrtKey) {
            final RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;
            return getRSAPublicKey(privk.getModulus(), privk.getPublicExponent());
        }
        return null;
    }

    /**
     * 获得RSA公钥对象。
     *
     * @param modulus        Modulus
     * @param publicExponent Public Exponent
     * @return 公钥
     * @since 5.3.6
     */
    public static PublicKey getRSAPublicKey(final String modulus, final String publicExponent) {
        return getRSAPublicKey(
                new BigInteger(modulus, 16), new BigInteger(publicExponent, 16));
    }

    /**
     * 获得RSA公钥对象。
     *
     * @param modulus        Modulus
     * @param publicExponent Public Exponent
     * @return 公钥
     * @since 5.3.6
     */
    public static PublicKey getRSAPublicKey(final BigInteger modulus, final BigInteger publicExponent) {
        final RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        try {
            return getKeyFactory("RSA").generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 将密钥编码为Base64格式。
     *
     * @param key 密钥
     * @return Base64格式密钥
     * @since 5.7.22
     */
    public static String toBase64(final Key key) {
        return Base64.encode(key.getEncoded());
    }

    /**
     * 生成X500Name，用于证书的颁发者（issuer）与使用者（subject）名称。 <br>
     * 传入为空白字符串的字段会被跳过，示例：
     *
     * <pre>
     * KeyUtil.generateX500Name("hongz", "Laser", "R&amp;D", "BeiJing", "BeiJing", "CN");
     * </pre>
     *
     * 此处使用通用的{@link BCStyle}，对RDN顺序无强约束；如需与严格CA交互，可自行用
     * {@link X500NameBuilder}构造。
     *
     * @param cn 通用名（Common Name），如域名或人名
     * @param o  组织名（Organization）
     * @param ou 组织单位（Organizational Unit）
     * @param l  城市或地区（Locality）
     * @param st 省或州（State）
     * @param c  国家代码（Country），如CN
     * @return {@link X500Name}
     * @since 1.0.0
     */
    public static X500Name generateX500Name(final String cn, final String o, final String ou, final String l,
                                            final String st, final String c) {
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        addRdn(builder, BCStyle.CN, cn);
        addRdn(builder, BCStyle.O, o);
        addRdn(builder, BCStyle.OU, ou);
        addRdn(builder, BCStyle.L, l);
        addRdn(builder, BCStyle.ST, st);
        addRdn(builder, BCStyle.C, c);
        return builder.build();
    }

    /**
     * 生成随机的证书序列号。
     *
     * @return 随机正整数序列号
     * @since 1.0.0
     */
    public static BigInteger generateRandomSerialNumber() {
        return new BigInteger(SERIAL_NUMBER_BITS, new SecureRandom());
    }

    /**
     * 生成自签X.509证书。 <br>
     * 颁发者与使用者为同一名称，常用于生成根证书。
     *
     * @param subject      使用者名称，同时作为颁发者名称
     * @param privateKey   私钥，用于签名
     * @param publicKey    公钥，写入证书
     * @param serialNumber 证书序列号，可通过{@link #generateRandomSerialNumber()}生成
     * @param notBefore    生效时间
     * @param notAfter     失效时间
     * @return {@link X509Certificate}
     * @since 1.0.0
     */
    public static X509Certificate generateSelfSignedX509Certificate(final X500Name subject, final PrivateKey privateKey,
                                                                    final PublicKey publicKey,
                                                                    final BigInteger serialNumber,
                                                                    final Date notBefore, final Date notAfter) {
        return generateX509Certificate(subject, subject, serialNumber, notBefore, notAfter, privateKey, publicKey);
    }

    /**
     * 生成X.509证书，使用默认签名算法{@link #SIGN_ALGORITHM_SHA256_WITH_RSA}。 <br>
     * 颁发者与使用者名称相同时生成自签证书，否则为由颁发者签发的下级证书。
     *
     * @param issuer           颁发者名称
     * @param subject          使用者名称
     * @param serialNumber     证书序列号，可通过{@link #generateRandomSerialNumber()}生成
     * @param notBefore        生效时间
     * @param notAfter         失效时间
     * @param issuerPrivateKey 颁发者私钥，用于签名
     * @param subjectPublicKey 使用者公钥，写入证书
     * @return {@link X509Certificate}
     * @since 1.0.0
     */
    public static X509Certificate generateX509Certificate(final X500Name issuer, final X500Name subject,
                                                          final BigInteger serialNumber, final Date notBefore,
                                                          final Date notAfter, final PrivateKey issuerPrivateKey,
                                                          final PublicKey subjectPublicKey) {
        return generateX509Certificate(issuer, subject, serialNumber, notBefore, notAfter, issuerPrivateKey,
                subjectPublicKey, SIGN_ALGORITHM_SHA256_WITH_RSA);
    }

    /**
     * 生成X.509证书，可指定签名算法。 <br>
     * 颁发者与使用者名称相同时生成自签证书（并标记为CA，可签发下级证书），否则为下级证书。
     *
     * @param issuer             颁发者名称
     * @param subject            使用者名称
     * @param serialNumber       证书序列号，可通过{@link #generateRandomSerialNumber()}生成
     * @param notBefore          生效时间
     * @param notAfter           失效时间
     * @param issuerPrivateKey   颁发者私钥，用于签名
     * @param subjectPublicKey   使用者公钥，写入证书
     * @param signatureAlgorithm 签名算法，如SHA256withRSA、SM3withSM2
     * @return {@link X509Certificate}
     * @since 1.0.0
     */
    public static X509Certificate generateX509Certificate(final X500Name issuer, final X500Name subject,
                                                          final BigInteger serialNumber, final Date notBefore,
                                                          final Date notAfter, final PrivateKey issuerPrivateKey,
                                                          final PublicKey subjectPublicKey,
                                                          final String signatureAlgorithm) {
        final X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(issuer, serialNumber, notBefore,
                notAfter, subject, SubjectPublicKeyInfo.getInstance(subjectPublicKey.getEncoded()));
        try {
            if (issuer.equals(subject)) {
                // 自签证书视为CA，允许签发下级证书
                certBuilder.addExtension(Extension.basicConstraints, false, new BasicConstraints(1));
            }
            final ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(issuerPrivateKey);
            final byte[] certBytes = certBuilder.build(signer).getEncoded();
            return (X509Certificate) getCertificateFactory(CERT_TYPE_X509)
                    .generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (CertificateException | IOException | OperatorCreationException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 生成PKCS#10证书签名请求（CSR），用于向CA申请证书。
     *
     * @param subject            使用者名称
     * @param publicKey          公钥，写入请求
     * @param privateKey         私钥，用于签名
     * @param signatureAlgorithm 签名算法，如SHA256withRSA、SM3withSM2
     * @return {@link PKCS10CertificationRequest}，DER编码可通过{@code getEncoded()}获取
     * @since 1.0.0
     */
    public static PKCS10CertificationRequest generateCsr(final X500Name subject, final PublicKey publicKey,
                                                         final PrivateKey privateKey,
                                                         final String signatureAlgorithm) {
        final JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(subject,
                publicKey);
        try {
            return builder.build(new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey));
        } catch (OperatorCreationException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 写出PKCS#12（pfx/p12）密钥库文件，内容为证书及其对应私钥。 <br>
     * 与{@link #readPKCS12KeyStore(File, char[])}互为读写。
     *
     * @param dest        目标文件
     * @param certificate 证书
     * @param privateKey  私钥
     * @param alias       别名，读取时需使用同一别名
     * @param password    密钥库密码
     * @since 1.0.0
     */
    public static void writePKCS12KeyStore(final File dest, final Certificate certificate, final PrivateKey privateKey,
                                           final String alias, final char[] password) {
        try (OutputStream out = FileUtil.getOutputStream(dest)) {
            writePKCS12KeyStore(out, certificate, privateKey, alias, password);
        } catch (IOException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 写出PKCS#12（pfx/p12）密钥库，内容为证书及其对应私钥。
     *
     * @param out         输出流
     * @param certificate 证书
     * @param privateKey  私钥
     * @param alias       别名，读取时需使用同一别名
     * @param password    密钥库密码
     * @since 1.0.0
     */
    public static void writePKCS12KeyStore(final OutputStream out, final Certificate certificate,
                                           final PrivateKey privateKey, final String alias, final char[] password) {
        try {
            final KeyStore keyStore = KeyStore.getInstance(KEY_TYPE_PKCS12);
            keyStore.load(null, null);
            keyStore.setKeyEntry(alias, privateKey, password, new Certificate[]{certificate});
            keyStore.store(out, password);
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 向X500Name构建器添加一个RDN。
     *
     * @param builder {@link X500NameBuilder}
     * @param oid     RDN的OID
     * @param value   值，为空白时跳过
     */
    private static void addRdn(final X500NameBuilder builder, final ASN1ObjectIdentifier oid, final String value) {
        if (false == StrUtil.isBlank(value)) {
            builder.addRDN(oid, value);
        }
    }
}
