package cc.hongz.ztools.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("Key Util测试")
public class KeyUtilTest {

    /**
     * 测试用临时目录。
     */
    @TempDir
    private File tempDir;

    /**
     * 测试关闭BouncyCastle支持时是否会正常抛出异常，即关闭是否有效
     */
    @Test
    @Disabled
    public void generateKeyPairTest() {
        assertThrows(CryptoException.class, () -> {
            GlobalBouncyCastleProvider.setUseBouncyCastle(false);
            KeyPair pair = KeyUtil.generateKeyPair("SM2");
            assertNotNull(pair);
        });
    }

    @Test
    @DisplayName("get RSA Public Key Test测试")
    public void getRSAPublicKeyTest(){
        final KeyPair keyPair = KeyUtil.generateKeyPair("RSA");
        final PrivateKey aPrivate = keyPair.getPrivate();
        final PublicKey rsaPublicKey = KeyUtil.getRSAPublicKey(aPrivate);
        assertEquals(rsaPublicKey, keyPair.getPublic());
    }

    /**
     * 测试EC和ECIES算法生成的KEY是一致的
     */
    @Test
    @DisplayName("generate ECIES Key Test测试")
    public void generateECIESKeyTest(){
        final KeyPair ecies = KeyUtil.generateKeyPair("ECIES");
        assertNotNull(ecies.getPrivate());
        assertNotNull(ecies.getPublic());

        byte[] privateKeyBytes = ecies.getPrivate().getEncoded();

        final PrivateKey privateKey = KeyUtil.generatePrivateKey("EC", privateKeyBytes);
        assertEquals(ecies.getPrivate(), privateKey);
    }

    @Test
    @DisplayName("generate DH Test测试")
    public void generateDHTest(){
        final KeyPair dh = KeyUtil.generateKeyPair("DH");
        assertNotNull(dh.getPrivate());
        assertNotNull(dh.getPublic());

        byte[] privateKeyBytes = dh.getPrivate().getEncoded();

        final PrivateKey privateKey = KeyUtil.generatePrivateKey("DH", privateKeyBytes);
        assertEquals(dh.getPrivate(), privateKey);
    }

    @Test
    @DisplayName("generate Sm4Key Test测试")
    public void generateSm4KeyTest(){
        // https://github.com/chinabugotech/hutool/issues/2150
        assertEquals(16, KeyUtil.generateKey("sm4").getEncoded().length);
        assertEquals(32, KeyUtil.generateKey("sm4", 256).getEncoded().length);
    }

    @Test
    @DisplayName("生成X500Name测试")
    public void generateX500NameTest() {
        final X500Name name = KeyUtil.generateX500Name("hongz", "Laser", "R&D", "BeiJing", "BeiJing", "CN");
        final String dn = name.toString();
        assertTrue(dn.contains("hongz"));
        assertTrue(dn.contains("Laser"));
        assertTrue(dn.contains("R&D"));
        assertTrue(dn.contains("BeiJing"));
        assertTrue(dn.contains("CN"));

        // null 与空字符串的字段应被跳过
        final X500Name minimal = KeyUtil.generateX500Name("hongz", null, "", null, null, "CN");
        assertEquals(2, minimal.getRDNs().length);
    }

    @Test
    @DisplayName("生成随机证书序列号测试")
    public void generateRandomSerialNumberTest() {
        final BigInteger first = KeyUtil.generateRandomSerialNumber();
        final BigInteger second = KeyUtil.generateRandomSerialNumber();

        assertNotNull(first);
        assertTrue(first.signum() > 0);
        assertNotEquals(first, second);
    }

    @Test
    @DisplayName("生成自签X509证书测试")
    public void generateSelfSignedX509CertificateTest() throws Exception {
        final KeyPair keyPair = KeyUtil.generateKeyPair("RSA", 2048);
        final X500Name subject = KeyUtil.generateX500Name("hongz", null, null, null, null, "CN");
        final Date notBefore = new Date();
        final Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));
        final BigInteger serialNumber = KeyUtil.generateRandomSerialNumber();

        final X509Certificate certificate = KeyUtil.generateSelfSignedX509Certificate(subject, keyPair.getPrivate(),
                keyPair.getPublic(), serialNumber, notBefore, notAfter);

        assertEquals(subject, new X500Name(certificate.getIssuerX500Principal().getName()));
        assertEquals(subject, new X500Name(certificate.getSubjectX500Principal().getName()));
        assertEquals(serialNumber, certificate.getSerialNumber());
        assertEquals(keyPair.getPublic(), certificate.getPublicKey());
        // 当前时间应落在有效期内
        certificate.checkValidity();
    }

    @Test
    @DisplayName("CA签发用户证书测试")
    public void generateX509CertificateByIssuerTest() throws Exception {
        final KeyPair caKeyPair = KeyUtil.generateKeyPair("RSA", 2048);
        final KeyPair userKeyPair = KeyUtil.generateKeyPair("RSA", 2048);
        final X500Name caName = KeyUtil.generateX500Name("hongz-ca", "Laser", null, null, null, "CN");
        final X500Name userName = KeyUtil.generateX500Name("hongz-user", "Laser", null, null, null, "CN");
        final Date notBefore = new Date();
        final Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));

        final X509Certificate caCertificate = KeyUtil.generateSelfSignedX509Certificate(caName, caKeyPair.getPrivate(),
                caKeyPair.getPublic(), KeyUtil.generateRandomSerialNumber(), notBefore, notAfter);
        final X509Certificate userCertificate = KeyUtil.generateX509Certificate(caName, userName,
                KeyUtil.generateRandomSerialNumber(), notBefore, notAfter, caKeyPair.getPrivate(),
                userKeyPair.getPublic());

        // 用户证书的颁发者即CA
        assertEquals(caCertificate.getSubjectX500Principal(), userCertificate.getIssuerX500Principal());
        assertEquals(userKeyPair.getPublic(), userCertificate.getPublicKey());
        // 用户证书由CA私钥签名，用CA公钥验签应通过
        userCertificate.verify(caKeyPair.getPublic());
    }

    @Test
    @DisplayName("PKCS12密钥库读写闭环测试")
    public void writeAndReadPKCS12KeyStoreTest() throws Exception {
        final KeyPair keyPair = KeyUtil.generateKeyPair("RSA", 2048);
        final X500Name subject = KeyUtil.generateX500Name("hongz", null, null, null, null, "CN");
        final Date notBefore = new Date();
        final Date notAfter = new Date(notBefore.getTime() + TimeUnit.DAYS.toMillis(365));
        final X509Certificate certificate = KeyUtil.generateSelfSignedX509Certificate(subject, keyPair.getPrivate(),
                keyPair.getPublic(), KeyUtil.generateRandomSerialNumber(), notBefore, notAfter);

        final char[] password = "12345678".toCharArray();
        final File pfxFile = new File(this.tempDir, "hongz.pfx");
        KeyUtil.writePKCS12KeyStore(pfxFile, certificate, keyPair.getPrivate(), "hongz", password);
        assertTrue(pfxFile.length() > 0);

        // 写出的密钥库应能被自身读回，且私钥与证书一致
        final KeyStore keyStore = KeyUtil.readPKCS12KeyStore(pfxFile, password);
        assertEquals(certificate, keyStore.getCertificate("hongz"));
        assertEquals(keyPair.getPrivate(), keyStore.getKey("hongz", password));
    }

    @Test
    @DisplayName("生成PKCS10证书签名请求测试")
    public void generateCsrTest() throws Exception {
        final KeyPair keyPair = KeyUtil.generateKeyPair("RSA", 2048);
        final X500Name subject = KeyUtil.generateX500Name("hongz", null, null, null, null, "CN");

        final PKCS10CertificationRequest csr = KeyUtil.generateCsr(subject, keyPair.getPublic(), keyPair.getPrivate(),
                "SHA256withRSA");

        assertNotNull(csr);
        assertEquals(subject, csr.getSubject());
        // DER编码往返应一致
        assertArrayEquals(csr.getEncoded(), new PKCS10CertificationRequest(csr.getEncoded()).getEncoded());
    }
}
