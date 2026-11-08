package cc.hongz.ztools.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CertUtil} 测试.
 */
class CertUtilTest {

    @TempDir
    File tempDir;

    @Test
    @DisplayName("内存生成自签证书与 PEM/CSR")
    void generateBundleTest() throws Exception {
        final CertBundle bundle = CertUtil.generate(CertOptions.create().cn("hongz-cert").validityDays(30));
        assertNotNull(bundle.getKeyPair());
        assertNotNull(bundle.getCertificate());
        assertNotNull(bundle.getCsr());
        assertTrue(bundle.getPublicKeyPem().contains("BEGIN PUBLIC KEY"));
        assertTrue(bundle.getPrivateKeyPem().contains("BEGIN PRIVATE KEY"));
        assertTrue(bundle.getCertificatePem().contains("BEGIN CERTIFICATE"));
        assertTrue(bundle.getCsrPem().contains("BEGIN CERTIFICATE REQUEST"));
        CertUtil.verifySelfSigned(bundle.getCertificate());

        final CertInfo info = CertUtil.inspect(bundle.getCertificate());
        assertTrue(info.isSelfSigned());
        assertTrue(info.getSubject().contains("hongz-cert"));
    }

    @Test
    @DisplayName("落盘全格式并回读 PFX/CRT")
    void writeAllFormatsTest() throws Exception {
        final CertOptions options = CertOptions.create().cn("hongz-disk").filePrefix("demo").password("passw0rd")
                .alias("demo");
        final Map<CertOptions.Format, File> files = CertUtil.write(options, this.tempDir);

        assertEquals(CertOptions.Format.values().length, files.size());
        for (final File file : files.values()) {
            assertTrue(file.isFile() && file.length() > 0, file.getName());
        }

        final X509Certificate fromCrt = CertUtil.readCertificate(files.get(CertOptions.Format.CRT));
        CertUtil.verifySelfSigned(fromCrt);

        final X509Certificate fromCer = CertUtil.readCertificate(files.get(CertOptions.Format.CER));
        assertEquals(fromCrt.getSerialNumber(), fromCer.getSerialNumber());

        final KeyStore keyStore = KeyUtil.readPKCS12KeyStore(files.get(CertOptions.Format.PFX), "passw0rd".toCharArray());
        assertEquals(fromCrt, keyStore.getCertificate("demo"));
    }

    @Test
    @DisplayName("仅生成公钥 PEM")
    void writePublicOnlyTest() {
        final Map<CertOptions.Format, File> files = CertUtil.write(
                CertOptions.create().formats(CertOptions.Format.PUBLIC_PEM).filePrefix("only"), this.tempDir);
        assertEquals(1, files.size());
        assertTrue(files.get(CertOptions.Format.PUBLIC_PEM).getName().endsWith("PublicKey.pem"));
    }
}
