package cc.hongz.ztools.crypto;

import cc.hongz.ztools.crypto.asymmetric.SignAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Issue3512测试")
public class Issue3512Test {
    @Test
    @DisplayName("sign Test测试")
    public void signTest() {
        SecureUtil.sign(SignAlgorithm.SHA256withRSA);
    }
}
