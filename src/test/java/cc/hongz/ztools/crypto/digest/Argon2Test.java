package cc.hongz.ztools.crypto.digest;

import cc.hongz.ztools.core.codec.Base64;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Argon2测试")
public class Argon2Test {
    @Test
    @DisplayName("argon2Test测试")
    public void argon2Test() {
        Argon2 argon2 = new Argon2();
        final byte[] digest = argon2.digest("123456".toCharArray());
        Assertions.assertEquals("wVGMOdzf5EdKGANPeHjaUnaFEJA0BnAq6HcF2psFmFo=", Base64.encode(digest));
    }

    @Test
    @DisplayName("argon2With Salt Test测试")
    public void argon2WithSaltTest() {
        final Argon2 argon2 = new Argon2();
        argon2.setSalt("123456".getBytes());
        final byte[] digest = argon2.digest("123456".toCharArray());
        Assertions.assertEquals("sEpbXTdMWra36JXPVxrZMm3xyoR5GkMlLhtW0Kwp9Ag=", Base64.encode(digest));
    }
}
