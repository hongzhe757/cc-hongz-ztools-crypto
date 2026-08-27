package cc.hongz.ztools.crypto.digest;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("B Crypt测试")
public class BCryptTest {

    @Test
    @DisplayName("checkpw Test测试")
    public void checkpwTest(){
        assertFalse(BCrypt.checkpw("xxx",
                "$2a$2a$10$e4lBTlZ019KhuAFyqAlgB.Jxc6cM66GwkSR/5/xXNQuHUItPLyhzy"));
    }

    @Test
    @DisplayName("hashpw Short Salt Throws Illegal Argument Exception测试")
    public void hashpwShortSaltThrowsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> BCrypt.hashpw("password", "$"));
        assertThrows(IllegalArgumentException.class, () -> BCrypt.hashpw("password", "$2"));
        assertThrows(IllegalArgumentException.class, () -> BCrypt.hashpw("password", "$2a"));
        assertThrows(IllegalArgumentException.class, () -> BCrypt.hashpw("password", "$2a$"));
        assertThrows(IllegalArgumentException.class, () -> BCrypt.hashpw("password", "$2a$10$"));
    }
}
