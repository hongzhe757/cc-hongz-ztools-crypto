package cc.hongz.ztools.crypto.symmetric;

import cc.hongz.ztools.core.util.CharsetUtil;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RC4测试")
public class RC4Test {

    @Test
    @DisplayName("Crypt Message测试")
    public void testCryptMessage() {
        String key = "This is pretty long key";
        RC4 rc4 = new RC4(key);
        String message = "Hello, World!";
        byte[] crypt = rc4.encrypt(message);
        String msg = rc4.decrypt(crypt);
        assertEquals(message, msg);

        String message2 = "Hello, World， this is megssage 2";
        byte[] crypt2 = rc4.encrypt(message2);
        String msg2 = rc4.decrypt(crypt2);
        assertEquals(message2, msg2);
    }

    @Test
    @DisplayName("Crypt With Chinese Characters测试")
    public void testCryptWithChineseCharacters() {
        String message = "这是一个中文消息！";
        String key = "我是一个文件密钥";
        RC4 rc4 = new RC4(key);
        byte[] crypt = rc4.encrypt(message);
        String msg = rc4.decrypt(crypt);
        assertEquals(message, msg);

        String message2 = "这是第二个中文消息！";
        byte[] crypt2 = rc4.encrypt(message2);
        String msg2 = rc4.decrypt(crypt2);
        assertEquals(message2, msg2);
    }

    @Test
    @DisplayName("Decrypt With Hex Message测试")
    public void testDecryptWithHexMessage() {
        String message = "这是第一个用来测试密文为十六进制字符串的消息！";
        String key = "生成一个密钥";
        RC4 rc4 = new RC4(key);
        String encryptHex = rc4.encryptHex(message, CharsetUtil.CHARSET_UTF_8);
        String msg = rc4.decrypt(encryptHex);
        assertEquals(message, msg);

        String message2 = "这是第二个用来测试密文为十六进制字符串的消息！";
        String encryptHex2 = rc4.encryptHex(message2);
        String msg2 = rc4.decrypt(encryptHex2);
        assertEquals(message2, msg2);
    }


    @Test
    @DisplayName("Decrypt With Base64Message测试")
    public void testDecryptWithBase64Message() {
        String message = "这是第一个用来测试密文为Base64编码的消息！";
        String key = "生成一个密钥";
        RC4 rc4 = new RC4(key);
        String encryptHex = rc4.encryptBase64(message, CharsetUtil.CHARSET_UTF_8);
        String msg = rc4.decrypt(encryptHex);
        assertEquals(message, msg);

        String message2 = "这是第一个用来测试密文为Base64编码的消息！";
        String encryptHex2 = rc4.encryptBase64(message2);
        String msg2 = rc4.decrypt(encryptHex2);
        assertEquals(message2, msg2);
    }
}
