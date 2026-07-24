// Weak cipher mode: requesting a cipher in ECB mode leaks plaintext block
// patterns (identical blocks encrypt identically) — a CWE-327 weakness even with
// AES. Detected by java-ecb-mode via a dynamic guard on the transformation
// string. javax.crypto is part of the JDK, so no stubs are needed.
import javax.crypto.Cipher;

public class EcbCipher {
    public Cipher weak() throws Exception {
        return Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB mode (sink)
    }
}
