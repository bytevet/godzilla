// Safe twin of weak_cipher_ecb: an authenticated mode (GCM) is not ECB, so the
// dynamic guard `includes(arg[0], "/ECB/")` does not confirm and java-ecb-mode
// stays silent.
import javax.crypto.Cipher;

public class GcmCipher {
    public Cipher safe() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding"); // authenticated mode (no finding)
    }
}
