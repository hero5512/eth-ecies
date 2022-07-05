import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.junit.Test;

import java.io.IOException;
import java.math.BigInteger;

public class TestCrypto {
    @Test
    public void TestEncryptAndDecrypt() throws InvalidCipherTextException, IOException {
        String msg = "hello world";
        ECKey key = ECKey.fromPrivate(new BigInteger("40726844782749937894834151007763016161820451265783099183065635627847362290970", 10));
        byte[] cipher = ECIES.encrypt(key.getPubKeyPoint(), msg.getBytes(), null, null);
        byte[] msgBytes = ECIES.decrypt(((BCECPrivateKey) key.getPrivatePoint()).getD(), cipher, null, null);
        assert (msg.equals(new String(msgBytes)));
    }
}
