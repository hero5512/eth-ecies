import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class ECIES {

    public static final int KEY_SIZE = 128;

    public static byte[] encrypt(byte[] publicKey, byte[] m, byte[] s1, byte[] s2) {
        ECKey ecKey = ECKey.fromPublicOnly(publicKey);
        return encrypt(ecKey.getPubKeyPoint(), m, s1, s2);
    }

    public static byte[] encrypt(ECPoint publicKey, byte[] m, byte[] s1, byte[] s2) {

        ECKeyPairGenerator eGen = new ECKeyPairGenerator();
        SecureRandom random = new SecureRandom();
        KeyGenerationParameters gParam = new ECKeyGenerationParameters(ECKey.CURVE, random);

        eGen.init(gParam);
        byte[] IV = new byte[KEY_SIZE / 8];
        new SecureRandom().nextBytes(IV);

        AsymmetricCipherKeyPair ephemPair = eGen.generateKeyPair();
        BigInteger prv = ((ECPrivateKeyParameters) ephemPair.getPrivate()).getD();
        ECPoint pub = ((ECPublicKeyParameters) ephemPair.getPublic()).getQ();
        ECIESEngine iesEngine = makeIESEngine(true, publicKey, prv, IV, s1);

        ECKeyGenerationParameters keygenParams = new ECKeyGenerationParameters(ECKey.CURVE, random);
        ECKeyPairGenerator generator = new ECKeyPairGenerator();
        generator.init(keygenParams);

        ECKeyPairGenerator gen = new ECKeyPairGenerator();
        gen.init(new ECKeyGenerationParameters(ECKey.CURVE, random));

        byte[] cipher;
        try {
            cipher = iesEngine.processBlock(m, 0, m.length, s2);
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(pub.getEncoded(false));
            bos.write(IV);
            bos.write(cipher);
            return bos.toByteArray();
        } catch (InvalidCipherTextException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] decrypt(BigInteger privKey, byte[] cipher, byte[] s1, byte[] s2) throws IOException, InvalidCipherTextException {

        byte[] plaintext;

        ByteArrayInputStream is = new ByteArrayInputStream(cipher);
        byte[] ephemBytes = new byte[2 * ((ECKey.CURVE.getCurve().getFieldSize() + 7) / 8) + 1];

        is.read(ephemBytes);
        ECPoint ephem = ECKey.CURVE.getCurve().decodePoint(ephemBytes);
        byte[] IV = new byte[KEY_SIZE / 8];
        is.read(IV);
        byte[] cipherBody = new byte[is.available()];
        is.read(cipherBody);

        plaintext = decrypt(ephem, privKey, IV, cipherBody, s1, s2);

        return plaintext;
    }

    public static byte[] decrypt(ECPoint ephem, BigInteger prv, byte[] IV, byte[] cipher, byte[] s1, byte[] s2) throws InvalidCipherTextException {
        AESEngine aesFastEngine = new AESEngine();

        ECIESEngine iesEngine = new ECIESEngine(
                new ECDHBasicAgreement(),
                new ConcatKDFBytesGenerator(new SHA256Digest()),
                new HMac(new SHA256Digest()),
                new SHA256Digest(),
                new BufferedBlockCipher(new SICBlockCipher(aesFastEngine)));

        byte[] e = new byte[]{};

        IESParameters p = new IESWithCipherParameters(s1, e, KEY_SIZE, KEY_SIZE);
        ParametersWithIV parametersWithIV =
                new ParametersWithIV(p, IV);

        iesEngine.init(false, new ECPrivateKeyParameters(prv, ECKey.CURVE), new ECPublicKeyParameters(ephem, ECKey.CURVE), parametersWithIV);

        return iesEngine.processBlock(cipher, 0, cipher.length, s2);
    }


    private static ECIESEngine makeIESEngine(boolean isEncrypt, ECPoint pub, BigInteger prv, byte[] IV, byte[] d) {
        AESEngine aesFastEngine = new AESEngine();
        ECIESEngine iesEngine = new ECIESEngine(
                new ECDHBasicAgreement(),
                new ConcatKDFBytesGenerator(new SHA256Digest()),
                new HMac(new SHA256Digest()),
                new SHA256Digest(),
                new BufferedBlockCipher(new SICBlockCipher(aesFastEngine)));

        byte[] e = new byte[]{};

        IESParameters p = new IESWithCipherParameters(d, e, KEY_SIZE, KEY_SIZE);
        ParametersWithIV parametersWithIV = new ParametersWithIV(p, IV);

        iesEngine.init(isEncrypt, new ECPrivateKeyParameters(prv, ECKey.CURVE), new ECPublicKeyParameters(pub, ECKey.CURVE), parametersWithIV);
        return iesEngine;
    }

}
