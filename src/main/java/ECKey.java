import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;

public class ECKey {

    public static final ECDomainParameters CURVE;
    public static final ECParameterSpec CURVE_SPEC;

    public static final BigInteger HALF_CURVE_ORDER;

    private static final SecureRandom secureRandom;


    private final PrivateKey privKey;
    protected final ECPoint pub;
    private final Provider provider;


    static {
        X9ECParameters params = SECNamedCurves.getByName("secp256r1");
        CURVE = new ECDomainParameters(params.getCurve(), params.getG(), params.getN(), params.getH());
        CURVE_SPEC = new ECParameterSpec(params.getCurve(), params.getG(), params.getN(), params.getH());
        HALF_CURVE_ORDER = params.getN().shiftRight(1);
        secureRandom = new SecureRandom();
    }

    public ECKey(Provider provider, SecureRandom secureRandom) {
        this.provider = provider;

        final KeyPairGenerator keyPairGen = ECKeyPairGenerator.getInstance(provider, secureRandom);
        final KeyPair keyPair = keyPairGen.generateKeyPair();

        this.privKey = keyPair.getPrivate();

        final PublicKey pubKey = keyPair.getPublic();
        if (pubKey instanceof BCECPublicKey) {
            this.pub = ((BCECPublicKey) pubKey).getQ();
        } else if (pubKey instanceof ECPublicKey) {
            this.pub = extractPublicKey((ECPublicKey) pubKey);
        } else {
            throw new AssertionError(
                    "Expected Provider " + provider.getName() +
                            " to produce a subtype of ECPublicKey, found " + pubKey.getClass());
        }
    }

    public ECKey(Provider provider, PrivateKey privKey, ECPoint pub) {
        this.provider = provider;

        if (privKey == null || isECPrivateKey(privKey)) {
            this.privKey = privKey;
        } else {
            throw new IllegalArgumentException(
                    "Expected EC private key, given a private key object with class " +
                            privKey.getClass().toString() +
                            " and algorithm " + privKey.getAlgorithm());
        }

        if (pub == null) {
            throw new IllegalArgumentException("Public key may not be null");
        }

        if (pub.isInfinity()) {
            throw new IllegalArgumentException("Public key must not be a point at infinity, probably your private key is incorrect");
        }

        this.pub = pub;
    }

    public ECKey(BigInteger priv, ECPoint pub) {
        this(
                BouncyCastle.getInstance(),
                privateKeyFromBigInteger(priv),
                pub
        );
    }

    private static boolean isECPrivateKey(PrivateKey privKey) {
        return privKey instanceof ECPrivateKey || privKey.getAlgorithm().equals("EC");
    }


    private static ECPoint extractPublicKey(final ECPublicKey ecPublicKey) {
        final java.security.spec.ECPoint publicPointW = ecPublicKey.getW();
        final BigInteger xCoord = publicPointW.getAffineX();
        final BigInteger yCoord = publicPointW.getAffineY();

        return CURVE.getCurve().createPoint(xCoord, yCoord);
    }

    private static PrivateKey privateKeyFromBigInteger(BigInteger priv) {
        if (priv == null) {
            return null;
        } else {
            try {
                return ECKeyFactory
                        .getInstance(BouncyCastle.getInstance())
                        .generatePrivate(new ECPrivateKeySpec(priv, CURVE_SPEC));
            } catch (InvalidKeySpecException ex) {
                throw new AssertionError("Assumed correct key spec statically");
            }
        }
    }

    public static ECKey fromPublicOnly(byte[] pub) {
        return new ECKey(null, CURVE.getCurve().decodePoint(pub));
    }

    public ECPoint getPubKeyPoint() {
        return pub;
    }

    public PrivateKey getPrivatePoint() {
        return privKey;
    }

    public static ECKey fromPrivate(BigInteger privKey) {
        return new ECKey(privKey, CURVE.getG().multiply(privKey));
    }

}
