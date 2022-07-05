import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.DigestDerivationFunction;
import org.bouncycastle.crypto.params.KDFParameters;
import org.bouncycastle.util.Pack;

public class ConcatKDFBytesGenerator
        implements DigestDerivationFunction {
    private final int counterStart;
    private final Digest digest;
    private byte[] shared;
    private byte[] iv;

    protected ConcatKDFBytesGenerator(int counterStart, Digest digest) {
        this.counterStart = counterStart;
        this.digest = digest;
    }

    public ConcatKDFBytesGenerator(Digest digest) {
        this(1, digest);
    }

    @Override
    public void init(DerivationParameters param) {
        if (param instanceof KDFParameters) {
            KDFParameters p = (KDFParameters) param;
            shared = p.getSharedSecret();
            iv = p.getIV();
        } else {
            throw new IllegalArgumentException("KDF parameters required for KDF2Generator");
        }
    }

    public Digest getDigest() {
        return digest;
    }


    public int generateBytes(byte[] out, int outOff, int len) throws DataLengthException,
            IllegalArgumentException {
        if ((out.length - len) < outOff) {
            throw new DataLengthException("output buffer too small");
        }

        long oBytes = len;
        int outLen = digest.getDigestSize();

        if (oBytes > ((2L << 32) - 1)) {
            throw new IllegalArgumentException("Output length too large");
        }

        int cThreshold = (int) ((oBytes + outLen - 1) / outLen);

        byte[] dig = new byte[digest.getDigestSize()];

        byte[] C = new byte[4];
        Pack.intToBigEndian(counterStart, C, 0);

        int counterBase = counterStart & ~0xFF;

        for (int i = 0; i < cThreshold; i++) {
            digest.update(C, 0, C.length);
            digest.update(shared, 0, shared.length);

            if (iv != null) {
                digest.update(iv, 0, iv.length);
            }

            digest.doFinal(dig, 0);

            if (len > outLen) {
                System.arraycopy(dig, 0, out, outOff, outLen);
                outOff += outLen;
                len -= outLen;
            } else {
                System.arraycopy(dig, 0, out, outOff, len);
            }

            if (++C[3] == 0) {
                counterBase += 0x100;
                Pack.intToBigEndian(counterBase, C, 0);
            }
        }

        digest.reset();

        return (int) oBytes;
    }
}

