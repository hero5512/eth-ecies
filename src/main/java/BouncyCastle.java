import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public final class BouncyCastle {

  private static class Holder {
    private static final Provider INSTANCE;
    static{
        Provider p = Security.getProvider("BC");
        INSTANCE = (p != null) ? p : new BouncyCastleProvider();

    }
  }

  public static Provider getInstance() {
    return Holder.INSTANCE;
  }
}
