package bouncycas.bouncycas;

import java.security.Security;

import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;


public class Setup
{
    public static void installProvider()
    {
        Security.addProvider(new BouncyCastleFipsProvider());
    }

    public static void main(String[] args) {
        installProvider();
    }
}
