package multisig;

import com.codahale.shamir.Scheme;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.HashMap;

public class SecretSharing {

    public SecretSharing() {
    }

    public Map<Integer, byte[]> splitSecret(String secret, int n, int m) {
        Scheme scheme = new Scheme(new SecureRandom(), m, n);

        byte[] secretBytes = secret.getBytes(StandardCharsets.UTF_8);

        Map<Integer, byte[]> splited = scheme.split(secretBytes);

        return splited;
    }

    public String recoverSecret(Map<Integer, byte[]> parts, int n, int m) {
        Scheme scheme = new Scheme(new SecureRandom(), m, n);

        byte[] recovered = scheme.join(parts);

        return new String(recovered, StandardCharsets.UTF_8);
    }
}