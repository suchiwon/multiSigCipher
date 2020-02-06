package encrypt;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

import java.security.SecureRandom;
import java.util.Base64;

public class Secp256k1Util {

    private KeyPairGenerator kpg;
    private KeyPair keyPair;

    public Secp256k1Util() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        this.kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256k1");
        this.kpg.initialize(ecSpec, new SecureRandom());
    }

    public KeyPair generateKeyPair() {
        this.keyPair = this.kpg.generateKeyPair();

        // PublicKey publicKey = keyPair.getPublic();
        // PrivateKey privateKey = keyPair.getPrivate();

        // String stringPublicKey =  new String(Base64.encodeBase64(publicKey.getEncoded()));
        // String stringPrivateKey = new String(Base64.encodeBase64(privateKey.getEncoded()));

        // System.out.println(stringPublicKey);
        // System.out.println(stringPrivateKey);

        return this.keyPair;
    }

    public PublicKey getPublicKey() {
        return this.keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return this.keyPair.getPrivate();
    }
}