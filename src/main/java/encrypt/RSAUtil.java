package encrypt;

import java.io.UnsupportedEncodingException;
import java.io.FileNotFoundException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

import java.security.SecureRandom;
 
import java.util.Base64;

import util.FileUtil;

public class RSAUtil {

    public RSAUtil() {

    }

    public PrivateKey readPrivateKeyPKCS1PEM(String pemPath) throws Exception {
        //String data = FileUtil.readString("private_key.pem");
        // String data = FileUtil.readString(pemPath);
        String data = pemPath;
        // ���ʿ��� ���� ������ �����մϴ�.
        data = data.replaceAll("\\n","");
	    data = data.replaceAll("-----BEGIN RSA PRIVATE KEY-----", "");
	    data = data.replaceAll("-----END RSA PRIVATE KEY-----", "");
	    //System.out.print(data);
	   // byte[] decoded = Base64.decodeBase64(data);
	    byte[] decoded = Base64.getDecoder().decode(data);
	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
	    KeyFactory factory = KeyFactory.getInstance("RSA");
	    PrivateKey privateKey = factory.generatePrivate(spec);

	    //System.out.println(privateKey);
	    return privateKey;
    }

    public PublicKey importPublicKeyFromPemString(String pemStr) throws Exception {
        pemStr = pemStr.replaceAll("\\n","");
        pemStr = pemStr.replaceAll("-----BEGIN PUBLIC KEY-----", "");
        pemStr = pemStr.replaceAll("-----END PUBLIC KEY-----", "");

        byte[] pemBytes = Base64.getDecoder().decode(pemStr);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(pemBytes);
	    KeyFactory factory = KeyFactory.getInstance("RSA");
	    PublicKey publicKey = factory.generatePublic(spec);

	    return publicKey;
    } 

    public byte[] encryptRSA(byte[] plainText, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

            Cipher cipher = Cipher.getInstance("RSA");

            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            byte[] encrypted = cipher.doFinal(plainText);

            //String encrypted = Base64.getEncoder().encodeToString(bytePlain);

            return encrypted;
    }

    public static byte[] decryptRSA(byte[] encrypted, PrivateKey privateKey)

    throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,

             BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

        Cipher cipher = Cipher.getInstance("RSA");

        //byte[] byteEncrypted = Base64.getDecoder().decode(encrypted.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] bytePlain = cipher.doFinal(encrypted);

        //String decrypted = new String(bytePlain, "utf-8");

        return bytePlain;

    }
}