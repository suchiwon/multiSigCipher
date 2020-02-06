package util;

import java.io.UnsupportedEncodingException;
import java.io.FileNotFoundException;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

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
import java.security.InvalidKeyException;
import java.security.KeyFactory;

import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import encrypt.AES256Util;
import encrypt.RSAUtil;
import encrypt.Secp256k1Util;

import multisig.SecretSharing;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.util.Map;
import java.util.HashMap;
import java.util.ArrayList;

public class CipherUtil {

    private AES256Util aes256Util;
    private RSAUtil rsaUtil;
    private Secp256k1Util secp256k1Util;

    private SecretSharing secretSharing;

    public CipherUtil() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        this.aes256Util = new AES256Util();
        this.rsaUtil = new RSAUtil();
        this.secp256k1Util = new Secp256k1Util();

        this.secretSharing = new SecretSharing();
    }

    public String encryptDocument(String plain) throws Exception {

        String encrypted = this.aes256Util.aesEncode(plain.getBytes("UTF-8"));

        return encrypted;
    }

    public String decryptDocument(byte[] encrypted) {
        try {
            String decrypted = this.aes256Util.aesDecode(encrypted);

            return decrypted;
        } catch(Exception e) {
            return e.getMessage();
        }
    }

    public void setAESSecretKey(String aesKey) throws Exception {

        this.aes256Util.SetAesKey(aesKey);
    }

    public String getAESSecretKey() throws Exception {

        return this.aes256Util.getEncodedKey();
    }

    public Map<Integer, byte[]> splitAESSecretKey(int n, int m, ArrayList<String> pubKeyList) throws Exception {
        String aesKey = this.getAESSecretKey();

        Map<Integer, byte[]> parts = this.secretSharing.splitSecret(aesKey, n, m);

        Map<Integer, byte[]> encryptedParts = new HashMap<Integer, byte[]>();

        int idx = 0;

        for ( Integer key : parts.keySet()) {

            byte[] encPart = this.encryptAESKeyPart(parts.get(key), pubKeyList.get(idx++));
            encryptedParts.put(key, encPart);
        }

        return encryptedParts;
    }

    public String recoverAESSecretKey(Map<Integer, byte[]> recoverParts, int n, int m) throws Exception {
        String aesKey = this.secretSharing.recoverSecret(recoverParts, n, m);

        return aesKey;
    }

    public byte[] encryptAESKey(String pubKeyStr) throws Exception {
        String aesKey = this.getAESSecretKey();

        PublicKey pubKey = this.rsaUtil.importPublicKeyFromPemString(pubKeyStr);

        byte[] encKey = this.rsaUtil.encryptRSA(aesKey.getBytes("UTF-8"), pubKey);

        return encKey;
    }

    public byte[] encryptAESKeyPart(byte[] aesKeyPart, String pubKeyStr) throws Exception {
        PublicKey pubKey = this.rsaUtil.importPublicKeyFromPemString(pubKeyStr);

        byte[] encKey = this.rsaUtil.encryptRSA(aesKeyPart, pubKey);

        return encKey;
    }

    public String decryptAESKey(byte[] encryptedKey) throws Exception {
        PrivateKey privKey = this.rsaUtil.readPrivateKeyPKCS1PEM("private_key.pem");

        byte[] aesKey = this.rsaUtil.decryptRSA(encryptedKey, privKey);

        return new String(aesKey, "UTF-8");
    }

    public byte[] decryptAESKeyPart(byte[] encryptedPart, String pemPath) throws Exception {
        PrivateKey privKey = this.rsaUtil.readPrivateKeyPKCS1PEM(pemPath);

        byte[] aesKeyPart = this.rsaUtil.decryptRSA(encryptedPart, privKey);

        return aesKeyPart;
    }

    public KeyPair generateECCKeyPair() throws Exception {
        return this.secp256k1Util.generateKeyPair();
    }

    public PublicKey getECCPublicKey() throws Exception {
        return this.secp256k1Util.getPublicKey();
    }

    public PrivateKey getECCPrivateKey() throws Exception {
        return this.secp256k1Util.getPrivateKey();
    }

}

