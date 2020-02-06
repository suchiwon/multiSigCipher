package encrypt;
 
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
 
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;

import java.security.SecureRandom;
 
import org.apache.commons.codec.binary.Base64;
import util.EncodeUtil;
 
/*
Copyright 회사명 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
 
public class AES256Util {
    private byte[] ivBytes;
    private Key keySpec;
    
    public AES256Util() throws UnsupportedEncodingException,
                                NoSuchAlgorithmException {

        Key key;
        SecureRandom rand = new SecureRandom();
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, rand);
        key = generator.generateKey();
        
        this.keySpec = key;
        byte[] _ivBytes = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    
        this.ivBytes = _ivBytes;
    }

    public void SetAesKey(String aesKey) throws Exception {
        byte[] aesKeyBytes = Base64.decodeBase64(aesKey.getBytes("UTF-8"));

        Key skey = new SecretKeySpec(aesKeyBytes, "AES");

        this.keySpec = skey;
    }

    public String getEncodedKey() throws Exception {
        String encoded = new String(Base64.encodeBase64(this.keySpec.getEncoded()), "UTF-8");

        return encoded;
    }
    
 
    // 암호화
    public String aesEncode(byte[] str) throws java.io.UnsupportedEncodingException, 
                                                    NoSuchAlgorithmException, 
                                                    NoSuchPaddingException, 
                                                    InvalidKeyException, 
                                                    InvalidAlgorithmParameterException, 
                                                    IllegalBlockSizeException, 
                                                    BadPaddingException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, this.keySpec, new IvParameterSpec(this.ivBytes));
 
        byte[] encrypted = c.doFinal(str);
        String enStr = new String(Base64.encodeBase64(encrypted));
 
        return enStr;
    }
 
    //복호화
    public String aesDecode(byte[] str) throws java.io.UnsupportedEncodingException,
                                                        NoSuchAlgorithmException,
                                                        NoSuchPaddingException, 
                                                        InvalidKeyException, 
                                                        InvalidAlgorithmParameterException,
                                                        IllegalBlockSizeException, 
                                                        BadPaddingException {
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, this.keySpec, new IvParameterSpec(this.ivBytes));
 
        byte[] byteStr = Base64.decodeBase64(str);
 
        return new String(c.doFinal(byteStr),"UTF-8");
    }
 
}