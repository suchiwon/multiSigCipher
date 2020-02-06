package util;

import java.util.Base64;

public class EncodeUtil {

    public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;
	}
	
	
	public static String byteArrayToHexString(byte[] bytes){ 
		
		StringBuilder sb = new StringBuilder(); 
		
		for(byte b : bytes){ 
			
			sb.append(String.format("%02X", b&0xff)); 
		} 
		
		return sb.toString(); 
	} 

}