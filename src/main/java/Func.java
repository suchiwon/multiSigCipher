import util.*;
import java.util.ArrayList;
import java.util.Map;
import java.util.HashMap;

public class Func {

    private CipherUtil cipherUtil;

    public Func() throws Exception {
        this.cipherUtil = new CipherUtil();
    }

    public String EncryptDocument(String[] args) throws Exception {
        
        if (args.length < 4) {
            throw new Exception("encryptDoc 기능은 인자가 <문서 내용> <복호화에 필요한 sharing part 갯수> <암호화 공개키 리스트> 가 필요합니다.");
        }

        String documentPath = args[1];

        String requiredPartNumStr = args[2];

        int requiredPartNum = Integer.parseInt(requiredPartNumStr);

        ArrayList<String> pubKeyStrList = new ArrayList<String>();

        for (int i = 3; i < args.length; i++) {
            pubKeyStrList.add(args[i]);
        }

        if (requiredPartNum < 1 && requiredPartNum > pubKeyStrList.size()) {
            throw new Exception("복호화에 필요한 sharing part 갯수는 암호화 공개키 리스트의 갯수 이하의 수를 가져야 합니다.");
        }

        ArrayList<String> encInfo = new ArrayList<String>();

        //String docStr = FileUtil.readString(documentPath);
        String docStr = documentPath;

        String encDoc = cipherUtil.encryptDocument(docStr);

        encInfo.add(encDoc);

        Map<Integer, byte[]> keyPartList = cipherUtil.splitAESSecretKey(requiredPartNum, pubKeyStrList.size(), pubKeyStrList);

        for (Integer key : keyPartList.keySet()) {
            encInfo.add(EncodeUtil.byteArrayToHexString(keyPartList.get(key)));
        }

        StringBuilder sb = new StringBuilder();

        for (String s : encInfo) {
            sb.append(s);
            sb.append(",");
        }

        return sb.toString();
    }

    public String DecryptKeyPart(String[] args) throws Exception {
        if (args.length != 3) {
            throw new Exception("decryptKeyPart 기능은 인자가 <복호화할 sharing part> <개인키 데이터> 가 필요합니다.");
        }

        String encKeyPart = args[1];

        String pemPath = args[2];

        byte[] encKeyPartBytes = EncodeUtil.hexStringToByteArray(encKeyPart);

        byte[] decryptedKeyPart = cipherUtil.decryptAESKeyPart(encKeyPartBytes, pemPath);

        return EncodeUtil.byteArrayToHexString(decryptedKeyPart);
    }

    public String DecryptDoc(String[] args) throws Exception {
        if (args.length < 5) {
            throw new Exception("DecryptDoc 기능은 인자가 <암호화된 문서 문자열> <대칭키 복구에 사용할 리스트 길이> [<대칭키 sharing part의 인덱스 리스트> <대칭키를 복구할 sharing part 부분 리스트>] 가 필요합니다.");
        }

        String encDoc = args[1];

        byte[] encDocBytes = encDoc.getBytes("UTF-8");

        String partNumStr = args[2];

        int partNum = Integer.parseInt(partNumStr);

        Map<Integer, byte[]> recoverKeyParts = new HashMap<Integer, byte[]>();

        for (int i = 3; i < args.length; i += 2) {
            int partIndex = Integer.parseInt(args[i]);
            recoverKeyParts.put(partIndex, EncodeUtil.hexStringToByteArray(args[i+1]));
        }

        String aesKey = cipherUtil.recoverAESSecretKey(recoverKeyParts, recoverKeyParts.size(), recoverKeyParts.size());

        cipherUtil.setAESSecretKey(aesKey);

        String docStr = cipherUtil.decryptDocument(encDocBytes);

        return docStr;
    }
}