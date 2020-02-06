

public class ErrorMsg {

    public static void funcErrorMsg() {
        System.out.println("첫 번째 인자에 사용할 기능을 입력해 주세요.");
		System.out.println("==============================================");
		System.out.println("문서 암호화:                    EncryptDoc      - <문서 경로> <복호화에 필요한 sharing part 갯수> <암호화 공개키 리스트>");
		System.out.println("대칭키 sharing part 복호화:     DecryptKeyPart  - <복호화할 sharing part> <개인키 데이터>");
		System.out.println("대칭키 복구 후 문서 복호화:      DecryptDoc      - <암호화된 문서 문자열> <대칭키 복구에 사용할 리스트 길이> [<대칭키 sharing part의 인덱스 리스트> <대칭키를 복구할 sharing part 부분 리스트>]");
    }
} 