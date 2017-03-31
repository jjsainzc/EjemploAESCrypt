package utilidades;

import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/*
 * DES fortaleza
 * En general, DES utiliza una clave simétrica de 64 bits, 
 * de los cuales 56 son usados para la encriptación, mientras que los 8 restantes son de paridad, 
 * y se usan para la detección de errores en el proceso.
 * 
 * Como la clave efectiva es de 56 bits, 
 * son posible un total de 2 elevado a 56 = 72.057.594.037.927.936 claves posibles, 
 * es decir, unos 72.000 billones de claves, 
 * por lo que la ruptura del sistema por fuerza bruta o diccionario es sumamente improbable, 
 * aunque no imposible si se dispone de suerte y una gran potencia de cálculo.
 */



public class EncryptUserName {

    private static Logger log = Logger.getLogger(EncryptUserName.class.getName());
    private final static String SEPARADOR = ":";
    private static String key = "A3$g6T-*u4";



    private static String invertidor(String invertirTexto) {
        char[] inverted = invertirTexto.toCharArray();

        for (int i = 0; i < invertirTexto.length(); i++) {
            if (invertirTexto.codePointAt(i) >= 65 && invertirTexto.codePointAt(i) <= 90) {
                inverted[i] = Character.toLowerCase(inverted[i]);
            } else {
                if (invertirTexto.codePointAt(i) >= 97 && invertirTexto.codePointAt(i) <= 122) {
                    inverted[i] = Character.toUpperCase(inverted[i]);
                }
            }
        }
        return String.valueOf(inverted);
    }

    private static String reves(String objeto) {
        StringBuffer sb = new StringBuffer(objeto);
        return sb.reverse().toString();
    }

    private static String mix2Str(String s1, String s2) {
        StringBuilder sb = new StringBuilder();

        s1 = reves(s1);
        s2 = reves(invertidor(s2));

        int min = (s1.length() < s2.length()) ? s1.length() : s2.length();

        for (int i = 0; i < min; i++) {
            sb.append(s1.charAt(i) );
            sb.append(s2.charAt(i));
        }
        String res = sb.toString();

        return (res.length() > 8) ? res.substring(1, 8) : res;
    }

    private static String decrypt(String message) throws Exception {
        byte[] bytesrc = convertHexString(message);
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes("UTF-8"));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        IvParameterSpec iv = new IvParameterSpec(key.getBytes("UTF-8"));

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] retByte = cipher.doFinal(bytesrc);
        return new String(retByte);
    }

    private static String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
        DESKeySpec desKeySpec = new DESKeySpec(key.getBytes("UTF-8"));
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
        IvParameterSpec iv = new IvParameterSpec(key.getBytes("UTF-8"));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        return toHexString(cipher.doFinal(message.getBytes("UTF-8")));
    }

    private static byte[] convertHexString(String ss) {
        byte digest[] = new byte[ss.length() / 2];
        for (int i = 0; i < digest.length; i++) {
            String byteString = ss.substring(2 * i, 2 * i + 2);
            int byteValue = Integer.parseInt(byteString, 16);
            digest[i] = (byte) byteValue;
        }
        return digest;
    }

    private static String toHexString(byte b[]) {
        StringBuffer hexString = new StringBuffer();
        for (int i = 0; i < b.length; i++) {
            String plainText = Integer.toHexString(0xff & b[i]);
            if (plainText.length() < 2) {
                plainText = "0" + plainText;
            }
            hexString.append(plainText);
        }
        return hexString.toString();
    }

    public static Boolean validAccount(String cry, String username, String password) {
        key = mix2Str(username, password);
        String[] dec = decodeAccount(cry);
        return dec[0].equals(username) && dec[1].equals(password);
    }

    private static String[] decodeAccount(String cookieValue) {
        try {
            String origi = decrypt(cookieValue);
            String[] parts = origi.split(SEPARADOR);
            if (parts.length == 2 && !parts[0].equals("") && !parts[1].equals("")) {
                return parts;
            }
        } catch (Exception e) {
            e.printStackTrace();
            log.warning(e.getMessage());
        }
        return null;
    }

    public static String encodeAccount(String username, String password) {
        String encryptString = null;
        key = mix2Str(username, password);
        try {
            encryptString = encrypt(username + SEPARADOR + password);
        } catch (Exception e) {
            log.warning(e.getMessage());
        }
        return encryptString;
    }

    public static void main(String[] args) {

    }
}