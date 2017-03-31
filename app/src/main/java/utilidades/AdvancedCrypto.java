package utilidades;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/* Fortaleza del AES-128
 *
 * Un billón de ordenadores que pudieran cada uno probar mil millones de claves por segundo,
 * tardarían más de 2.000 millones de años en dar con una del sistema AES-128,
 * y hay que tener en cuenta que las máquinas actuales sólo pueden probar
 * 10 millones de claves por segundo
 *
 */
public class AdvancedCrypto {

    private final int IV_LENGTH = 16;
    private final int PBE_ITERATION_COUNT = 50;
    private final String RANDOM_ALGORITHM = "SHA1PRNG";
    private final String HASH_ALGORITHM = "SHA1"; // SHA-256
    private final String PBE_ALGORITHM = "PBEWithSHAAnd128BitRC2-CBC"; // "PBEWithSHA256And256BitAES-CBC-BC";
    private final String CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";
    private final String SECRET_KEY_ALGORITHM = "AES";
    private final Provider PROVIDER = new org.bouncycastle.jce.provider.BouncyCastleProvider();

    private static AdvancedCrypto instance;

    public static AdvancedCrypto getInstance() {
        if (instance == null) {
            instance = new AdvancedCrypto();
        }
        return instance;
    }

    private AdvancedCrypto() {
        //Security.addProvider(new org.bouncycastle.jce.PROVIDER.BouncyCastleProvider());
    }


    private String toHex(byte b[]) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            String plainText = Integer.toHexString(0xff & b[i]);
            if (plainText.length() < 2) {
                plainText = "0" + plainText;
            }
            hexString.append(plainText);
        }
        return hexString.toString();
    }

    private byte[] toBytes(String ss) {
        byte digest[] = new byte[ss.length() / 2];
        for (int i = 0; i < digest.length; i++) {
            String byteString = ss.substring(2 * i, 2 * i + 2);
            int byteValue = Integer.parseInt(byteString, 16);
            digest[i] = (byte) byteValue;
        }
        return digest;
    }

    public String encrypt(SecretKey secret, String cleartext) throws Exception {
        try {

            byte[] iv = generateIv();
            String ivHex = toHex(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);

            Cipher encryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, secret, ivspec);
            byte[] encryptedText = encryptionCipher.doFinal(cleartext.getBytes("UTF-8"));
            String encryptedHex = toHex(encryptedText);

            return ivHex + encryptedHex;

        } catch (Exception e) {
            throw new Exception("ERROR Encriptar", e);
        }
    }

    public String decrypt(SecretKey secret, String encrypted) throws Exception {
        try {
            Cipher decryptionCipher = Cipher.getInstance(CIPHER_ALGORITHM, PROVIDER);
            String ivHex = encrypted.substring(0, IV_LENGTH * 2);
            String encryptedHex = encrypted.substring(IV_LENGTH * 2);
            IvParameterSpec ivspec = new IvParameterSpec(toBytes(ivHex));
            decryptionCipher.init(Cipher.DECRYPT_MODE, secret, ivspec);
            byte[] decryptedText = decryptionCipher.doFinal(toBytes(encryptedHex));
            String decrypted = new String(decryptedText, "UTF-8");
            return decrypted;
        } catch (Exception e) {
            throw new Exception("ERROR Desencriptar", e);
        }
    }

    public SecretKeySpec getSecretKey(String password, String salt) throws Exception {
        try {
            PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray(), toBytes(salt), PBE_ITERATION_COUNT, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBE_ALGORITHM, PROVIDER);
            SecretKey tmpKey = factory.generateSecret(pbeKeySpec);
            return new SecretKeySpec(tmpKey.getEncoded(), SECRET_KEY_ALGORITHM);
        } catch (Exception e) {
            throw new Exception("ERROR al tomar llave", e);
        }
    }

    protected String getHash(String password, String salt) throws Exception {
        try {
            String input = password + salt;
            MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM, PROVIDER);
            byte[] out = md.digest(input.getBytes("UTF-8"));
            return toHex(out);
        } catch (Exception e) {
            throw new Exception("ERROR al hacer hash", e);
        }
    }

    private static String reves(String objeto) {
        StringBuffer sb = new StringBuffer(objeto);
        return sb.reverse().toString();
    }

    public String generateSalt(String salt) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        try {
            //SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
            //byte[] salt1 = new byte[SALT_LENGTH];
            //random.nextBytes(salt1);
            md5.update(getHash(reves(salt), salt).getBytes());
            sha1.update(salt.getBytes());

            md5.update( (md5.toString()+sha1.toString()).getBytes()  );

            String saltHex = toHex(md5.digest());
            //String saltHex = toHex(salt1);
            return saltHex;
        } catch (Exception e) {
            throw new Exception("ERROR al generar salt", e);
        }
    }

    private byte[] generateIv() throws NoSuchAlgorithmException, NoSuchProviderException {
        SecureRandom random = SecureRandom.getInstance(RANDOM_ALGORITHM);
        byte[] iv = new byte[IV_LENGTH];
        random.nextBytes(iv);
        return iv;
    }




}
