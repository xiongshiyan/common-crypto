package top.jfunc.common.crypto.symmetric;

import top.jfunc.common.crypto.CryptoException;
import top.jfunc.common.crypto.KeyCrypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * DES加解密
 * @author 熊诗言
 */
public class DesCrypto implements KeyCrypto {
    private static final String ENCODING = "ASCII";
    private String key;
    public DesCrypto(String key){this.key = key;}
    public DesCrypto(){}

    @Override
    public KeyCrypto setKey(String key) {
        this.key = key;
        return this;
    }

    @Override
    public byte[] encrypt(byte[] src){
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(ENCODING));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
            IvParameterSpec iv = new IvParameterSpec(key.getBytes(ENCODING));
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
            return cipher.doFinal(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] src) {
        try {
            Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
            DESKeySpec desKeySpec = new DESKeySpec(key.getBytes(ENCODING));
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            SecretKey secretKey = keyFactory.generateSecret(desKeySpec);
            IvParameterSpec iv = new IvParameterSpec(key.getBytes(ENCODING));
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            return cipher.doFinal(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
