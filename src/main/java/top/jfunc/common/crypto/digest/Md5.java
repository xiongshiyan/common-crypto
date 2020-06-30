package top.jfunc.common.crypto.digest;

import top.jfunc.common.crypto.Crypto;
import top.jfunc.common.crypto.CryptoException;

import java.security.MessageDigest;

/**
 * MD5摘要
 * @author 熊诗言
 */
public class Md5 extends AbstractDigestCrypto implements Crypto {
    @Override
    public byte[] encrypt(byte[] src) {
        try {
            MessageDigest md5 = MessageDigest.getInstance("MD5");
            return md5.digest(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
}
