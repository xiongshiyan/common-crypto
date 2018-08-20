package top.jfunc.common.crypto.symmetric;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import top.jfunc.common.crypto.Crypto;
import top.jfunc.common.crypto.CryptoException;
import top.jfunc.common.utils.CharsetUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 *  Base64加解密
 *  @author 熊诗言
 */
public class Base64Crypto implements Crypto {
    @Override
    public byte[] encrypt(byte[] src) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            new BASE64Encoder().encode(src,out);
            return out.toByteArray();
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] src) {
        try {
            ByteArrayInputStream in = new ByteArrayInputStream(src);
            return new BASE64Decoder().decodeBuffer(in);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void encrypt(InputStream in, OutputStream out) {
        try {
            new BASE64Encoder().encodeBuffer(in,out);
            //什么区别？new BASE64Encoder().encode(in,out);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void decrypt(InputStream in, OutputStream out) {
        try {
            new BASE64Decoder().decodeBuffer(in,out);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String encrypt(String src, String charset) {
        return new BASE64Encoder().encodeBuffer(src.getBytes(CharsetUtil.charset(charset)) ).trim();
    }

    @Override
    public String encrypt(String src){
        return encrypt(src, CharsetUtil.UTF_8);
    }

    @Override
    public String decrypt(String src, String charset) {
        try {
            return new String(new BASE64Decoder().decodeBuffer(src) , CharsetUtil.charset(charset)).trim();
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String decrypt(String src){
        return decrypt(src, CharsetUtil.UTF_8);
    }
}
