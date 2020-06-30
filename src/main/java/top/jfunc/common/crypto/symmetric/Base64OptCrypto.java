package top.jfunc.common.crypto.symmetric;

import top.jfunc.common.crypto.Crypto;
import top.jfunc.common.crypto.CryptoException;
import top.jfunc.common.utils.CharsetUtil;
import top.jfunc.common.utils.IoUtil;

import java.io.InputStream;
import java.io.OutputStream;

/**
 *  Base64加解密
 *  1、支持URL SAFE +/ --> -_
 *  2、多行，Base64一般76个字符就换行
 *  @author 熊诗言
 */
public class Base64OptCrypto implements Crypto {

    /**
     * 如果isMultiLine为<code>true</code>，则每76个字符一个换行符，否则在一行显示
     */
    private boolean isMultiLine = false;
    /**
     * 是否使用URL安全字符
     */
    private boolean isUrlSafe = false;

    public Base64OptCrypto() {
    }

    public Base64OptCrypto(boolean isMultiLine, boolean isUrlSafe) {
        this.isMultiLine = isMultiLine;
        this.isUrlSafe = isUrlSafe;
    }

    @Override
    public byte[] encrypt(byte[] src) {
        try {
            return top.jfunc.common.crypto.symmetric.Base64.encode(src, isMultiLine, isUrlSafe);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] decrypt(byte[] src) {
        try {
            return top.jfunc.common.crypto.symmetric.Base64.decode(src);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void encrypt(InputStream in, OutputStream out) {
        try {
            byte[] bytes = IoUtil.stream2Bytes(in);
            byte[] encode = top.jfunc.common.crypto.symmetric.Base64.encode(bytes, isMultiLine, isUrlSafe);
            out.write(encode);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void decrypt(InputStream in, OutputStream out) {
        try {
            byte[] bytes = IoUtil.stream2Bytes(in);
            byte[] decode = top.jfunc.common.crypto.symmetric.Base64.decode(bytes);
            out.write(decode);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public String encrypt(String src, String charset) {
        byte[] bytes = src.getBytes(CharsetUtil.charset(charset));
        return new String(encrypt(bytes));
    }

    @Override
    public String encrypt(String src){
        return encrypt(src, CharsetUtil.UTF_8);
    }

    @Override
    public String decrypt(String src, String charset) {
        byte[] decode = decrypt(src.getBytes());
        return new String(decode , CharsetUtil.charset(charset));
    }

    @Override
    public String decrypt(String src){
        return decrypt(src, CharsetUtil.UTF_8);
    }
}
