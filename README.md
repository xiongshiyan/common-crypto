##  加密解密模块(crypto)

### 1.Crypto接口

本模块主要定义了`Crypto`接口，抽象了加密和解密。分别有对称加密实现和非对称加密实现，可以有不同的实现算法，所以理论上支持所有的加密解密方式。对于摘要算法，亦可应用该接口，只是不可逆而已。通过`CompositeCrypto`可以轻松实现多层加密解密。Crypto接口的实现有对称实现(AES/DES/...)，非对称实现(RSA...)，摘要实现(MD5/hmac...)。感谢Looly提供的各种算法实现。

```java
/**
 * 加密解密接口，对于MD5，SHA1等摘要算法解密方法直接抛出异常.
 * 如果遇到结果或者入参是byte字节数组类型的，默认就转换为16进制的字符串，为了好统一使用String来表达
 * 加密解密其实更好的是针对byte[]其变种就是inputStream和outputStream，字符串类型的只是一层封装
 * @author 熊诗言
 * @see RadixUtil#toHex(byte[])
 * @see RadixUtil#toBytes(String)
 */
public interface Crypto {
    /**
     * 加密
     * @param src 待加密字节数组
     * @return 加密后的
     */
    byte[] encrypt(byte[] src);

    /**
     * 解密
     * @param src 待解密字节数组
     * @return 加密后的
     */
    byte[] decrypt(byte[] src);

    /**
     * 加密，如果数据量不大，才使用该接口默认的方式，因为它使用了缓冲数组，如果数据量大请自行实现
     * @param in 输入流
     * @param out 输出流
     */
    default void encrypt(InputStream in, OutputStream out){
        try {
//            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            FastByteArrayOutputStream baos = new FastByteArrayOutputStream();
            IoUtil.copy(in,baos);
            byte[] bytes = baos.toByteArray();
            byte[] encrypted = encrypt(bytes);
            out.write(encrypted);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /**
     * 解密，如果数据量不大，才使用该接口默认的方式，因为它使用了缓冲数组，如果数据量大请自行实现
     * @param in 输入流
     * @param out 输出流
     */
    default void decrypt(InputStream in, OutputStream out) {
        try {
            //ByteArrayOutputStream baos = new ByteArrayOutputStream();
            FastByteArrayOutputStream baos = new FastByteArrayOutputStream();
            IoUtil.copy(in,baos);
            byte[] bytes = baos.toByteArray();
            byte[] encrypted = decrypt(bytes);
            out.write(encrypted);
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }
    /**
     * 加密
     * @param src 原字符串
     * @param charset 字符编码
     * @return 加密后的
     */
    default String encrypt(String src,String charset){
        byte[] bytes = src.getBytes(CharsetUtil.charset(charset));
        byte[] encrypted = encrypt(bytes);
        return RadixUtil.toHex(encrypted);
    }

    /**
     * 加密
     * @param src 原字符串
     * @return 加密后的
     */
    default String encrypt(String src){
        byte[] bytes = src.getBytes(CharsetUtil.CHARSET_UTF_8);
        byte[] encrypted = encrypt(bytes);
        return RadixUtil.toHex(encrypted);
    }

    /**
     * 解密
     * @param src 原字符串
     * @return 解密后的
     */
    default String decrypt(String src){
        byte[] bytes = RadixUtil.toBytes(src);
        byte[] decrypted = decrypt(bytes);
        return new String(decrypted);
    }
}
```