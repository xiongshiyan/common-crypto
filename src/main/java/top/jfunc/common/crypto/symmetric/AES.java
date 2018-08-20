package top.jfunc.common.crypto.symmetric;

import top.jfunc.common.utils.StrUtil;

import javax.crypto.spec.IvParameterSpec;

/**
 * AES加密算法实现<br>
 * 高级加密标准（英语：Advanced Encryption Standard，缩写：AES），在密码学中又称Rijndael加密法
 * 
 * @author Looly
 * @since 3.0.8
 */
public class AES extends SymmetricCrypto {
	
	/**
	 * 构造，默认AES/CBC/PKCS5Padding，使用随机密钥
	 */
	public AES() {
		super(SymmetricAlgorithm.AES);
	}
	
	/**
	 * 构造，使用默认的AES/CBC/PKCS5Padding
	 * @param key 密钥
	 */
	public AES(byte[] key) {
		super(SymmetricAlgorithm.AES, key);
	}
	
	/**
	 * 构造，使用随机密钥
	 * @param mode 模式{@link Mode}
	 * @param padding {@link Padding}补码方式
	 */
	public AES(Mode mode, Padding padding) {
		this(mode.name(), padding.name());
	}
	
	/**
	 * 构造
	 * @param mode 模式{@link Mode}
	 * @param padding {@link Padding}补码方式
	 * @param key 密钥，支持三种密钥长度：128、192、256位
	 */
	public AES(Mode mode, Padding padding, byte[] key) {
		this(mode.name(), padding.name(), key);
	}
	
	/**
	 * 构造
	 * @param mode 模式
	 * @param padding 补码方式
	 */
	public AES(String mode, String padding) {
		this(mode, padding, null);
	}

	/**
	 * 构造
	 * @param mode 模式
	 * @param padding 补码方式
	 * @param key 密钥，支持三种密钥长度：128、192、256位
	 */
	public AES(String mode, String padding, byte[] key) {
		super(StrUtil.format("AES/{}/{}", mode, padding), key);
	}
	
	/**
	 * 设置偏移向量
	 * @param iv {@link IvParameterSpec}偏移向量
	 * @return 自身
	 */
	public AES setIv(IvParameterSpec iv){
		super.setParams(iv);
		return this;
	}

}
