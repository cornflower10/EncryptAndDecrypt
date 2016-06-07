package com.cornflower.encryptanddecrypt;

import java.io.UnsupportedEncodingException;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 对称加密，对称加密称为密钥加密，速度快，但加密和解密的钥匙必须相同，只有通信双方才能知道密钥。
 */
public class AESHelper {

	public static SecretKeySpec getKey(String password)
			throws UnsupportedEncodingException {
		int keyLength = 256;

		byte[] keyBytes = new byte[keyLength / 8];

		// explicitly fill with zeros

		Arrays.fill(keyBytes, (byte) 0x0);

		byte[] passwordBytes = password.getBytes("UTF-8");

		int length = passwordBytes.length < keyBytes.length ? passwordBytes.length
				: keyBytes.length;

		System.arraycopy(passwordBytes, 0, keyBytes, 0, length);

		SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

		return key;

	}

	/**
	 * AES256加密
	 * 
	 * @param content
	 * @param encryptKey
	 * @return
	 * @throws Exception
	 */
	public static byte[] encrypt(byte[] content, String encryptKey)
			throws Exception {
		SecretKeySpec skeySpec = getKey(encryptKey);
		final byte[] iv = new byte[16];
		Arrays.fill(iv, (byte) 0x00);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivParameterSpec);
		return cipher.doFinal(content);
	}

	/**
	 * 解密
	 * @param content
	 * @param encryptKey
	 * @return
	 * @throws Exception
     */
	public static byte[] decrypt(byte[] content, String encryptKey)
			throws Exception {
		SecretKeySpec skeySpec = getKey(encryptKey);
		final byte[] iv = new byte[16];
		Arrays.fill(iv, (byte) 0x00);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivParameterSpec);
		return cipher.doFinal(content);
	}
}
