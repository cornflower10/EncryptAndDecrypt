package com.cornflower.encryptanddecrypt.RSA;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Cipher;

/**
 * 支持加密字符串过长导致加密解密失败的问题
 * @author xiejingbao
 *
 */

public abstract class RSACoder extends Coder {
	private static final String KEY_ALGORITHM_RSA = "RSA";
	private static final String SIGNATURE_ALGORITHM = "MD5withRSA";
	
	private static final String PADDING = "RSA/ECB/PKCS1Padding"; //私钥加密, 公钥解密
	private static final String PADDINGEx = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"; //公钥加密, 私钥解密
	
	private static final String PUBLIC_KEY = "RSAPublicKey";
	private static final String PRIVATE_KEY = "RSAPrivateKey";

	/**
	 * 用私钥对信息生成数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param privateKey
	 *            私钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {

		// 构造PKCS8EncodedKeySpec对象
		PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);

		// KEY_ALGORITHM_RSA 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);

		// 取私钥匙对象
		PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);

		// 用私钥对信息生成数字签名
		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initSign(priKey);
		signature.update(data);

		return signature.sign();
	}

	/**
	 * 校验数字签名
	 * 
	 * @param data
	 *            加密数据
	 * @param publicKey
	 *            公钥
	 * @param sign
	 *            数字签名
	 * 
	 * @return 校验成功返回true 失败返回false
	 * @throws Exception
	 * 
	 */
	public static boolean verify(byte[] data, byte[] publicKey, byte[] sign)
			throws Exception {

		// 构造X509EncodedKeySpec对象
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);

		// KEY_ALGORITHM_RSA 指定的加密算法
		KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);

		// 取公钥匙对象
		PublicKey pubKey = keyFactory.generatePublic(keySpec);

		Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
		signature.initVerify(pubKey);
		signature.update(data);

		// 验证签名是否正常
		return signature.verify(sign);
	}

	/**
	 * 解密<br>
	 * 用私钥解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPrivateKey(byte[] data, String key)
			throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		return decryptByPrivateKey(data, keyBytes);
	}
	
	public static byte[] decryptByPrivateKey(byte[] data, byte[] keyBytes)
            throws Exception {

        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(PADDINGEx);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        
        int blockSize = cipher.getBlockSize();
        
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for(int i = 0; i < data.length; i += blockSize)
        {
            int inputLen;
            if (i + blockSize > data.length)
            {
                inputLen = data.length - i;
            }
            else
            {
                inputLen = blockSize;
            }
            os.write(cipher.doFinal(data, i, inputLen)); 
        }
        os.close();
        return os.toByteArray();
    }

	/**
	 * 解密<br>
	 * 用公钥解密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] decryptByPublicKey(byte[] data, String key)
			throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		return decryptByPublicKey(data, keyBytes);
	}
	
	public static byte[] decryptByPublicKey(byte[] data, byte[] keyBytes)
            throws Exception {
        
        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        
        int blockSize = cipher.getBlockSize();
        
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for(int i = 0; i < data.length; i += blockSize)
        {
            int inputLen;
            if (i + blockSize > data.length)
            {
                inputLen = data.length - i;
            }
            else
            {
                inputLen = blockSize;
            }
            os.write(cipher.doFinal(data, i, inputLen)); 
        }
        os.close();
        return os.toByteArray();
    }

	/**
	 * 加密<br>
	 * 用公钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPublicKey(byte[] data, String key)
			throws Exception {
		// 对公钥解密
		byte[] keyBytes = decryptBASE64(key);

		return encryptByPublicKey(data, keyBytes);
	}
	
	public static byte[] encryptByPublicKey(byte[] data, byte[] keyBytes)
            throws Exception {

        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据加密

        Cipher cipher = Cipher.getInstance(PADDINGEx);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        
        int blockSize = cipher.getBlockSize();
        
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for(int i = 0; i < data.length; i += blockSize)
        {
            int inputLen;
            if (i + blockSize > data.length)
            {
                inputLen = data.length - i;
            }
            else
            {
                inputLen = blockSize;
            }
            os.write(cipher.doFinal(data, i, inputLen)); 
        }
        os.close();
        return os.toByteArray();
    }

	/**
	 * 加密<br>
	 * 用私钥加密
	 * 
	 * @param data
	 * @param key
	 * @return
	 * @throws Exception
	 */
	public static byte[] encryptByPrivateKey(byte[] data, String key)
			throws Exception {
		// 对密钥解密
		byte[] keyBytes = decryptBASE64(key);

		return encryptByPrivateKey(data, keyBytes);
	}
	
	public static byte[] encryptByPrivateKey(byte[] data, byte[] keyBytes)
            throws Exception {
        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM_RSA);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        
        int blockSize = cipher.getBlockSize();
        
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        for(int i = 0; i < data.length; i += blockSize)
        {
            int inputLen;
            if (i + blockSize > data.length - i)
            {
                inputLen = data.length - i;
            }
            else
            {
                inputLen = blockSize;
            }
            os.write(cipher.doFinal(data, i, inputLen)); 
        }
        os.close();
        return os.toByteArray();
    }

	/**
	 * 取得私钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	
	public static byte[] getPrivateKey(Map<String, Object> keyMap)
            throws Exception {
        RSAPrivateKey  key = (RSAPrivateKey ) keyMap.get(PRIVATE_KEY);
        return key.getEncoded();
    }

	/**
	 * 取得公钥
	 * 
	 * @param keyMap
	 * @return
	 * @throws Exception
	 */
	
	public static byte[] getPublicKey(Map<String, Object> keyMap)
            throws Exception {
        RSAPublicKey key = (RSAPublicKey) keyMap.get(PUBLIC_KEY);
        return key.getEncoded();
    }
	
	public static String printByte(byte[] data)
	{
	    String printStr = new String();
	    for (byte b : data)
        {
            String hex = Integer.toHexString(b & 0xFF);
            if (hex.length() == 1)
            {
                hex = '0' + hex;
            }
            printStr += hex.toUpperCase();
        }
        return printStr;
	}

	/**
	 * 初始化密钥
	 * 
	 * @return
	 * @throws Exception
	 */
	public static Map<String, Object> initKey(int keysize) throws Exception {
	    
		KeyPairGenerator keyPairGen = KeyPairGenerator
				.getInstance(KEY_ALGORITHM_RSA);
		SecureRandom random = new SecureRandom();
		byte bytes[] = new byte[10];
		random.nextBytes(bytes);
		keyPairGen.initialize(keysize, random);

		KeyPair keyPair = keyPairGen.generateKeyPair();

		// 公钥
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

		// 私钥
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

		Map<String, Object> keyMap = new HashMap<String, Object>(2);

		keyMap.put(PUBLIC_KEY, publicKey);
		keyMap.put(PRIVATE_KEY, privateKey);
		return keyMap;
	}
}
