package com.cornflower.encryptanddecrypt.RSA;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class RSACoderTest {

	public static void main() throws Exception {
		byte[] publicKey;
		byte[] privateKey;
		Map<String, Object> keyMap = RSACoder.initKey(4096);

		Date date = new Date(); 
		SimpleDateFormat dateFormat = new SimpleDateFormat("HHmmssSSS");

		System.out.println("产生密钥对开始：" + dateFormat.format(date));

		publicKey = RSACoder.getPublicKey(keyMap);
		privateKey = RSACoder.getPrivateKey(keyMap);

		date = new Date(); 
		dateFormat = new SimpleDateFormat("HHmmssSSS");
		System.out.println("产生密钥对结束：" + dateFormat.format(date));

		System.out.println("公钥: \n\r" + publicKey);
		System.out.println("私钥： \n\r" + privateKey);

		String inputStr = "hello wengchao!";

		byte[] data = inputStr.getBytes();

		date = new Date(); 
		dateFormat = new SimpleDateFormat("HHmmssSSS");
		System.out.println("公钥加密开始：" + dateFormat.format(date));

		byte[] encodedData = RSACoder.encryptByPublicKey(data, publicKey);
		String encodedStr = new String(encodedData);
		System.out.println("密文：" + encodedStr);

		date = new Date(); 
		dateFormat = new SimpleDateFormat("HHmmssSSS");
		System.out.println("公钥加密结束：" + dateFormat.format(date));

		date = new Date(); 
		dateFormat = new SimpleDateFormat("HHmmssSSS");
		System.out.println("私钥解密开始：" + dateFormat.format(date));

		byte[] decodedData = RSACoder.decryptByPrivateKey(encodedData,
				privateKey);
		date = new Date(); 
		dateFormat = new SimpleDateFormat("HHmmssSSS");
		System.out.println("解密开始：" + dateFormat.format(date));
		String outputStr = new String(decodedData);
		System.err.println("加密前: " + inputStr + "\n\r" + "解密后: " + outputStr);
		// assertEquals(inputStr, outputStr);`
	}
}
