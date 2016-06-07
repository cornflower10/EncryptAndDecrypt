package com.cornflower.encryptanddecrypt;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * 不可逆加密，在相同的硬件上，SHA-1的运行速度比MD5慢，安全性高
 */
public class Sha256 {
    /**
     * 加密
     *
     * @param bt
     * @return
     */
    public static byte[] Encrypt(byte[] bt) {
        MessageDigest md = null;
        byte[] strDes = null;
        try {
            String encName = "SHA-256";
            md = MessageDigest.getInstance(encName);
            md.update(bt);
            strDes = md.digest(); // to HexString
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return strDes;
    }


    public static String bytes2Hex(byte[] bts) {
        String des = "";
        String tmp = null;
        for (int i = 0; i < bts.length; i++) {
            tmp = (Integer.toHexString(bts[i] & 0xFF));
            if (tmp.length() == 1) {
                des += "0";
            }
            des += tmp;
        }
        return des;
    }
}


