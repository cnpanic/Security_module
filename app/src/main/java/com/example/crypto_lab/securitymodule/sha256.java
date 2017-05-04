package com.example.crypto_lab.securitymodule;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Created by crypto_lab on 2017-02-01.
 */

public class sha256 {

    String TAG = "SHA256";
    public StringBuilder Sha256_E(String input) throws UnsupportedEncodingException {
        StringBuilder hexSHA256hash = null;
        try {
            MessageDigest mdSHA256 = MessageDigest.getInstance("SHA-256");
            mdSHA256.update(input.getBytes("UTF-8"));

            byte[] sha256Hash = mdSHA256.digest();

            hexSHA256hash = new StringBuilder();
            for (byte b : sha256Hash) {
                String hexString = String.format("%02x", b);
                hexSHA256hash.append(hexString);
            }

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        return hexSHA256hash;
    }
}
