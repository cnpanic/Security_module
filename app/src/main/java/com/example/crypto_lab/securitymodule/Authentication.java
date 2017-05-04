package com.example.crypto_lab.securitymodule;

/**
 * Created by crypto_lab on 2017-01-24.
 */

import android.util.Log;

import com.example.crypto_lab.securitymodule.crypto;

import java.io.UnsupportedEncodingException;

import static com.example.crypto_lab.securitymodule.crypto.AUTH_ALGORITHM.AUTH_LEA128_ECB_SHA256;


public class Authentication
{
    public void Auth() throws UnsupportedEncodingException {
        int i;

        crypto C = new crypto();

        //AUTH_ALGORITHM preAuthType = AUTH_PRESENT_ECB_SHA256;
        //unsigned char preKey[CRYPTO_PRESENT_KEYLENGTH] = { 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a' }; //pre shared key = link key

        crypto.AUTH_ALGORITHM preAuthType = AUTH_LEA128_ECB_SHA256;
        byte[] preKey = new byte[C.CRYPTO_LEA128_KEYLENGTH];
        preKey[0] = '0';
        preKey[1] = '1';
        preKey[2] = '2';
        preKey[3] = '3';
        preKey[4] = '4';
        preKey[5] = '5';
        preKey[6] = '6';
        preKey[7] = '7';
        preKey[8] = '8';
        preKey[9] = '9';
        preKey[10] = '0';
        preKey[11] = '1';
        preKey[12] = '2';
        preKey[13] = '3';
        preKey[14] = '4';
        preKey[15] = '5';


        CRYPTO_SESN sens = new CRYPTO_SESN();

        sens.key = new byte[8];

        sens.cryptoSupport = (0 == 1);

        String temp;

        C.req_auth(preAuthType, preKey, C.getCryptoKeyLength(C.getCryptoAlgorithm(preAuthType)), sens);//?


        for (i = 0; i < sens.keyLen; i++) {

                temp = Integer.toString(((sens.key[i] & 0xFF) + 0x100), 16).substring(1);
                  if (BuildConfig.DEBUG) Log.d("session key", temp);
        }

    }

}
