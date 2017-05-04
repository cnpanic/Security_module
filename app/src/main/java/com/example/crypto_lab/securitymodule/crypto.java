package com.example.crypto_lab.securitymodule;

import android.util.Log;

import com.example.crypto_lab.securitymodule.sha256;
import com.example.crypto_lab.securitymodule.CRYPTO_SESN;

import java.io.PipedInputStream;
import java.io.UnsupportedEncodingException;
import com.example.crypto_lab.securitymodule.ECBpadding;
import com.example.crypto_lab.securitymodule.present;
//import com.example.crypto_lab.securitymodule.lea;
import com.example.crypto_lab.securitymodule.present;

import static com.example.crypto_lab.securitymodule.crypto.MAC_ALGORITHM.MAC_SHA256;
import static com.example.crypto_lab.securitymodule.crypto.AUTH_ALGORITHM.AUTH_LEA128_ECB_SHA256;
import static com.example.crypto_lab.securitymodule.crypto.AUTH_ALGORITHM.AUTH_PRESENT_ECB_SHA256;
import static com.example.crypto_lab.securitymodule.crypto.CRYPTO_ALGORITHM.CRYPTO_LEA128_ECB;
import static com.example.crypto_lab.securitymodule.crypto.CRYPTO_ALGORITHM.CRYPTO_PRESENT_ECB;
import static com.example.crypto_lab.securitymodule.crypto.CRYPTO_CIPHERMODE.ECB;

/**
 * Created by crypto_lab on 2017-01-25.
 */

public class crypto {


    public enum AUTH_ALGORITHM {AUTH_PRESENT_ECB_SHA256, AUTH_LEA128_ECB_SHA256}

    public enum MAC_ALGORITHM {MAC_SHA256}

    public enum CRYPTO_ALGORITHM {CRYPTO_LEA128_ECB, CRYPTO_LEA192_ECB, CRYPTO_PRESENT_ECB, CRYPTO_LEA256_ECB}

    public enum CRYPTO_CIPHERMODE {ECB}

    public boolean cryptoSupport;
    public CRYPTO_ALGORITHM type;
    public byte[] key;
    public int keyLen;


    public final int AUTH_BOARD_ADDR_LENGTH = 6;
    public final int AUTH_RAND_LENGTH = 15;
    public final int AUTH_SRES_LENGTH = 4;
    public final int AUTH_MSG_LENGTH = (AUTH_BOARD_ADDR_LENGTH + AUTH_RAND_LENGTH);
    public final int MAC_SHA256_BLOCKSIZE = 64;

    public final int HMAC_BLOCKSIZE = 64;

    public final int IPAD = 0x36;
    public final int OPAD = 0x5C;
    public final int CRYPTO_PRESENT_KEYLENGTH = 10;
    public final int CRYPTO_LEA128_KEYLENGTH = 16;
    public final int CRYPTO_LEA192_KEYLENGTH = 24;
    public final int CRYPTO_LEA256_KEYLENGTH = 32;

    public final int CRYPTO_PRESENT_BLOCKSIZE = 8;
    public final int CRYPTO_LEA_BLOCKSIZE = 16;

    public final int CRYPTO_PRESENT_ROUNDS = 31;
    public final int CRYPTO_LEA128_ROUNDS = 24;
    public final int CRYPTO_LEA192_ROUNDS = 28;
    public final int CRYPTO_LEA256_ROUNDS = 32;

    public final int CRYPTO_LEA_ROUNDKEY_LENGTH = 6;


    sha256 SHA256 = new sha256();
    ECBpadding ECBP = new ECBpadding();
    present PRE = new present();






    public MAC_ALGORITHM getMacAlgorithm(AUTH_ALGORITHM type) {
        MAC_ALGORITHM algorithm = null;
        switch (type) {
            case AUTH_PRESENT_ECB_SHA256:
            case AUTH_LEA128_ECB_SHA256:
                algorithm = MAC_SHA256;
                break;
        }

        return algorithm;
    }

    public int getCryptoKeyLength(CRYPTO_ALGORITHM type) {
        int keyLen = 0;

        switch (type) {
            case CRYPTO_PRESENT_ECB:
                keyLen = CRYPTO_PRESENT_KEYLENGTH;
                break;
            case CRYPTO_LEA128_ECB:
                keyLen = CRYPTO_LEA128_KEYLENGTH;
                break;
        }

        return keyLen;
    }


    public int getCryptoBlockSize(CRYPTO_ALGORITHM type) {
        int blockSize = 0;

        switch (type) {
            case CRYPTO_PRESENT_ECB:
                blockSize = CRYPTO_PRESENT_BLOCKSIZE;
                break;
            case CRYPTO_LEA128_ECB:
                blockSize = CRYPTO_LEA_BLOCKSIZE;
                break;
        }

        return blockSize;
    }

    public int getMacAlgorithmBlockSize(MAC_ALGORITHM type) {
        int blockSize = 0;

        switch (type) {
            case MAC_SHA256:
                blockSize = MAC_SHA256_BLOCKSIZE;
                break;
        }
        return blockSize;
    }


    public int getMacAlgorithmMacSize(MAC_ALGORITHM type) {
        int macSize = 0;

        switch (type) {
            case MAC_SHA256:
                macSize = MAC_SHA256_BLOCKSIZE;
                break;
        }
        return macSize;
    }

    public byte[] mac(MAC_ALGORITHM macAlgorithm, byte[] msg, int msgLeng) throws UnsupportedEncodingException {
        String temp = null;
        String text;
        text = null;
        byte[] result = null;
        switch (macAlgorithm) {
            case MAC_SHA256: {


                for (int i = 0; i < msg.length; i++) {
                    temp = Integer.toString(((msg[i] & 0xFF) + 0x100), 16).substring(1);
                    text = text + temp;
                }

                StringBuilder ctx;
                ctx = SHA256.Sha256_E(text);
                result = String.valueOf(ctx).getBytes();

                break;
            }
        }

        return result;
    }


    public byte[] hmac(MAC_ALGORITHM macAlgorithm, byte[] key, byte[] msg, int resultLen) throws UnsupportedEncodingException {

        int i;

        int hmacSumSize = getMacAlgorithmMacSize(macAlgorithm);
        byte[] hmacSum;
        byte[] buffer;
        byte[] result;
        int bufferSize = (msg.length > hmacSumSize) ? msg.length : hmacSumSize;


        for (i = 0; i < key.length; i++) {
            String temp_text = Integer.toString(((key[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("key", temp_text);

        }

        for (i = 0; i < msg.length; i++) {
            String temp_text = Integer.toString(((msg[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("hmac msg", temp_text);
        }

        buffer = new byte[HMAC_BLOCKSIZE + bufferSize];

        for (i = 0; i < HMAC_BLOCKSIZE; i++) {
            buffer[i] = 0x00;
        }


        if (keyLen > HMAC_BLOCKSIZE) {
            buffer = mac(macAlgorithm, msg, msg.length);
        } else {
            for (i = 0; i < key.length; i++) {
                buffer[i] = key[i];
            }
        }

        for (i = 0; i < HMAC_BLOCKSIZE; i++) {
            buffer[i] ^= IPAD;
        }

        for (i = 0; i < msg.length; i++) {
            buffer[i + HMAC_BLOCKSIZE] = msg[i];
        }

        hmacSum = new byte[hmacSumSize];
        hmacSum = mac(macAlgorithm, buffer, HMAC_BLOCKSIZE + msg.length);

        for (i = 0; i < HMAC_BLOCKSIZE; i++) {
            buffer[i] ^= IPAD ^ OPAD;
        }

        for (i = 0; i < hmacSumSize; i++) {
            buffer[i + HMAC_BLOCKSIZE] = hmacSum[i];
        }

        hmacSum = mac(macAlgorithm, buffer, HMAC_BLOCKSIZE + hmacSumSize);

        resultLen = hmacSumSize;//*resultLen = hmacSumSize; ???????????????????

        result = new byte[hmacSum.length];//????????????  내가 추가함

        for (i = 0; i < resultLen; i++) {
            result[i] = hmacSum[i];
        }


        for (i = 0; i < hmacSumSize; i++) {
            String temp_text = Integer.toString(((hmacSum[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("hmac", temp_text);

        }


        return result;
    }


    public CRYPTO_CIPHERMODE getCipherMode(CRYPTO_ALGORITHM type) {
        CRYPTO_CIPHERMODE mode = null;
        switch (type) {
            case CRYPTO_PRESENT_ECB:
                mode = ECB;
                break;
            case CRYPTO_LEA128_ECB:
                mode = ECB;
                break;
        }

        return mode;
    }

    public CRYPTO_ALGORITHM getCryptoAlgorithm(AUTH_ALGORITHM type) {
        CRYPTO_ALGORITHM algorithm = null;
        switch (type) {
            case AUTH_PRESENT_ECB_SHA256:
                algorithm = CRYPTO_PRESENT_ECB;
                break;
            case AUTH_LEA128_ECB_SHA256:
                algorithm = CRYPTO_LEA128_ECB;
                break;
        }

        return algorithm;
    }


    public boolean req_auth(AUTH_ALGORITHM type, byte[] preSharedKey, int preSharedKeyLen, CRYPTO_SESN session) throws UnsupportedEncodingException {
        int i;

        byte[] BD_ADDR = new byte[AUTH_BOARD_ADDR_LENGTH];
        BD_ADDR[0] = 'l';
        BD_ADDR[1] = 'u';
        BD_ADDR[2] = '5';
        BD_ADDR[3] = 'c';
        BD_ADDR[4] = '8';
        BD_ADDR[5] = '7'; //48bits 보드나, 핸드폰의 식별명에서 6bytes 따옴
        byte[] AU_RAND = new byte[AUTH_RAND_LENGTH]; //120bits //검증자에게서 받아옴
        byte[] AU_MSG = new byte[AUTH_RAND_LENGTH];

        for (i = 0; i < AUTH_RAND_LENGTH; i++) {
            AU_RAND[i] = (byte) 0x00;
            AU_MSG[i] = (byte) 0x00;
        }


        byte[] hmacSum;
        MAC_ALGORITHM macType = getMacAlgorithm(type);
        int macSize;

        CRYPTO_ALGORITHM cryptoType = getCryptoAlgorithm(type);

        byte[] SRES = new byte[AUTH_SRES_LENGTH];

        for (i = 0; i < AUTH_SRES_LENGTH; i++) {
            SRES[i] = (byte) 0x00;
        }

        byte[] cipher;
        int cipherLen = 0;

        byte[] decipher;
        int decipherLen = 0;
        byte[] test = new byte[8];
        test[0] = '1';
        test[1] = '2';
        test[2] = '3';
        test[3] = '4';
        test[4] = '5';
        test[5] = '6';
        test[6] = '7';
        test[7] = '8';
        ;
	/* step 1 : sends BD_ADDR */
        while (0 == 0) {
		/* step 2 : sends AU_RAND */
            generateRandNumber(AU_RAND); //발신자가 생성해서 요청자에게 보낸다.//삭제
            if (0 == 0) //AU_RAND를 수신하면
            {
                break;
            }
        } // end step 1

	/* step 3 : Both calculate HMAC */
        hmacSum = new byte[getMacAlgorithmMacSize(macType)];


        for (i = 0; i < AUTH_BOARD_ADDR_LENGTH; i++) {
            AU_MSG[i] = BD_ADDR[i];
        }
        for (i = 0; i < AUTH_RAND_LENGTH; i++) {
            AU_MSG[i + AUTH_BOARD_ADDR_LENGTH] = AU_RAND[i];
        }


        hmacSum = hmac(macType, preSharedKey, AU_MSG, AUTH_MSG_LENGTH);

        for (i = 0; i < AUTH_SRES_LENGTH; i++) {
            SRES[i] = hmacSum[i];
        }

	/* sends E_preSharedKey(AU_MSG + SRES) */
        cipher = new byte[8];

        cipher = crypto_encrypt(cryptoType, preSharedKey, preSharedKeyLen, SRES, AUTH_SRES_LENGTH); //뒤에 함수 추가

        decipher = new byte[8];
        decipher = crypto_decrypt(cryptoType, preSharedKey, preSharedKeyLen, cipher, cipherLen); //뒤에 함수 추가

        for (i = 0; i < decipher.length; i++) {
            String temp_text = Integer.toString(((decipher[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("crypto_decrypt", temp_text);

        }


        while (0 == 0) {
		/* compares */
            byte[] rxSRES = new byte[AUTH_SRES_LENGTH];

            for (i = 0; i < AUTH_SRES_LENGTH; i++) {
                rxSRES[i] = (byte) 0x00;
            }


            for (i = 0; i < AUTH_SRES_LENGTH; i++) {

                rxSRES[i] = decipher[i + (decipher.length - AUTH_SRES_LENGTH)]; //삭제
                rxSRES[i] = SRES[i];//삭제
            }


            boolean temp = macCompare(SRES, rxSRES, AUTH_SRES_LENGTH); //삭제 //발신자가 수신한 HMAC과 직접 계산한 HMAC을 비교함, 동일하면 sends 1, 상이하면 sends 0 //뒤에함수

            if (temp == (0 == 0)) //1이나 0을 수신하면
            {
                break;

            }
        }

	/* step 4 : 알고리즘 저장 및 상위 레이어로 결과 전달 */
        session.cryptoSupport = (0 == 0);
        session.type = cryptoType;
        session.key = new byte[preSharedKeyLen];

        for (i = 0; i < preSharedKeyLen; i++) {
            session.key[i] = hmacSum[i + AUTH_SRES_LENGTH];
        }
        session.keyLen = preSharedKeyLen;

        return (0 == 0);
    }

    public byte[] crypto_decrypt(CRYPTO_ALGORITHM type, byte[] key, int keyLen, byte[] cipher, int cipherLen)
    {

        int block_len = getCryptoBlockSize(type);
        byte[] unPadMsg;
        byte[] decipher;
        int unPadMsgLen = 0;

        unPadMsg = new byte[8];

        switch (type)
        {
            case CRYPTO_PRESENT_ECB:
                unPadMsg = PRE.pre_dec(0, key, cipher);//확인해보고 고치기
                break;

            case CRYPTO_LEA128_ECB:

               // unPadMsg = DEC_LEA(cipher.toString(), key);//확인해보고 고치기
                break;
        }

        //unpadding
        decipher = ECBP.unpad(unPadMsg,block_len);//확인해보고 고치기

        return decipher;

    }

    public byte[] crypto_encrypt(CRYPTO_ALGORITHM type, byte[] key, int keyLen, byte[] msg, int msgLen)
    {
        //*cipher = realloc(*cipher, sizeof(unsigned char) * 100);
        int i;
        int block_len = getCryptoBlockSize(type);
        byte[] padMsg;
        int padMsgLen;
        byte[] cipher;
        padMsg = new byte[8];

        //padding
        padMsg = ECBP.pad(msg, block_len, msg.length);// 나중에 추가
        cipher = new byte[padMsg.length];
        for (i = 0; i < padMsg.length; i++)
        {

            String temp_text = Integer.toString(((padMsg[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("pad msg", temp_text);

        }
        //encryption
        switch (type)
        {
            case CRYPTO_PRESENT_ECB:
                cipher = PRE.pre_enc(0, key, padMsg); //나중에 추가
                break;

            case CRYPTO_LEA128_ECB:
               // cipher = ENC_LEA(padMsg, key); // 나중에 추가
                break;
        }

    return cipher;
    }

   public void generateRandNumber(byte[] andNumber)
    {
        int i;
        byte[] randNumber = new byte[AUTH_RAND_LENGTH];


        for (i = 0; i < AUTH_RAND_LENGTH; i++)
        {
            randNumber[i] = (byte)(Math.random() * 255);;
        }
    }

    public boolean macCompare(byte[] calculatedMac, byte[] receivedMac, int macSize) {
        for (int i = 0; i < macSize; i++)
            calculatedMac[i] = receivedMac[i];

        if (calculatedMac != null) {
            return (0 == 0);
        } else {
            return (0 == 1);
        }
    }

}

