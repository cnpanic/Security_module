package com.example.crypto_lab.securitymodule;

/**
 * Created by crypto_lab on 2017-01-24.
 */

import android.util.Log;
import com.example.crypto_lab.securitymodule.ECBpadding;

/**
 * Created by crypto_lab on 2017-01-19.
 */

public class present {
    String TAG = "PRESENT";
    private byte round_key[][] = new byte[32][10];

    private byte sbox[] = {(byte) 0xC0, (byte) 0x50, (byte) 0x60, (byte) 0xB0, (byte) 0x90, (byte) 0x00, (byte) 0xA0, (byte) 0xD0, (byte) 0x30, (byte) 0xE0, (byte) 0xF0, (byte) 0x80, (byte) 0x40, (byte) 0x70, (byte) 0x10, (byte) 0x20};

    private byte dec_sboxL[] = { (byte)0x50, (byte)0xE0, (byte)0xF0, (byte)0x80, (byte)0xC0, (byte)0x10, (byte)0x20, (byte)0xD0, (byte)0xB0, (byte)0x40, (byte)0x60, (byte)0x30, (byte)0x00, (byte)0x70, (byte)0x90, (byte)0xA0 };
    private byte dec_sboxR[] = { (byte)0x05, (byte)0x0E, (byte)0x0F, (byte)0x08, (byte)0x0C, (byte)0x01, (byte)0x02, (byte)0x0D, (byte)0x0B, (byte)0x04, (byte)0x06, (byte)0x03, (byte)0x00, (byte)0x07, (byte)0x09,(byte)0x0A };
    ECBpadding ECBP = new ECBpadding();

    private void pre_key_sche(byte[] key) {
        byte key_state[] = new byte[8];
        char rc = 1;

        round_key[1][9] = (byte) (((key[6] << 5) & 0xE0) | ((key[7] >> 3) & 0x1F));
        round_key[1][8] = (byte) (((key[5] << 5) & 0xE0) | ((key[6] >> 3) & 0x1F));
        round_key[1][7] = (byte) (((key[4] << 5) & 0xE0) | ((key[5] >> 3) & 0x1F));
        round_key[1][6] = (byte) (((key[3] << 5) & 0xE0) | ((key[4] >> 3) & 0x1F));
        round_key[1][5] = (byte) (((key[2] << 5) & 0xE0) | ((key[3] >> 3) & 0x1F));
        round_key[1][4] = (byte) (((key[1] << 5) & 0xE0) | ((key[2] >> 3) & 0x1F));
        round_key[1][3] = (byte) (((key[0] << 5) & 0xE0) | ((key[1] >> 3) & 0x1F));
        round_key[1][2] = (byte) (((key[9] << 5) & 0xE0) | ((key[0] >> 3) & 0x1F));
        round_key[1][1] = (byte) (((key[8] << 5) & 0xE0) | ((key[9] >> 3) & 0x1F));
        round_key[1][0] = (byte) (((key[7] << 5) & 0xE0) | ((key[8] >> 3) & 0x1F));

        round_key[1][0] = (byte) ((round_key[rc][0] & 0x0F) | ((sbox[(byte) (round_key[1][0] >> 4) & 0x0F]) & 0xF0));

        round_key[1][7] ^= rc >> 1;
        round_key[1][8] ^= rc << 7;


        for (rc = 2; rc <= 31; rc++) {
            key_state[5] = (byte) ((round_key[rc - 1][5] ^ (rc << 2))); // do this first, which may be faster

            // use state[] for temporary storage
            key_state[2] = round_key[rc - 1][9];
            key_state[1] = round_key[rc - 1][8];
            key_state[0] = round_key[rc - 1][7];

            round_key[rc][9] = (byte) (((round_key[rc - 1][6] << 5) & 0xE0) | ((round_key[rc - 1][7] >> 3) & 0x1F));
            round_key[rc][8] = (byte) (((key_state[5] << 5) & 0xE0) | ((round_key[rc - 1][6] >> 3) & 0x1F));
            round_key[rc][7] = (byte) (((round_key[rc - 1][4] << 5) & 0xE0) | ((key_state[5] >> 3) & 0x1F));
            round_key[rc][6] = (byte) (((round_key[rc - 1][3] << 5) & 0xE0) | ((round_key[rc - 1][4] >> 3) & 0x1F));
            round_key[rc][5] = (byte) (((round_key[rc - 1][2] << 5) & 0xE0) | ((round_key[rc - 1][3] >> 3) & 0x1F));
            round_key[rc][4] = (byte) (((round_key[rc - 1][1] << 5) & 0xE0) | ((round_key[rc - 1][2] >> 3) & 0x1F));
            round_key[rc][3] = (byte) (((round_key[rc - 1][0] << 5) & 0xE0) | ((round_key[rc - 1][1] >> 3) & 0x1F));
            round_key[rc][2] = (byte) (((key_state[2] << 5) & 0xE0) | ((round_key[rc - 1][0] >> 3) & 0x1F));
            round_key[rc][1] = (byte) (((key_state[1] << 5) & 0xE0) | ((key_state[2] >> 3) & 0x1F));
            round_key[rc][0] = (byte) (((key_state[0] << 5) & 0xE0) | ((key_state[1] >> 3) & 0x1F));
            round_key[rc][0] = (byte) ((round_key[rc][0] & 0x0F) | ((sbox[(byte) (round_key[rc][0] >> 4) & 0x0F]) & 0xF0));

        }


    }




    public byte[] pre_block_encrypt(byte[] key, byte plain[]) { // -> pre_block_encrypt

        int rounds = 31;

        int round_counter = 1;
        byte[] state = new byte[8];
        byte[] cipher = {(byte)0x00 , (byte)0x00 ,(byte)0x00 ,(byte)0x00 ,(byte)0x00 ,(byte)0x00 ,(byte)0x00 ,(byte)0x00};

        byte[] sbox_pmt3_00 = new byte[256];
        byte[] sbox_pmt3_01 = new byte[256];
        byte[] sbox_pmt3_02 = new byte[256];
        byte[] sbox_pmt3_03 = new byte[256];
        byte[] sbox_pmt3_10 = new byte[256];
        byte[] sbox_pmt3_11 = new byte[256];
        byte[] sbox_pmt3_12 = new byte[256];
        byte[] sbox_pmt3_13 = new byte[256];
        byte[] sbox_pmt3_20 = new byte[256];
        byte[] sbox_pmt3_21 = new byte[256];
        byte[] sbox_pmt3_22 = new byte[256];
        byte[] sbox_pmt3_23 = new byte[256];
        byte[] sbox_pmt3_30 = new byte[256];
        byte[] sbox_pmt3_31 = new byte[256];
        byte[] sbox_pmt3_32 = new byte[256];
        byte[] sbox_pmt3_33 = new byte[256];

        //key_sche(key);


        for (int i = 0; i < 16; i++)
        {
            for (int j = 0; j < 16; j++)
            {

                sbox_pmt3_00[(16 * i) + j] = (byte)((sbox[i] & 0x80) | ((sbox[j] & 0x80) >> 1) & 0x40);
                sbox_pmt3_01[(16 * i) + j] = (byte)((((sbox[i] & 0x80) >> 2) & 0x20) |(((sbox[j] & 0x80) >> 3) & 0x10));
                sbox_pmt3_02[(16 * i) + j] = (byte)((((sbox[i] & 0x80) >> 4) & 0x08) | (((sbox[j] & 0x80) >> 5) & 0x04));
                sbox_pmt3_03[(16 * i) + j] = (byte)((((sbox[i] & 0x80) >> 6) & 0x02) | (((sbox[j] & 0x80) >> 7) & 0x01));


                sbox_pmt3_10[(16 * i) + j] = (byte)((((sbox[i] & 0x40) << 1) & 0x80) | (sbox[j] & 0x40));
                sbox_pmt3_11[(16 * i) + j] = (byte)((((sbox[i] & 0x40) >> 1) & 0x20) | (((sbox[j] & 0x40) >> 2) & 0x10));
                sbox_pmt3_12[(16 * i) + j] = (byte)((((sbox[i] & 0x40) >> 3) & 0x08) |(((sbox[j] & 0x40) >> 4) & 0x04));
                sbox_pmt3_13[(16 * i) + j] = (byte)((((sbox[i] & 0x40) >> 5) & 0x02) | (((sbox[j] & 0x40) >> 6)& 0x01));

                sbox_pmt3_20[(16 * i) + j] = (byte)((((sbox[i] & 0x20) << 2) & 0x80) | (((sbox[j] & 0x20) << 1) & 0x40));
                sbox_pmt3_21[(16 * i) + j] = (byte)((sbox[i] & 0x20) | (((sbox[j] & 0x20) >> 1) & 0x10));
                sbox_pmt3_22[(16 * i) + j] = (byte)((((sbox[i] & 0x20) >> 2) & 0x08) | (((sbox[j] & 0x20) >> 3)& 0x04));
                sbox_pmt3_23[(16 * i) + j] = (byte)((((sbox[i] & 0x20) >> 4) & 0x02) | (((sbox[j] & 0x20) >> 5)& 0x01));

                sbox_pmt3_30[(16 * i) + j] = (byte)((((sbox[i] & 0x10) << 3) & 0x80) | (((sbox[j] & 0x10) << 2)& 0x40));
                sbox_pmt3_31[(16 * i) + j] = (byte)((((sbox[i] & 0x10) << 1) & 0x20) | (sbox[j] & 0x10));
                sbox_pmt3_32[(16 * i) + j] = (byte)((((sbox[i] & 0x10) >> 1) & 0x08) | (((sbox[j] & 0x10) >> 2) & 0x04));
                sbox_pmt3_33[(16 * i) + j] = (byte)((((sbox[i] & 0x10) >> 3) & 0x02) | (((sbox[j] & 0x10) >> 4) & 0x01));
            }
        }

        state[0] = (byte)(plain[0] ^ key[0]);
        state[1] = (byte)(plain[1] ^ key[1]);
        state[2] = (byte)(plain[2] ^ key[2]);
        state[3] = (byte)(plain[3] ^ key[3]);
        state[4] = (byte)(plain[4] ^ key[4]);
        state[5] = (byte)(plain[5] ^ key[5]);
        state[6] = (byte)(plain[6] ^ key[6]);
        state[7] = (byte)(plain[7] ^ key[7]);




        cipher[0] = (byte)(sbox_pmt3_00[state[0] & 0xFF] | sbox_pmt3_01[state[1] & 0xFF] | sbox_pmt3_02[state[2] & 0xFF] | sbox_pmt3_03[state[3] & 0xFF]);
        cipher[1] = (byte)(sbox_pmt3_00[state[4] & 0xFF] | sbox_pmt3_01[state[5] & 0xFF] | sbox_pmt3_02[state[6] & 0xFF] | sbox_pmt3_03[state[7] & 0xFF]);
        cipher[2] = (byte)(sbox_pmt3_10[state[0] & 0xFF] | sbox_pmt3_11[state[1] & 0xFF] | sbox_pmt3_12[state[2] & 0xFF] | sbox_pmt3_13[state[3] & 0xFF]);
        cipher[3] = (byte)(sbox_pmt3_10[state[4] & 0xFF] | sbox_pmt3_11[state[5] & 0xFF] | sbox_pmt3_12[state[6] & 0xFF] | sbox_pmt3_13[state[7] & 0xFF]);
        cipher[4] = (byte)(sbox_pmt3_20[state[0] & 0xFF] | sbox_pmt3_21[state[1] & 0xFF] | sbox_pmt3_22[state[2] & 0xFF] | sbox_pmt3_23[state[3] & 0xFF]);
        cipher[5] = (byte)(sbox_pmt3_20[state[4] & 0xFF] | sbox_pmt3_21[state[5] & 0xFF] | sbox_pmt3_22[state[6] & 0xFF] | sbox_pmt3_23[state[7] & 0xFF]);
        cipher[6] = (byte)(sbox_pmt3_30[state[0] & 0xFF] | sbox_pmt3_31[state[1] & 0xFF] | sbox_pmt3_32[state[2] & 0xFF] | sbox_pmt3_33[state[3] & 0xFF]);
        cipher[7] = (byte)(sbox_pmt3_30[state[4] & 0xFF] | sbox_pmt3_31[state[5] & 0xFF] | sbox_pmt3_32[state[6] & 0xFF] | sbox_pmt3_33[state[7] & 0xFF]);


        for (round_counter = 2; round_counter <= rounds; round_counter++) {

            state[0] = (byte) (cipher[0] ^ round_key[round_counter - 1][0]);
            state[1] = (byte) (cipher[1] ^ round_key[round_counter - 1][1]);
            state[2] = (byte) (cipher[2] ^ round_key[round_counter - 1][2]);
            state[3] = (byte) (cipher[3] ^ round_key[round_counter - 1][3]);
            state[4] = (byte) (cipher[4] ^ round_key[round_counter - 1][4]);
            state[5] = (byte) (cipher[5] ^ round_key[round_counter - 1][5]);
            state[6] = (byte) (cipher[6] ^ round_key[round_counter - 1][6]);
            state[7] = (byte) (cipher[7] ^ round_key[round_counter - 1][7]);


            cipher[0] = (byte)(sbox_pmt3_00[state[0] & 0xFF] | sbox_pmt3_01[state[1] & 0xFF] | sbox_pmt3_02[state[2] & 0xFF] | sbox_pmt3_03[state[3] & 0xFF]);

            cipher[1] = (byte)(sbox_pmt3_00[state[4] & 0xFF] | sbox_pmt3_01[state[5] & 0xFF] | sbox_pmt3_02[state[6] & 0xFF] | sbox_pmt3_03[state[7] & 0xFF]);

            cipher[2] = (byte)(sbox_pmt3_10[state[0] & 0xFF] | sbox_pmt3_11[state[1] & 0xFF] | sbox_pmt3_12[state[2] & 0xFF] | sbox_pmt3_13[state[3] & 0xFF]);

            cipher[3] = (byte)(sbox_pmt3_10[state[4] & 0xFF] | sbox_pmt3_11[state[5] & 0xFF] | sbox_pmt3_12[state[6] & 0xFF] | sbox_pmt3_13[state[7] & 0xFF]);

            cipher[4] = (byte)(sbox_pmt3_20[state[0] & 0xFF] | sbox_pmt3_21[state[1] & 0xFF] | sbox_pmt3_22[state[2] & 0xFF] | sbox_pmt3_23[state[3] & 0xFF]);

            cipher[5] = (byte)(sbox_pmt3_20[state[4] & 0xFF] | sbox_pmt3_21[state[5] & 0xFF] | sbox_pmt3_22[state[6] & 0xFF] | sbox_pmt3_23[state[7] & 0xFF]);

            cipher[6] = (byte)(sbox_pmt3_30[state[0] & 0xFF] | sbox_pmt3_31[state[1] & 0xFF] | sbox_pmt3_32[state[2] & 0xFF] | sbox_pmt3_33[state[3] & 0xFF]);

            cipher[7] = (byte)(sbox_pmt3_30[state[4] & 0xFF] | sbox_pmt3_31[state[5] & 0xFF] | sbox_pmt3_32[state[6] & 0xFF] | sbox_pmt3_33[state[7] & 0xFF]);

        }


        // if round is not equal to 31, then do not perform the last adding key operation
        // this can be used in constructing PRESENT based algorithm, such as MAC
        if (31 == rounds) {
            cipher[0] ^= round_key[31][0];
            cipher[1] ^= round_key[31][1];
            cipher[2] ^= round_key[31][2];
            cipher[3] ^= round_key[31][3];
            cipher[4] ^= round_key[31][4];
            cipher[5] ^= round_key[31][5];
            cipher[6] ^= round_key[31][6];
            cipher[7] ^= round_key[31][7];


        }


        return cipher;
    }


    public byte[] pre_enc(int type, byte[] key, byte[] unpadplain)//public byte[] pre_enc(CRYPTO_ALGORITHM type, uint8 *key, int keyLen, uint8 *plain, int plainLen)
    {

        byte[] plain=  ECBP.pad(unpadplain, (int)(Math.ceil((unpadplain.length/8)+((unpadplain.length%8)*0.125))*8), unpadplain.length);

        int i,j;
        int CRYPTO_PRESENT_BLOCKSIZE = 8;

        byte[] blockPlain;// = new byte[CRYPTO_PRESENT_BLOCKSIZE];
        byte[] blockCipher = new byte[CRYPTO_PRESENT_BLOCKSIZE];

        byte[] cipher = new byte[plain.length]; //*cipher = realloc(*cipher, sizeof(unsigned char) * plainLen);


        //키스케쥴링
        pre_key_sche(key);

        switch (type)//(getCipherMode(type))
        {
            case 0 ://ECB: //나중에 함수로 만들기
            {
                for (i = 0; i < plain.length; i += CRYPTO_PRESENT_BLOCKSIZE)
                {
                    blockPlain = new byte[CRYPTO_PRESENT_BLOCKSIZE]; //memcpy(blockPlain, plain + i, CRYPTO_PRESENT_BLOCKSIZE);

                    for(int c = 0; c < CRYPTO_PRESENT_BLOCKSIZE; c++)
                {
                    blockPlain[c] = plain[c + i];
                }
                    blockCipher = new byte[CRYPTO_PRESENT_BLOCKSIZE];// memcpy((*cipher) + i, blockCipher, CRYPTO_PRESENT_BLOCKSIZE);
                    blockCipher = pre_block_encrypt(key, blockPlain);

                    //*cipherLen += CRYPTO_PRESENT_BLOCKSIZE;
                    for(int c=0; c<CRYPTO_PRESENT_BLOCKSIZE; c++)
                    {
                        cipher[c + i] = blockCipher[c];
                    }
                }
                break;
            }
        }
        return cipher;
    }

    public byte[] pre_block_decrypt(byte[] key, byte[] cipher)
    {
        int i, j, k, l ;
        int round_counter = 1;
        int rounds = 31;

        byte[] state = new byte[8];
        byte[] dec_sboxT = new byte[256];

        byte[] pmt_sboxR_1 = new byte[256];
        byte[] pmt_sboxR_2 = new byte[256];
        byte[] pmt_sboxR_3 = new byte[256];
        byte[] pmt_sboxR_4 = new byte[256];

        byte[] pmt_sboxL_1 = new byte[256];
        byte[] pmt_sboxL_2 = new byte[256];
        byte[] pmt_sboxL_3 = new byte[256];
        byte[] pmt_sboxL_4 = new byte[256];


        for (i = 0; i < 16; i++)
        {
            for (j = 0; j < 16; j++)
            {
                pmt_sboxL_1[(16 * i) + j] = (byte)((((((i & 0x08) << 4) & 0x80)| ((((j & 0x08) << 3) & 0x40)))));  // xx00 0000
                pmt_sboxL_2[(16 * i) + j] = (byte)((((i & 0x04) << 1) & 0x08) | ((j & 0x04))); // 0000 xx00
                pmt_sboxL_3[(16 * i) + j] = (byte)((((i & 0x02) << 6) & 0x80) | (((j & 0x02) << 5) & 0x40)); // xx00 0000
                pmt_sboxL_4[(16 * i) + j] = (byte)((((i & 0x01) << 3) & 0x08) | (((j & 0x01) << 2) & 0x04)); // 0000 xx00

                pmt_sboxR_1[(16 * i) + j] = (byte)((((i & 0x08) << 2) & 0x20) | (((j & 0x08) << 1) & 0x10));  // 00xx 0000
                pmt_sboxR_2[(16 * i) + j] = (byte)((((i & 0x04) >> 1) & 0x02) | (((j & 0x04) >> 2) & 0x01));  // 0000 00xx
                pmt_sboxR_3[(16 * i) + j] = (byte)((((i & 0x02) << 4) & 0x20) | (((j & 0x02) << 3) & 0x10)); // 00xx 0000
                pmt_sboxR_4[(16 * i) + j] = (byte)((((i & 0x01) << 1) & 0x02) | ((j & 0x01))); // 0000 00xx


            }
        }

        for (k = 0; k < 16; k++)
        {
            for (l = 0; l < 16; l++)
            {
                dec_sboxT[(16 * k) + l] = (byte)(((dec_sboxL[k] & 0xF0) | (dec_sboxR[l] & 0x0F))& 0xFF) ;

            }
        }

        for (i = 0; i < 8; i++)
            state[i] = cipher[i];



        for (round_counter = rounds; round_counter > 0; round_counter--)
        {
            for (i = 0; i < 8; i++)
            {
                cipher[i] = (byte)((state[i] ^ round_key[round_counter][i]) & 0xFF);
                state[i] = 0x00;

            }

            state[0] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(cipher[0] & 0xF0 | ((cipher[2] >> 4) & 0x0F)) & 0xFF] | pmt_sboxR_1[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(cipher[0] & 0xF0 | (cipher[2] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
            state[1] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(cipher[0] & 0xF0 | (cipher[2] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(cipher[0] & 0xF0 | (cipher[2] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
            state[2] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(((cipher[0] & 0x0F) << 4) & 0xF0 | cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_1[(byte)(((cipher[4] & 0x0F) << 4) & 0xF0 | cipher[6] & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(((cipher[0] & 0x0F) << 4)  & 0xF0 | cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(((cipher[4] & 0x0F) << 4)& 0xF0 | cipher[6] & 0x0F) & 0xFF]) & 0xFF]);
            state[3] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(((cipher[0] & 0x0F) << 4) & 0xF0 | cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(((cipher[4] & 0x0F) << 4) & 0xF0 | cipher[6] & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(((cipher[0] & 0x0F) << 4) &  0xF0| cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(((cipher[4] & 0x0F) << 4) & 0xF0 | cipher[6] & 0x0F) & 0xFF]) & 0xFF]);
            state[4] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_1[(byte)(cipher[5] & 0xF0 | (cipher[7] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(cipher[5] & 0xF0 |(cipher[7] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
            state[5] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(cipher[5] & 0xF0 | (cipher[7] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(cipher[5] & 0xF0 |(cipher[7] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
            state[6] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_1[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF]) & 0xFF]);
            state[7] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF]) & 0xFF]);
            String temp_text = Integer.toString(((state[5] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("state", temp_text);

        }

        state[0] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(cipher[0] & 0xF0 | ((cipher[2] >> 4) & 0x0F)) & 0xFF] | pmt_sboxR_1[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(cipher[0] & 0xF0 | (cipher[2] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
        state[1] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(cipher[0] & 0xF0 | (cipher[2] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(cipher[0] & 0xF0 | (cipher[2] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(cipher[4] & 0xF0 | (cipher[6] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
        state[2] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(((cipher[0] & 0x0F) << 4) & 0xF0 | cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_1[(byte)(((cipher[4] & 0x0F) << 4) & 0xF0 | cipher[6] & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(((cipher[0] & 0x0F) << 4)  & 0xF0 | cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(((cipher[4] & 0x0F) << 4)& 0xF0 | cipher[6] & 0x0F) & 0xFF]) & 0xFF]);
        state[3] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(((cipher[0] & 0x0F) << 4) & 0xF0 | cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(((cipher[4] & 0x0F) << 4) & 0xF0 | cipher[6] & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(((cipher[0] & 0x0F) << 4) &  0xF0| cipher[2] & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(((cipher[4] & 0x0F) << 4) & 0xF0 | cipher[6] & 0x0F) & 0xFF]) & 0xFF]);
        state[4] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_1[(byte)(cipher[5] & 0xF0 | (cipher[7] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(cipher[5] & 0xF0 |(cipher[7] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
        state[5] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(cipher[5] & 0xF0 | (cipher[7] >> 4) & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(cipher[1] & 0xF0 | (cipher[3] >> 4) & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(cipher[5] & 0xF0 |(cipher[7] >> 4) & 0x0F) & 0xFF]) & 0xFF]);
        state[6] = (dec_sboxT[(byte)(pmt_sboxL_1[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_1[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF] | pmt_sboxL_2[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_2[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF]) & 0xFF]);
        state[7] = (dec_sboxT[(byte)(pmt_sboxL_3[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_3[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF] | pmt_sboxL_4[(byte)(((cipher[1] & 0x0F) << 4) & 0xF0 | cipher[3] & 0x0F) & 0xFF] | pmt_sboxR_4[(byte)(((cipher[5] & 0x0F) << 4) & 0xF0 | cipher[7] & 0x0F) & 0xFF]) & 0xFF]);

        for (i = 0; i < 8; i++)
            state[i] ^= key[i];

        return state;

    }


    public byte[] pre_dec(int type, byte[] key, byte[] cipher)
    {
        int i;

        for(i= 0 ; i < cipher.length; i++)
            Log.d("DONGGUK : ",String.format("cipher : %02x", cipher[i]));
        int CRYPTO_PRESENT_BLOCKSIZE = 8;
        byte[] blockCipher = new byte[CRYPTO_PRESENT_BLOCKSIZE];
        byte[] blockDecipher = new byte[CRYPTO_PRESENT_BLOCKSIZE];

        byte[] decipher = new byte[cipher.length]; //*decipher = realloc(*decipher, sizeof(unsigned char) * cipherLen);
        byte[] paddecipher;

        pre_key_sche(key);


        switch (type)
        {
            case 0://ECB: //나중에 함수로 만들기
            {
                for (i = 0; i < cipher.length; i += CRYPTO_PRESENT_BLOCKSIZE)
                {
                    for(int c = 0; c < CRYPTO_PRESENT_BLOCKSIZE; c++)
                    {
                        blockCipher[c] = cipher[c + i];
                    }// memcpy(blockCipher, cipher + i, CRYPTO_PRESENT_BLOCKSIZE);

                    blockDecipher = pre_block_decrypt(key, blockCipher);//memcpy((*decipher) + i, blockDecipher, CRYPTO_PRESENT_BLOCKSIZE);

                    for(int c = 0; c < CRYPTO_PRESENT_BLOCKSIZE; c++)
                    {
                        decipher[c + i] = blockDecipher[c];
                    }
                }
                break;
            }
        }
        for(i= 0 ; i < decipher.length; i++)
            Log.d("DONGGUK : ",String.format("decipher : %02x", decipher[i]));
        paddecipher = ECBP.unpad(decipher, decipher.length);
        for(i= 0 ; i < paddecipher.length; i++)
            Log.d("DONGGUK : ",String.format("paddecipher : %02x", paddecipher[i]));
        return paddecipher;

    }

}


