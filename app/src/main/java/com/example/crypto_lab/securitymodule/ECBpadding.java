package com.example.crypto_lab.securitymodule;

import android.util.Log;

/**
 * Created by crypto_lab on 2017-01-19.
 */

public class ECBpadding
{


    public byte[] pad(byte[] source, int block_size, int source_len)
    {
       int dest_len = (source_len / block_size + 1) * block_size;
       byte pad = 0x01;
       byte test[] = new byte[dest_len];

        for (int i = 1; i < (dest_len - source_len); i++)
            pad += 0x01;

        if (source_len % block_size == 0)
        {
            dest_len +=  block_size;
            pad = 0x00;

        }

        dest_len = (source_len / block_size + 1) * block_size;

        for(int i =0; i<dest_len; i++)
        {
            test[i] = pad;
        }

        for(int i=0; i<source_len; i++) {
            test[i] = source[i];
        }

       /* Arrays.fill(dest, pad);
        memcpy((*dest), source, source_len);

        return dest_len;*/
        return test;
    }



    public byte[] unpad(byte[] source, int block_size)
    {

        int i;
        for(i= 0 ; i < source.length; i++)
            Log.d("DONGGUK : ",String.format("unpad Source : %02x", source[i]));
        byte[] dest;
        int dest_len = source.length - source[source.length - 1];

        if (source[source.length - 1] == 0) //원래 블록에 패딩된 경우
        {
            dest_len -= block_size; //실제 소스길이
        }

        dest = new byte[dest_len];//*dest = realloc(*dest, sizeof(unsigned char) * dest_len);

        for(i=0; i<dest_len; i++)
        {
            dest[i] = source[i];
        }//memcpy((*dest), source, dest_len);

        return  dest;

    }


}
