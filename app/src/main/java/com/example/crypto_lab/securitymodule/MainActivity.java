package com.example.crypto_lab.securitymodule;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.example.crypto_lab.securitymodule.ECBpadding;
import com.example.crypto_lab.securitymodule.present;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        ECBpadding ECBP = new ECBpadding();
        byte[] msg = new byte[3];
        msg[0] = (byte)0x83;
        msg[1] = (byte)0x04;
        msg[2] = (byte)0x00;


        //byte[] padMsg = ECBP.pad(msg, 8, 8);

        /*if (BuildConfig.DEBUG) Log.d("PADDINGs", "1" );
        for(int i=0; i<padMsg.length; i++) {
            String temp_text = Integer.toString(((padMsg[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("PADDING", temp_text);
        }*/

        present PRE = new present();
        byte[] key = new byte[10];
        key[0] = (byte)0x24; key[1] = (byte)0xE5; key[2] = (byte)0x22; key[3] = (byte)0x31; key[4] = (byte)0x4E; key[5] = (byte)0x8D; key[6] = (byte)0xBC; key[7] = (byte)0xC1; key[8] =(byte)0xE3 ; key[9] = (byte)0xF5;

        String temp_text = Integer.toString((msg.length ), 16).substring(1);

        Log.d("msglength",temp_text);
        byte[] cipher = PRE.pre_enc(0, key, msg);

        for(int i = 0; i<cipher.length; i++)
        {
            temp_text = Integer.toString(((cipher[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("end", temp_text);
        }
        cipher[0] = (byte)0x2D;
        cipher[1] = (byte)0x60;
        cipher[2] = (byte)0xDF;
        cipher[3] = (byte)0x8A;
        cipher[4] = (byte)0xDA;
        cipher[5] = (byte)0x05;
        cipher[6] = (byte)0x2F;
        cipher[7] = (byte)0xF2;

        byte[] decipher = PRE.pre_dec(0, key, cipher);

        for(int i = 0; i<decipher.length; i++)
        {
            temp_text = Integer.toString(((decipher[i] & 0xFF) + 0x100), 16).substring(1);
            if (BuildConfig.DEBUG) Log.d("end", temp_text);
        }
    }
}
