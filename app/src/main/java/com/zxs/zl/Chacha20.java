package com.zxs.zl;

/*
 * Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

public class Chacha20 {
    /*
     * ChaCha20_ctr32 encrypts |len| bytes from |inp| with the given key and
     * nonce and writes the result to |out|, which may be equal to |inp|.
     * The |key| is not 32 bytes of verbatim key material though, but the
     * said material collected into 8 32-bit elements array in host byte
     * order. Same approach applies to nonce: the |counter| argument is
     * pointer to concatenated nonce and counter values collected into 4
     * 32-bit elements. This, passing crypto material collected into 32-bit
     * elements as opposite to passing verbatim byte vectors, is chosen for
     * efficiency in multi-call scenarios.
     */

    /**
     * function same  ,encrypt and decrypt
     * @param inp source data (encrypt data or decrypt data)
     * @param key int[8] array
     * @param counter int[4] array
     * @return  decrypt data or encrypt data ; see inp param.
     */
    public static byte[] crytpoCounter32(byte[] inp, int[] key,int[] counter)
    {
        byte[] out = new byte[inp.length];

        int[] input = new int[16];

        byte[] buf = new byte[64];
        int todo, i;

        /* sigma constant "expand 32-byte k" in little-endian encoding */
        input[0] = ((int)'e') | ((int)'x'<<8) | ((int)'p'<<16) | ((int)'a'<<24);
        input[1] = ((int)'n') | ((int)'d'<<8) | ((int)' '<<16) | ((int)'3'<<24);
        input[2] = ((int)'2') | ((int)'-'<<8) | ((int)'b'<<16) | ((int)'y'<<24);
        input[3] = ((int)'t') | ((int)'e'<<8) | ((int)' '<<16) | ((int)'k'<<24);

        input[4] = key[0];
        input[5] = key[1];
        input[6] = key[2];
        input[7] = key[3];
        input[8] = key[4];
        input[9] = key[5];
        input[10] = key[6];
        input[11] = key[7];

        input[12] = counter[0];
        input[13] = counter[1];
        input[14] = counter[2];
        input[15] = counter[3];

        int len = inp.length;
        int offset = 0;
        while (len > 0) {
            todo = 64;// equal to buf.length;
            if (len < todo)
                todo = len;

            chacha20_core(buf, input);

            for (i = 0; i < todo; i++){
                out[i+offset] = (byte) (inp[i+offset] ^ buf[i]);
            }
            offset += todo;
            len -= todo;

            /*
             * Advance 32-bit counter. Note that as subroutine is so to
             * say nonce-agnostic, this limited counter width doesn't
             * prevent caller from implementing wider counter. It would
             * simply take two calls split on counter overflow...
             */
            input[12]++;
        }
        return out;
    }



    /* chacha_core performs 20 rounds of ChaCha on the input words in
     * |input| and writes the 64 output bytes to |output|. */
    private static void chacha20_core(byte[] output, int[] input)
    {
        //output byte[64]
        long[] x = new long[16];
        for (int i = 0 ; i < 16 ;i++){
            x[i] = (input[i] & 0xFFFFFFFFL );
        }
        for (int i = 20; i > 0; i -= 2) {
            QUARTERROUND(x,0, 4, 8, 12);
            QUARTERROUND(x,1, 5, 9, 13);
            QUARTERROUND(x,2, 6, 10, 14);
            QUARTERROUND(x,3, 7, 11, 15);
            QUARTERROUND(x,0, 5, 10, 15);
            QUARTERROUND(x,1, 6, 11, 12);
            QUARTERROUND(x,2, 7, 8, 13);
            QUARTERROUND(x,3, 4, 9, 14);
        }

        for (int i = 0; i < 16; ++i) {
            long v = (x[i] + input[i]) & 0xFFFFFFFFL;
            output[i<<2] = (byte) (v & 0xFF);
            output[(i<<2) + 1] = (byte) ((v>>8) & 0xFF);
            output[(i<<2) + 2] = (byte) ((v>>16) & 0xFF);
            output[(i<<2) + 3] = (byte) ((v>>24) & 0xFF);
        }
    }

    /* QUARTERROUND updates a, b, c, d with a ChaCha "quarter" round. */
    private static void QUARTERROUND(long[]x, int a,int b,int c,int d){
        x[a] = (x[a] + x[b]) & 0xFFFFFFFFL;
        x[d] = ROTATE((x[d] ^ x[a]),16) & 0xFFFFFFFFL;
        x[c] = (x[c] + x[d]) & 0xFFFFFFFFL;
        x[b] = ROTATE((x[b] ^ x[c]),12) & 0xFFFFFFFFL;
        x[a] = (x[a] + x[b]) & 0xFFFFFFFFL;
        x[d] = ROTATE((x[d] ^ x[a]), 8) & 0xFFFFFFFFL;
        x[c] = (x[c] + x[d]) & 0xFFFFFFFFL;
        x[b] = ROTATE((x[b] ^ x[c]), 7) & 0xFFFFFFFFL;
    }
    private static long ROTATE(long v,int n)
    {
        v = v & 0xFFFFFFFFL;
        return (((v) << (n)) | ((v) >> (32 - (n))));
    }
}
