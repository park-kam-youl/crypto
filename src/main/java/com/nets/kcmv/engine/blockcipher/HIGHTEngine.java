package com.nets.kcmv.engine.blockcipher;

import java.security.InvalidKeyException;
import java.util.Arrays;

public class HIGHTEngine implements BlockCipherEngine
{

    private static final int BLOCK_SIZE = 8;

    private static final byte[] Delta = new byte[]
            {
                    (byte) 0x5A, (byte) 0x6D, (byte) 0x36, (byte) 0x1B, (byte) 0x0D, (byte) 0x06, (byte) 0x03, (byte) 0x41,
                    (byte) 0x60, (byte) 0x30, (byte) 0x18, (byte) 0x4C, (byte) 0x66, (byte) 0x33, (byte) 0x59, (byte) 0x2C,
                    (byte) 0x56, (byte) 0x2B, (byte) 0x15, (byte) 0x4A, (byte) 0x65, (byte) 0x72, (byte) 0x39, (byte) 0x1C,
                    (byte) 0x4E, (byte) 0x67, (byte) 0x73, (byte) 0x79, (byte) 0x3C, (byte) 0x5E, (byte) 0x6F, (byte) 0x37,
                    (byte) 0x5B, (byte) 0x2D, (byte) 0x16, (byte) 0x0B, (byte) 0x05, (byte) 0x42, (byte) 0x21, (byte) 0x50,
                    (byte) 0x28, (byte) 0x54, (byte) 0x2A, (byte) 0x55, (byte) 0x6A, (byte) 0x75, (byte) 0x7A, (byte) 0x7D,
                    (byte) 0x3E, (byte) 0x5F, (byte) 0x2F, (byte) 0x17, (byte) 0x4B, (byte) 0x25, (byte) 0x52, (byte) 0x29,
                    (byte) 0x14, (byte) 0x0A, (byte) 0x45, (byte) 0x62, (byte) 0x31, (byte) 0x58, (byte) 0x6C, (byte) 0x76,
                    (byte) 0x3B, (byte) 0x1D, (byte) 0x0E, (byte) 0x47, (byte) 0x63, (byte) 0x71, (byte) 0x78, (byte) 0x7C,
                    (byte) 0x7E, (byte) 0x7F, (byte) 0x3F, (byte) 0x1F, (byte) 0x0F, (byte) 0x07, (byte) 0x43, (byte) 0x61,
                    (byte) 0x70, (byte) 0x38, (byte) 0x5C, (byte) 0x6E, (byte) 0x77, (byte) 0x7B, (byte) 0x3D, (byte) 0x1E,
                    (byte) 0x4F, (byte) 0x27, (byte) 0x53, (byte) 0x69, (byte) 0x34, (byte) 0x1A, (byte) 0x4D, (byte) 0x26,
                    (byte) 0x13, (byte) 0x49, (byte) 0x24, (byte) 0x12, (byte) 0x09, (byte) 0x04, (byte) 0x02, (byte) 0x01,
                    (byte) 0x40, (byte) 0x20, (byte) 0x10, (byte) 0x08, (byte) 0x44, (byte) 0x22, (byte) 0x11, (byte) 0x48,
                    (byte) 0x64, (byte) 0x32, (byte) 0x19, (byte) 0x0C, (byte) 0x46, (byte) 0x23, (byte) 0x51, (byte) 0x68,
                    (byte) 0x74, (byte) 0x3A, (byte) 0x5D, (byte) 0x2E, (byte) 0x57, (byte) 0x6B, (byte) 0x35, (byte) 0x5A
            };

    private static final byte[] F0 = new byte[]
            {
                    (byte) 0x00, (byte) 0x86, (byte) 0x0D, (byte) 0x8B, (byte) 0x1A, (byte) 0x9C, (byte) 0x17, (byte) 0x91,
                    (byte) 0x34, (byte) 0xB2, (byte) 0x39, (byte) 0xBF, (byte) 0x2E, (byte) 0xA8, (byte) 0x23, (byte) 0xA5,
                    (byte) 0x68, (byte) 0xEE, (byte) 0x65, (byte) 0xE3, (byte) 0x72, (byte) 0xF4, (byte) 0x7F, (byte) 0xF9,
                    (byte) 0x5C, (byte) 0xDA, (byte) 0x51, (byte) 0xD7, (byte) 0x46, (byte) 0xC0, (byte) 0x4B, (byte) 0xCD,
                    (byte) 0xD0, (byte) 0x56, (byte) 0xDD, (byte) 0x5B, (byte) 0xCA, (byte) 0x4C, (byte) 0xC7, (byte) 0x41,
                    (byte) 0xE4, (byte) 0x62, (byte) 0xE9, (byte) 0x6F, (byte) 0xFE, (byte) 0x78, (byte) 0xF3, (byte) 0x75,
                    (byte) 0xB8, (byte) 0x3E, (byte) 0xB5, (byte) 0x33, (byte) 0xA2, (byte) 0x24, (byte) 0xAF, (byte) 0x29,
                    (byte) 0x8C, (byte) 0x0A, (byte) 0x81, (byte) 0x07, (byte) 0x96, (byte) 0x10, (byte) 0x9B, (byte) 0x1D,
                    (byte) 0xA1, (byte) 0x27, (byte) 0xAC, (byte) 0x2A, (byte) 0xBB, (byte) 0x3D, (byte) 0xB6, (byte) 0x30,
                    (byte) 0x95, (byte) 0x13, (byte) 0x98, (byte) 0x1E, (byte) 0x8F, (byte) 0x09, (byte) 0x82, (byte) 0x04,
                    (byte) 0xC9, (byte) 0x4F, (byte) 0xC4, (byte) 0x42, (byte) 0xD3, (byte) 0x55, (byte) 0xDE, (byte) 0x58,
                    (byte) 0xFD, (byte) 0x7B, (byte) 0xF0, (byte) 0x76, (byte) 0xE7, (byte) 0x61, (byte) 0xEA, (byte) 0x6C,
                    (byte) 0x71, (byte) 0xF7, (byte) 0x7C, (byte) 0xFA, (byte) 0x6B, (byte) 0xED, (byte) 0x66, (byte) 0xE0,
                    (byte) 0x45, (byte) 0xC3, (byte) 0x48, (byte) 0xCE, (byte) 0x5F, (byte) 0xD9, (byte) 0x52, (byte) 0xD4,
                    (byte) 0x19, (byte) 0x9F, (byte) 0x14, (byte) 0x92, (byte) 0x03, (byte) 0x85, (byte) 0x0E, (byte) 0x88,
                    (byte) 0x2D, (byte) 0xAB, (byte) 0x20, (byte) 0xA6, (byte) 0x37, (byte) 0xB1, (byte) 0x3A, (byte) 0xBC,
                    (byte) 0x43, (byte) 0xC5, (byte) 0x4E, (byte) 0xC8, (byte) 0x59, (byte) 0xDF, (byte) 0x54, (byte) 0xD2,
                    (byte) 0x77, (byte) 0xF1, (byte) 0x7A, (byte) 0xFC, (byte) 0x6D, (byte) 0xEB, (byte) 0x60, (byte) 0xE6,
                    (byte) 0x2B, (byte) 0xAD, (byte) 0x26, (byte) 0xA0, (byte) 0x31, (byte) 0xB7, (byte) 0x3C, (byte) 0xBA,
                    (byte) 0x1F, (byte) 0x99, (byte) 0x12, (byte) 0x94, (byte) 0x05, (byte) 0x83, (byte) 0x08, (byte) 0x8E,
                    (byte) 0x93, (byte) 0x15, (byte) 0x9E, (byte) 0x18, (byte) 0x89, (byte) 0x0F, (byte) 0x84, (byte) 0x02,
                    (byte) 0xA7, (byte) 0x21, (byte) 0xAA, (byte) 0x2C, (byte) 0xBD, (byte) 0x3B, (byte) 0xB0, (byte) 0x36,
                    (byte) 0xFB, (byte) 0x7D, (byte) 0xF6, (byte) 0x70, (byte) 0xE1, (byte) 0x67, (byte) 0xEC, (byte) 0x6A,
                    (byte) 0xCF, (byte) 0x49, (byte) 0xC2, (byte) 0x44, (byte) 0xD5, (byte) 0x53, (byte) 0xD8, (byte) 0x5E,
                    (byte) 0xE2, (byte) 0x64, (byte) 0xEF, (byte) 0x69, (byte) 0xF8, (byte) 0x7E, (byte) 0xF5, (byte) 0x73,
                    (byte) 0xD6, (byte) 0x50, (byte) 0xDB, (byte) 0x5D, (byte) 0xCC, (byte) 0x4A, (byte) 0xC1, (byte) 0x47,
                    (byte) 0x8A, (byte) 0x0C, (byte) 0x87, (byte) 0x01, (byte) 0x90, (byte) 0x16, (byte) 0x9D, (byte) 0x1B,
                    (byte) 0xBE, (byte) 0x38, (byte) 0xB3, (byte) 0x35, (byte) 0xA4, (byte) 0x22, (byte) 0xA9, (byte) 0x2F,
                    (byte) 0x32, (byte) 0xB4, (byte) 0x3F, (byte) 0xB9, (byte) 0x28, (byte) 0xAE, (byte) 0x25, (byte) 0xA3,
                    (byte) 0x06, (byte) 0x80, (byte) 0x0B, (byte) 0x8D, (byte) 0x1C, (byte) 0x9A, (byte) 0x11, (byte) 0x97,
                    (byte) 0x5A, (byte) 0xDC, (byte) 0x57, (byte) 0xD1, (byte) 0x40, (byte) 0xC6, (byte) 0x4D, (byte) 0xCB,
                    (byte) 0x6E, (byte) 0xE8, (byte) 0x63, (byte) 0xE5, (byte) 0x74, (byte) 0xF2, (byte) 0x79, (byte) 0xFF
            };

    private static final byte[] F1 = new byte[]
            {
                    (byte) 0x00, (byte) 0x58, (byte) 0xB0, (byte) 0xE8, (byte) 0x61, (byte) 0x39, (byte) 0xD1, (byte) 0x89,
                    (byte) 0xC2, (byte) 0x9A, (byte) 0x72, (byte) 0x2A, (byte) 0xA3, (byte) 0xFB, (byte) 0x13, (byte) 0x4B,
                    (byte) 0x85, (byte) 0xDD, (byte) 0x35, (byte) 0x6D, (byte) 0xE4, (byte) 0xBC, (byte) 0x54, (byte) 0x0C,
                    (byte) 0x47, (byte) 0x1F, (byte) 0xF7, (byte) 0xAF, (byte) 0x26, (byte) 0x7E, (byte) 0x96, (byte) 0xCE,
                    (byte) 0x0B, (byte) 0x53, (byte) 0xBB, (byte) 0xE3, (byte) 0x6A, (byte) 0x32, (byte) 0xDA, (byte) 0x82,
                    (byte) 0xC9, (byte) 0x91, (byte) 0x79, (byte) 0x21, (byte) 0xA8, (byte) 0xF0, (byte) 0x18, (byte) 0x40,
                    (byte) 0x8E, (byte) 0xD6, (byte) 0x3E, (byte) 0x66, (byte) 0xEF, (byte) 0xB7, (byte) 0x5F, (byte) 0x07,
                    (byte) 0x4C, (byte) 0x14, (byte) 0xFC, (byte) 0xA4, (byte) 0x2D, (byte) 0x75, (byte) 0x9D, (byte) 0xC5,
                    (byte) 0x16, (byte) 0x4E, (byte) 0xA6, (byte) 0xFE, (byte) 0x77, (byte) 0x2F, (byte) 0xC7, (byte) 0x9F,
                    (byte) 0xD4, (byte) 0x8C, (byte) 0x64, (byte) 0x3C, (byte) 0xB5, (byte) 0xED, (byte) 0x05, (byte) 0x5D,
                    (byte) 0x93, (byte) 0xCB, (byte) 0x23, (byte) 0x7B, (byte) 0xF2, (byte) 0xAA, (byte) 0x42, (byte) 0x1A,
                    (byte) 0x51, (byte) 0x09, (byte) 0xE1, (byte) 0xB9, (byte) 0x30, (byte) 0x68, (byte) 0x80, (byte) 0xD8,
                    (byte) 0x1D, (byte) 0x45, (byte) 0xAD, (byte) 0xF5, (byte) 0x7C, (byte) 0x24, (byte) 0xCC, (byte) 0x94,
                    (byte) 0xDF, (byte) 0x87, (byte) 0x6F, (byte) 0x37, (byte) 0xBE, (byte) 0xE6, (byte) 0x0E, (byte) 0x56,
                    (byte) 0x98, (byte) 0xC0, (byte) 0x28, (byte) 0x70, (byte) 0xF9, (byte) 0xA1, (byte) 0x49, (byte) 0x11,
                    (byte) 0x5A, (byte) 0x02, (byte) 0xEA, (byte) 0xB2, (byte) 0x3B, (byte) 0x63, (byte) 0x8B, (byte) 0xD3,
                    (byte) 0x2C, (byte) 0x74, (byte) 0x9C, (byte) 0xC4, (byte) 0x4D, (byte) 0x15, (byte) 0xFD, (byte) 0xA5,
                    (byte) 0xEE, (byte) 0xB6, (byte) 0x5E, (byte) 0x06, (byte) 0x8F, (byte) 0xD7, (byte) 0x3F, (byte) 0x67,
                    (byte) 0xA9, (byte) 0xF1, (byte) 0x19, (byte) 0x41, (byte) 0xC8, (byte) 0x90, (byte) 0x78, (byte) 0x20,
                    (byte) 0x6B, (byte) 0x33, (byte) 0xDB, (byte) 0x83, (byte) 0x0A, (byte) 0x52, (byte) 0xBA, (byte) 0xE2,
                    (byte) 0x27, (byte) 0x7F, (byte) 0x97, (byte) 0xCF, (byte) 0x46, (byte) 0x1E, (byte) 0xF6, (byte) 0xAE,
                    (byte) 0xE5, (byte) 0xBD, (byte) 0x55, (byte) 0x0D, (byte) 0x84, (byte) 0xDC, (byte) 0x34, (byte) 0x6C,
                    (byte) 0xA2, (byte) 0xFA, (byte) 0x12, (byte) 0x4A, (byte) 0xC3, (byte) 0x9B, (byte) 0x73, (byte) 0x2B,
                    (byte) 0x60, (byte) 0x38, (byte) 0xD0, (byte) 0x88, (byte) 0x01, (byte) 0x59, (byte) 0xB1, (byte) 0xE9,
                    (byte) 0x3A, (byte) 0x62, (byte) 0x8A, (byte) 0xD2, (byte) 0x5B, (byte) 0x03, (byte) 0xEB, (byte) 0xB3,
                    (byte) 0xF8, (byte) 0xA0, (byte) 0x48, (byte) 0x10, (byte) 0x99, (byte) 0xC1, (byte) 0x29, (byte) 0x71,
                    (byte) 0xBF, (byte) 0xE7, (byte) 0x0F, (byte) 0x57, (byte) 0xDE, (byte) 0x86, (byte) 0x6E, (byte) 0x36,
                    (byte) 0x7D, (byte) 0x25, (byte) 0xCD, (byte) 0x95, (byte) 0x1C, (byte) 0x44, (byte) 0xAC, (byte) 0xF4,
                    (byte) 0x31, (byte) 0x69, (byte) 0x81, (byte) 0xD9, (byte) 0x50, (byte) 0x08, (byte) 0xE0, (byte) 0xB8,
                    (byte) 0xF3, (byte) 0xAB, (byte) 0x43, (byte) 0x1B, (byte) 0x92, (byte) 0xCA, (byte) 0x22, (byte) 0x7A,
                    (byte) 0xB4, (byte) 0xEC, (byte) 0x04, (byte) 0x5C, (byte) 0xD5, (byte) 0x8D, (byte) 0x65, (byte) 0x3D,
                    (byte) 0x76, (byte) 0x2E, (byte) 0xC6, (byte) 0x9E, (byte) 0x17, (byte) 0x4F, (byte) 0xA7, (byte) 0xFF
            };

    private byte[] roundKeys = new byte[128]; // 32 rounds * 4 bytes/round
    private byte[] masterKey;

    public HIGHTEngine()
    {
    }

    @Override
    public void setKey(byte[] key) throws InvalidKeyException
    {
        if (key.length != 16)
        {
            throw new InvalidKeyException("Key size must be 16 bytes for HIGHT");
        }
        this.masterKey = key;
    }

    @Override
    public void setupEncRoundKeys() throws InvalidKeyException
    {
        if (masterKey == null)
        {
            throw new InvalidKeyException("Master key not set.");
        }
        generateRoundKeys(masterKey);
    }

    @Override
    public void setupDecRoundKeys() throws InvalidKeyException
    {
        // HIGHT uses the same round keys for encryption and decryption, but applied in reverse order
        // The decrypt method handles the reverse application of round keys.
        // So, no explicit reversal of roundKeys array is needed here.
        setupEncRoundKeys(); // Ensure encryption keys are set up first
    }

    @Override
    public int getBlockSize()
    {
        return BLOCK_SIZE;
    }

    @Override
    public void encrypt(byte[] in, int inOff, byte[] out, int outOff) throws InvalidKeyException
    {
        if (roundKeys == null)
        {
            throw new InvalidKeyException("Round keys not set. Call setupEncRoundKeys() first.");
        }
        byte[] t = new byte[8];
        byte[] key = this.roundKeys;

        t[1] = in[inOff + 1];
        t[3] = in[inOff + 3];
        t[5] = in[inOff + 5];
        t[7] = in[inOff + 7];

        EncIni_Transformation(t, in[inOff + 0], in[inOff + 2], in[inOff + 4], in[inOff + 6], roundKeys[12 * 4], roundKeys[12 * 4 + 1], roundKeys[12 * 4 + 2], roundKeys[12 * 4 + 3]);

        int key_offset = 0;
        for (int r = 0; r < 32; r++)
        {
            Round(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset);
            key_offset += 4;
        }

        EncFin_Transformation(out, t[1], t[3], t[5], t[7], roundKeys[0], roundKeys[1], roundKeys[2], roundKeys[3], outOff);

        out[outOff + 1] = t[2];
        out[outOff + 3] = t[4];
        out[outOff + 5] = t[6];
        out[outOff + 7] = t[0];
    }

    @Override
    public void decrypt(byte[] in, int inOff, byte[] out, int outOff) throws InvalidKeyException
    {
        if (roundKeys == null)
        {
            throw new InvalidKeyException("Round keys not set. Call setupDecRoundKeys() first.");
        }
        byte[] t = new byte[8];
        byte[] key = this.roundKeys;

        t[1] = in[inOff + 1];
        t[3] = in[inOff + 3];
        t[5] = in[inOff + 5];
        t[7] = in[inOff + 7];

        DecIni_Transformation(t, in[inOff + 0], in[inOff + 2], in[inOff + 4], in[inOff + 6], roundKeys[0], roundKeys[1], roundKeys[2], roundKeys[3]);

        int key_offset = 124; // Start from the last round key
        for (int r = 0; r < 32; r++)
        {
            DRound(t, 7, 6, 5, 4, 3, 2, 1, 0, key, key_offset);
            key_offset -= 4;
        }

        DecFin_Transformation(out, t[7], t[1], t[3], t[5], roundKeys[12 * 4], roundKeys[12 * 4 + 1], roundKeys[12 * 4 + 2], roundKeys[12 * 4 + 3], outOff);

        out[outOff + 1] = t[0];
        out[outOff + 3] = t[2];
        out[outOff + 5] = t[4];
        out[outOff + 7] = t[6];
    }

    private void generateRoundKeys(byte[] userKey)
    {
        byte i, j;
        byte[] pUserKey = Arrays.copyOf(userKey, 16);

        for (i = 0; i < BLOCK_SIZE; i++)
        {
            for (j = 0; j < BLOCK_SIZE; j++)
            {
                roundKeys[16 * i + j] = (byte) ((pUserKey[(j - i + 8) & 7] & 0x0ff) + (Delta[16 * i + j] & 0x0ff));
            }
        }
    }

    private byte ROTL(byte x, int n)
    {
        return (byte) ((x << n) | (x >>> (8 - n)));
    }

    private byte ROTR(byte x, int n)
    {
        return (byte) ((x >>> n) | (x << (8 - n)));
    }

    private byte f0(byte x)
    {
        return F0[x & 0x0ff];
    }

    private byte f1(byte x)
    {
        return F1[x & 0x0ff];
    }

    private void EncIni_Transformation(byte[] t, byte x0, byte x2, byte x4, byte x6, byte mk0, byte mk1, byte mk2, byte mk3)
    {
        t[0] = (byte) (((x0 & 0x0ff) + (mk0 & 0x0ff)) & 0x0ff);
        t[2] = (byte) (((x2 & 0x0ff) ^ (mk1 & 0x0ff)) & 0x0ff);
        t[4] = (byte) (((x4 & 0x0ff) + (mk2 & 0x0ff)) & 0x0ff);
        t[6] = (byte) (((x6 & 0x0ff) ^ (mk3 & 0x0ff)) & 0x0ff);
    }

    private void EncFin_Transformation(byte[] out, byte x1, byte x3, byte x5, byte x7, byte mk0, byte mk1, byte mk2, byte mk3, int outOff)
    {
        out[outOff + 0] = (byte) ((x1 & 0x0ff) + (mk0 & 0x0ff));
        out[outOff + 2] = (byte) ((x3 & 0x0ff) ^ (mk1 & 0x0ff));
        out[outOff + 4] = (byte) ((x5 & 0x0ff) + (mk2 & 0x0ff));
        out[outOff + 6] = (byte) ((x7 & 0x0ff) ^ (mk3 & 0x0ff));
    }

    private void Round(byte[] x, int i7, int i6, int i5, int i4, int i3, int i2, int i1, int i0, byte[] key, int key_offset)
    {
        x[i1] = (byte) ((x[i1] + (f1(x[i0]) ^ key[key_offset + 0])) & 0x0ff);
        x[i3] = (byte) ((x[i3] ^ (f0(x[i2]) + key[key_offset + 1])) & 0x0ff);
        x[i5] = (byte) ((x[i5] + (f1(x[i4]) ^ key[key_offset + 2])) & 0x0ff);
        x[i7] = (byte) ((x[i7] ^ (f0(x[i6]) + key[key_offset + 3])) & 0x0ff);
    }

    private void DecIni_Transformation(byte[] t, byte x0, byte x2, byte x4, byte x6, byte mk0, byte mk1, byte mk2, byte mk3)
    {
        t[0] = (byte) (((x0 & 0x0ff) - (mk0 & 0x0ff)) & 0x0ff);
        t[2] = (byte) (((x2 & 0x0ff) ^ (mk1 & 0x0ff)) & 0x0ff);
        t[4] = (byte) (((x4 & 0x0ff) - (mk2 & 0x0ff)) & 0x0ff);
        t[6] = (byte) (((x6 & 0x0ff) ^ (mk3 & 0x0ff)) & 0x0ff);
    }

    private void DecFin_Transformation(byte[] out, byte x1, byte x3, byte x5, byte x7, byte mk0, byte mk1, byte mk2, byte mk3, int outOff)
    {
        out[outOff + 0] = (byte) ((x1 & 0x0ff) - (mk0 & 0x0ff));
        out[outOff + 2] = (byte) ((x3 & 0x0ff) ^ (mk1 & 0x0ff));
        out[outOff + 4] = (byte) ((x5 & 0x0ff) - (mk2 & 0x0ff));
        out[outOff + 6] = (byte) ((x7 & 0x0ff) ^ (mk3 & 0x0ff));
    }

    private void DRound(byte[] x, int i7, int i6, int i5, int i4, int i3, int i2, int i1, int i0, byte[] key, int key_offset)
    {
        x[i1] = (byte) ((x[i1] - (f1(x[i0]) ^ key[key_offset + 0])) & 0x0ff);
        x[i3] = (byte) ((x[i3] ^ (f0(x[i2]) + key[key_offset + 1])) & 0x0ff);
        x[i5] = (byte) ((x[i5] - (f1(x[i4]) ^ key[key_offset + 2])) & 0x0ff);
        x[i7] = (byte) ((x[i7] ^ (f0(x[i6]) + key[key_offset + 3])) & 0x0ff);
    }
}
