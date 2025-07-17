package com.nets.kcmv.engine.blockcipher;

import java.security.InvalidKeyException;

public interface BlockCipherEngine
{
    void setKey(byte[] key) throws InvalidKeyException;

    void setupEncRoundKeys() throws InvalidKeyException;

    void setupDecRoundKeys() throws InvalidKeyException;

    void encrypt(byte[] in, int inOffset, byte[] out, int outOffset) throws InvalidKeyException;

    void decrypt(byte[] in, int inOffset, byte[] out, int outOffset) throws InvalidKeyException;

    int getBlockSize();
}
