package com.nets.kcmv.cipher.mode;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

public interface BlockCipherMode {
    void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException;
    byte[] update(byte[] input, int inputOffset, int inputLen);
    int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException;
    byte[] doFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException;
    int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException;
    byte[] getIV();
    int getOutputSize(int inputLen);
    int getBlockSize();
}