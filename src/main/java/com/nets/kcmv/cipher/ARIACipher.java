package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.ARIAEngine;
import com.nets.kcmv.cipher.mode.BlockCipherMode;
import com.nets.kcmv.cipher.mode.ECBMode;

import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.SecureRandom;

public class ARIACipher extends CipherSpi {

    private BlockCipherMode mode;

    public ARIACipher() {
        try {
            this.mode = new ECBMode(new ARIAEngine(128));
        } catch (InvalidKeyException e) {
            // This should not happen with a static key size
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("ECB")) {
            throw new java.security.NoSuchAlgorithmException("Only ECB mode is supported");
        }
        // Mode is already set in constructor, no action needed here for ECB
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (this.mode instanceof ECBMode) {
            ((ECBMode) this.mode).setPadding(padding);
        } else {
            throw new NoSuchPaddingException("Padding can only be set for ECBMode.");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return mode.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return mode.getOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
        return mode.getIV();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters() {
        return null; // No algorithm parameters to return for ECB mode
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            mode.init(opmode, key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        mode.init(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return mode.update(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return mode.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return mode.doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return mode.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }
}
