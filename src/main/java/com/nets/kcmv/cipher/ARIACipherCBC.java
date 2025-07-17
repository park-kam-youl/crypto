package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.ARIAEngine;
import com.nets.kcmv.cipher.mode.BlockCipherMode;
import com.nets.kcmv.cipher.mode.CBCMode;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class ARIACipherCBC extends CipherSpi {

    private BlockCipherMode mode;

    public ARIACipherCBC() {
        try {
            this.mode = new CBCMode(new ARIAEngine(128));
        } catch (InvalidKeyException e) {
            // Should not happen
            throw new RuntimeException(e);
        }
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("CBC")) {
            throw new java.security.NoSuchAlgorithmException("Only CBC mode is supported");
        }
        // Mode is already set in constructor, no action needed here for CBC
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (this.mode instanceof CBCMode) {
            ((CBCMode) this.mode).setPadding(padding);
        } else {
            throw new NoSuchPaddingException("Padding can only be set for CBCMode.");
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
        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("ARIA");
            params.init(new IvParameterSpec(mode.getIV()));
            return params;
        } catch (java.security.NoSuchAlgorithmException | java.security.spec.InvalidParameterSpecException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new InvalidKeyException("IV required for CBC mode");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        mode.init(opmode, key, params, random);
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
