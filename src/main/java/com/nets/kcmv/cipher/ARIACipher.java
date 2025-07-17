package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.ARIAEngine;
import com.nets.kcmv.cipher.mode.*; // Import all modes
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.PKCS5Padding;
import com.nets.kcmv.padding.NoPadding;

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
    private ARIAEngine engine; // Add engine instance

    public ARIACipher() {
        try {
            this.engine = new ARIAEngine(128); // Initialize engine with default key size
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e); // Should not happen with a fixed key size
        }
        this.mode = new ECBMode(engine); // Default mode
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        switch (mode.toUpperCase()) {
            case "ECB":
                this.mode = new ECBMode(engine);
                break;
            case "CBC":
                this.mode = new CBCMode(engine);
                break;
            case "CFB":
                this.mode = new CFBMode(engine);
                break;
            case "CTR":
                this.mode = new CTRMode(engine);
                break;
            case "OFB":
                this.mode = new OFBMode(engine);
                break;
            case "GCM":
                this.mode = new GCMMode(engine);
                break;
            case "CCM":
                this.mode = new CCMMode(engine);
                break;
            default:
                throw new java.security.NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        // Delegate padding setting to the current mode
        if (this.mode instanceof ECBMode) {
            ((ECBMode) this.mode).setPadding(padding);
        } else if (this.mode instanceof CBCMode) {
            ((CBCMode) this.mode).setPadding(padding);
        } else if (this.mode instanceof CFBMode) {
            ((CFBMode) this.mode).setPadding(padding);
        } else if (this.mode instanceof CTRMode) {
            ((CTRMode) this.mode).setPadding(padding);
        } else if (this.mode instanceof OFBMode) {
            ((OFBMode) this.mode).setPadding(padding);
        } else if (this.mode instanceof GCMMode) {
            ((GCMMode) this.mode).setPadding(padding);
        } else if (this.mode instanceof CCMMode) {
            ((CCMMode) this.mode).setPadding(padding);
        } else {
            throw new NoSuchPaddingException("Padding can only be set for BlockCipherMode implementations.");
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
