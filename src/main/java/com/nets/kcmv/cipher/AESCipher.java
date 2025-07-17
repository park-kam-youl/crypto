package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.AESEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;
import com.nets.kcmv.cipher.mode.BlockCipherMode;
import com.nets.kcmv.cipher.mode.ECBMode;
import com.nets.kcmv.cipher.mode.CBCMode;
import com.nets.kcmv.cipher.mode.CTRMode;
import com.nets.kcmv.cipher.mode.CFBMode;
import com.nets.kcmv.cipher.mode.OFBMode;
import com.nets.kcmv.cipher.mode.GCMMode;
import com.nets.kcmv.cipher.mode.CCMMode;

import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class AESCipher extends CipherSpi {

    private AESEngine engine = new AESEngine();
    private BlockCipherMode currentMode;

    public AESCipher() {
        // Default mode is ECB
        this.currentMode = new ECBMode(engine);
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (mode.equalsIgnoreCase("ECB")) {
            this.currentMode = new ECBMode(engine);
        } else if (mode.equalsIgnoreCase("CBC")) {
            this.currentMode = new CBCMode(engine);
        } else if (mode.equalsIgnoreCase("CTR")) {
            this.currentMode = new CTRMode(engine);
        } else if (mode.equalsIgnoreCase("CFB")) {
            this.currentMode = new CFBMode(engine);
        } else if (mode.equalsIgnoreCase("OFB")) {
            this.currentMode = new OFBMode(engine);
        } else if (mode.equalsIgnoreCase("GCM")) {
            this.currentMode = new GCMMode(engine);
        } else if (mode.equalsIgnoreCase("CCM")) {
            this.currentMode = new CCMMode(engine);
        } else {
            throw new java.security.NoSuchAlgorithmException("Mode " + mode + " not supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (currentMode instanceof ECBMode) {
            ((ECBMode) currentMode).setPadding(padding);
        } else if (currentMode instanceof CBCMode) {
            ((CBCMode) currentMode).setPadding(padding);
        } else if (currentMode instanceof CTRMode) {
            ((CTRMode) currentMode).setPadding(padding);
        } else if (currentMode instanceof CFBMode) {
            ((CFBMode) currentMode).setPadding(padding);
        } else if (currentMode instanceof OFBMode) {
            ((OFBMode) currentMode).setPadding(padding);
        } else if (currentMode instanceof GCMMode) {
            // GCM mode does not use padding, so no action needed
        } else if (currentMode instanceof CCMMode) {
            // CCM mode does not use padding, so no action needed
        } else {
            throw new NoSuchPaddingException("Padding can only be set for ECB, CBC, CTR, CFB, OFB modes.");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return currentMode.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return currentMode.getOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV() {
        return currentMode.getIV();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters() {
        return null; // Handled by mode implementations if applicable
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        try {
            currentMode.init(opmode, key, null, random);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidKeyException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        currentMode.init(opmode, key, params, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        return currentMode.update(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        return currentMode.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        return currentMode.doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return currentMode.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }
}