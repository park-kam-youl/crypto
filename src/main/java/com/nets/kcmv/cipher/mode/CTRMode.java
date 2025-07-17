package com.nets.kcmv.cipher.mode;

import com.nets.kcmv.engine.blockcipher.BlockCipherEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class CTRMode implements BlockCipherMode {

    private BlockCipherEngine engine;
    private byte[] counter;
    private byte[] keystreamBlock;
    private int byteCount;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public CTRMode(BlockCipherEngine engine) {
        this.engine = engine;
        this.counter = new byte[engine.getBlockSize()];
        this.keystreamBlock = new byte[engine.getBlockSize()];
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        // forEncryption is not used in CTR, but kept for consistency with other modes

        if (!(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for CTR mode");
        }

        byte[] iv = ((IvParameterSpec) params).getIV();
        if (iv.length != engine.getBlockSize()) {
            throw new InvalidAlgorithmParameterException("IV length must be " + engine.getBlockSize() + " bytes for AES/CTR");
        }
        System.arraycopy(iv, 0, this.counter, 0, engine.getBlockSize());
        this.byteCount = 0;

        engine.setKey(key.getEncoded());
        engine.setupEncRoundKeys();
        buffer.reset();
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        byte[] output = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            if (byteCount == 0) {
                try {
                    engine.encrypt(counter, 0, keystreamBlock, 0);
                } catch (InvalidKeyException e) {
                    throw new IllegalStateException("Error during CTR update operation", e);
                }
                incrementCounter();
            }
            output[i] = (byte) (data[i] ^ keystreamBlock[byteCount]);
            byteCount = (byteCount + 1) % engine.getBlockSize();
        }
        buffer.reset();
        return output;
    }

    @Override
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        byte[] result = update(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException();
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    public byte[] doFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        byte[] finalOutput = new byte[data.length];

        for (int i = 0; i < data.length; i++) {
            if (byteCount == 0) {
                try {
                    engine.encrypt(counter, 0, keystreamBlock, 0);
                } catch (InvalidKeyException e) {
                    throw new IllegalStateException("Error during CTR doFinal operation", e);
                }
                incrementCounter();
            }
            finalOutput[i] = (byte) (data[i] ^ keystreamBlock[byteCount]);
            byteCount = (byteCount + 1) % engine.getBlockSize();
        }

        // Apply padding/unpadding only if specified
        if (padding instanceof NoPadding) {
            return finalOutput;
        } else {
            return padding.unpad(finalOutput, 0, finalOutput.length, engine.getBlockSize());
        }
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = doFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException();
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    public byte[] getIV() {
        return this.counter.clone();
    }

    @Override
    public int getOutputSize(int inputLen) {
        int total = buffer.size() + inputLen;
        // CTR mode output size is always the same as input size, padding is handled separately
        return total;
    }

    @Override
    public int getBlockSize() {
        return engine.getBlockSize();
    }

    private void incrementCounter() {
        for (int i = engine.getBlockSize() - 1; i >= 0; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    // Method to set padding, called by CipherSpi
    public void setPadding(String paddingScheme) throws javax.crypto.NoSuchPaddingException {
        if (paddingScheme.equalsIgnoreCase("NoPadding")) {
            this.padding = new NoPadding();
        } else if (paddingScheme.equalsIgnoreCase("PKCS5Padding")) {
            this.padding = new PKCS5Padding();
        } else {
            throw new javax.crypto.NoSuchPaddingException("Padding " + paddingScheme + " not supported");
        }
    }
}