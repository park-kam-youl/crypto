package com.nets.kcmv.cipher.mode;

import com.nets.kcmv.engine.blockcipher.BlockCipherEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.ByteArrayOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class ECBMode implements BlockCipherMode {

    private BlockCipherEngine engine;
    private boolean forEncryption;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public ECBMode(BlockCipherEngine engine) {
        this.engine = engine;
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE);
        engine.setKey(key.getEncoded());
        if (this.forEncryption) {
            engine.setupEncRoundKeys();
        } else {
            engine.setupDecRoundKeys();
        }
        buffer.reset();
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        int blockSize = engine.getBlockSize();
        int numBlocks = data.length / blockSize;
        byte[] output = new byte[numBlocks * blockSize];

        for (int i = 0; i < numBlocks; i++) {
            try {
                if (forEncryption) {
                    engine.encrypt(data, i * blockSize, output, i * blockSize);
                } else {
                    engine.decrypt(data, i * blockSize, output, i * blockSize);
                }
            } catch (InvalidKeyException e) {
                // Should have been caught during init
            }
        }
        buffer.reset();
        buffer.write(data, numBlocks * blockSize, data.length % blockSize);
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
        byte[] finalOutput;

        if (forEncryption) {
            byte[] padded = padding.pad(data, 0, data.length, engine.getBlockSize());
            finalOutput = new byte[padded.length];
            for (int i = 0; i < padded.length; i += engine.getBlockSize()) {
                try {
                    engine.encrypt(padded, i, finalOutput, i);
                } catch (InvalidKeyException e) {
                    // Should not happen
                }
            }
        } else {
            byte[] decrypted = new byte[data.length];
            for (int i = 0; i < data.length; i += engine.getBlockSize()) {
                try {
                    engine.decrypt(data, i, decrypted, i);
                } catch (InvalidKeyException e) {
                    // Should not happen
                }
            }

            if (padding instanceof NoPadding) {
                if (data.length % engine.getBlockSize() != 0) {
                    throw new IllegalBlockSizeException("Input length must be a multiple of the block size for NoPadding.");
                }
                finalOutput = decrypted; // No unpadding for NoPadding
            } else { // PKCS5Padding
                finalOutput = padding.unpad(decrypted, 0, decrypted.length, engine.getBlockSize());
            }
        }
        buffer.reset();
        return finalOutput;
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
        return null; // IV not used in ECB mode
    }

    @Override
    public int getOutputSize(int inputLen) {
        int total = buffer.size() + inputLen;
        if (forEncryption) {
            return total + (engine.getBlockSize() - (total % engine.getBlockSize()));
        } else {
            return total;
        }
    }

    @Override
    public int getBlockSize() {
        return engine.getBlockSize();
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