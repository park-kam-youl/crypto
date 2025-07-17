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

public class CFBMode implements BlockCipherMode {

    private BlockCipherEngine engine;
    private boolean forEncryption;
    private byte[] iv;
    private byte[] feedback;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public CFBMode(BlockCipherEngine engine) {
        this.engine = engine;
        this.feedback = new byte[engine.getBlockSize()];
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE);

        if (!(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for CFB mode");
        }

        this.iv = ((IvParameterSpec) params).getIV();
        if (this.iv.length != engine.getBlockSize()) {
            throw new InvalidAlgorithmParameterException("IV length must be " + engine.getBlockSize() + " bytes for AES");
        }
        System.arraycopy(this.iv, 0, this.feedback, 0, engine.getBlockSize());

        engine.setKey(key.getEncoded());
        engine.setupEncRoundKeys();
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
            byte[] keystream = new byte[blockSize];
            try {
                engine.encrypt(feedback, 0, keystream, 0);
            } catch (InvalidKeyException e) {
                throw new IllegalStateException("Error during CFB update operation", e);
            }

            if (forEncryption) {
                for (int j = 0; j < blockSize; j++) {
                    output[i * blockSize + j] = (byte) (data[i * blockSize + j] ^ keystream[j]);
                }
                System.arraycopy(output, i * blockSize, feedback, 0, blockSize);
            } else {
                System.arraycopy(data, i * blockSize, feedback, 0, blockSize);
                for (int j = 0; j < blockSize; j++) {
                    output[i * blockSize + j] = (byte) (data[i * blockSize + j] ^ keystream[j]);
                }
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
                byte[] keystream = new byte[engine.getBlockSize()];
                try {
                    engine.encrypt(feedback, 0, keystream, 0);
                } catch (InvalidKeyException e) {
                    throw new IllegalStateException("Error during CFB encryption (doFinal)", e);
                }

                for (int j = 0; j < engine.getBlockSize(); j++) {
                    finalOutput[i + j] = (byte) (padded[i + j] ^ keystream[j]);
                }
                System.arraycopy(finalOutput, i, feedback, 0, engine.getBlockSize());
            }
        } else {
            if (data.length % engine.getBlockSize() != 0) {
                throw new IllegalBlockSizeException("Input length must be a multiple of the block size for decryption with padding.");
            }
            byte[] decrypted = new byte[data.length];
            for (int i = 0; i < data.length; i += engine.getBlockSize()) {
                byte[] keystream = new byte[engine.getBlockSize()];
                try {
                    engine.encrypt(feedback, 0, keystream, 0);
                } catch (InvalidKeyException e) {
                    throw new IllegalStateException("Error during CFB decryption (doFinal)", e);
                }

                System.arraycopy(data, i, feedback, 0, engine.getBlockSize());
                for (int j = 0; j < engine.getBlockSize(); j++) {
                    decrypted[i + j] = (byte) (data[i + j] ^ keystream[j]);
                }
            }
            finalOutput = padding.unpad(decrypted, 0, decrypted.length, engine.getBlockSize());
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
        return iv.clone();
    }

    @Override
    public int getOutputSize(int inputLen) {
        int total = buffer.size() + inputLen;
        if (forEncryption) {
            return total + (engine.getBlockSize() - (total % engine.getBlockSize()));
        } else {
            return total; // Decryption output size is determined after unpadding
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