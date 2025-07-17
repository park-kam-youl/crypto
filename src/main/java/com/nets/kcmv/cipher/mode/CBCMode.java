package com.nets.kcmv.cipher.mode;

import com.nets.kcmv.engine.blockcipher.BlockCipher;
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

public class CBCMode implements BlockCipherMode {

    private BlockCipher engine;
    private boolean forEncryption;
    private byte[] iv;
    private byte[] feedback;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public CBCMode(BlockCipher engine) {
        this.engine = engine;
        this.feedback = new byte[engine.getBlockSize()];
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE);

        if (!(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for CBC mode");
        }

        this.iv = ((IvParameterSpec) params).getIV();
        if (this.iv.length != engine.getBlockSize()) {
            throw new InvalidAlgorithmParameterException("IV length must be " + engine.getBlockSize() + " bytes for AES");
        }
        System.arraycopy(this.iv, 0, this.feedback, 0, engine.getBlockSize());

        engine.init(this.forEncryption ? BlockCipher.Mode.ENCRYPT : BlockCipher.Mode.DECRYPT, key.getEncoded());
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
            if (forEncryption) {
                for (int j = 0; j < blockSize; j++) {
                    feedback[j] ^= data[i * blockSize + j];
                }
                engine.encrypt(feedback, 0, feedback, 0);
                System.arraycopy(feedback, 0, output, i * blockSize, blockSize);
            } else {
                byte[] temp = new byte[blockSize];
                System.arraycopy(data, i * blockSize, temp, 0, blockSize);
                engine.decrypt(data, i * blockSize, output, i * blockSize);
                for (int j = 0; j < blockSize; j++) {
                    output[i * blockSize + j] ^= feedback[j];
                }
                feedback = temp;
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
                for (int j = 0; j < engine.getBlockSize(); j++) {
                    feedback[j] ^= padded[i + j];
                }
                engine.encrypt(feedback, 0, feedback, 0);
                System.arraycopy(feedback, 0, finalOutput, i, engine.getBlockSize());
            }
        } else {
            byte[] decrypted = new byte[data.length];
            for (int i = 0; i < data.length; i += engine.getBlockSize()) {
                byte[] temp = new byte[engine.getBlockSize()];
                System.arraycopy(data, i, temp, 0, engine.getBlockSize());
                engine.decrypt(data, i, decrypted, i);
                for (int j = 0; j < engine.getBlockSize(); j++) {
                    decrypted[i + j] ^= feedback[j];
                }
                feedback = temp;
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