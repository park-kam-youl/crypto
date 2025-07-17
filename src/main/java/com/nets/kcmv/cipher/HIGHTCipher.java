package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.HIGHTEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;

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

public class HIGHTCipher extends CipherSpi {

    private HIGHTEngine engine = new HIGHTEngine();
    private boolean forEncryption;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public HIGHTCipher() {
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("ECB")) {
            throw new java.security.NoSuchAlgorithmException("Only ECB mode is supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (padding.equalsIgnoreCase("NoPadding")) {
            this.padding = new NoPadding();
        } else if (padding.equalsIgnoreCase("PKCS5Padding")) {
            this.padding = new PKCS5Padding();
        } else {
            throw new NoSuchPaddingException("Padding " + padding + " not supported");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return engine.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int total = buffer.size() + inputLen;
        if (forEncryption) {
            // For encryption, consider padding
            return total + (engineGetBlockSize() - (total % engineGetBlockSize()));
        } else {
            // For decryption, output size is determined after unpadding
            return total; 
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters() {
        return null; // No algorithm parameters to return for ECB mode
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        this.forEncryption = (opmode == javax.crypto.Cipher.ENCRYPT_MODE);
        engine.init(forEncryption ? HIGHTEngine.Mode.ENCRYPT : HIGHTEngine.Mode.DECRYPT, key.getEncoded());
        buffer.reset();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        int blockSize = engineGetBlockSize();
        int numBlocks = data.length / blockSize;
        byte[] output = new byte[numBlocks * blockSize];

        for (int i = 0; i < numBlocks; i++) {
            if (forEncryption) {
                engine.encrypt(data, i * blockSize, output, i * blockSize);
            } else {
                engine.decrypt(data, i * blockSize, output, i * blockSize);
            }
        }
        buffer.reset();
        buffer.write(data, numBlocks * blockSize, data.length % blockSize);
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException();
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        byte[] finalOutput;

        if (forEncryption) {
            byte[] padded = padding.pad(data, 0, data.length, engine.getBlockSize());
            finalOutput = new byte[padded.length];
            for (int i = 0; i < padded.length; i += engine.getBlockSize()) {
                engine.encrypt(padded, i, finalOutput, i);
            }
        } else {
            byte[] decrypted = new byte[data.length];
            for (int i = 0; i < data.length; i += engineGetBlockSize()) {
                engine.decrypt(data, i, decrypted, i);
            }

            if (padding instanceof NoPadding) {
                if (data.length % engineGetBlockSize() != 0) {
                    throw new IllegalBlockSizeException("Input length must be a multiple of the block size for NoPadding.");
                }
                finalOutput = decrypted; // No unpadding for NoPadding
            } else { // PKCS5Padding
                finalOutput = padding.unpad(decrypted, 0, decrypted.length, engineGetBlockSize());
            }
        }
        buffer.reset();
        return finalOutput;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length) {
            throw new ShortBufferException();
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }
}
