package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.SEEDEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class SEEDCipherCFB extends CipherSpi {

    private final SEEDEngine engine = new SEEDEngine();
    private boolean forEncryption;
    private byte[] iv;
    private byte[] feedback;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public SEEDCipherCFB() {
        feedback = new byte[16];
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("CFB")) {
            throw new java.security.NoSuchAlgorithmException("Only CFB mode is supported");
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
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int total = buffer.size() + inputLen;
        if (forEncryption) {
            return total + (engineGetBlockSize() - (total % engineGetBlockSize()));
        } else {
            return total; // Decryption output size is determined after unpadding
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return iv.clone();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters() {
        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("SEED");
            params.init(new IvParameterSpec(iv));
            return params;
        } catch (java.security.NoSuchAlgorithmException | java.security.spec.InvalidParameterSpecException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new InvalidKeyException("IV required for CFB mode");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE);

        if (!(params instanceof IvParameterSpec)) {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for CFB mode");
        }

        this.iv = ((IvParameterSpec) params).getIV();
        if (this.iv.length != 16) {
            throw new InvalidAlgorithmParameterException("IV length must be 16 bytes for SEED");
        }
        System.arraycopy(this.iv, 0, this.feedback, 0, 16);

        engine.setKey(key.getEncoded());
        buffer.reset();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        int blockSize = engineGetBlockSize();
        int numBlocks = data.length / blockSize;
        byte[] output = new byte[numBlocks * blockSize];

        for (int i = 0; i < numBlocks; i++) {
            byte[] keystream = new byte[blockSize];
            engine.encrypt(feedback, 0, keystream, 0);

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
            byte[] padded = padding.pad(data, 0, data.length, engineGetBlockSize());
            finalOutput = new byte[padded.length];
            for (int i = 0; i < padded.length; i += engineGetBlockSize()) {
                byte[] keystream = new byte[engineGetBlockSize()];
                engine.encrypt(feedback, 0, keystream, 0);

                for (int j = 0; j < engineGetBlockSize(); j++) {
                    finalOutput[i + j] = (byte) (padded[i + j] ^ keystream[j]);
                }
                System.arraycopy(finalOutput, i, feedback, 0, engineGetBlockSize());
            }
        } else {
            if (data.length % engineGetBlockSize() != 0) {
                throw new IllegalBlockSizeException("Input length must be a multiple of the block size for decryption with padding.");
            }
            byte[] decrypted = new byte[data.length];
            for (int i = 0; i < data.length; i += engineGetBlockSize()) {
                byte[] keystream = new byte[engineGetBlockSize()];
                engine.encrypt(feedback, 0, keystream, 0);

                System.arraycopy(data, i, feedback, 0, engineGetBlockSize());
                for (int j = 0; j < engineGetBlockSize(); j++) {
                    decrypted[i + j] = (byte) (data[i + j] ^ keystream[j]);
                }
            }
            finalOutput = padding.unpad(decrypted, 0, decrypted.length, engineGetBlockSize());
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
