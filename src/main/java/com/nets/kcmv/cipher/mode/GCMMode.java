package com.nets.kcmv.cipher.mode;

import com.nets.kcmv.engine.blockcipher.BlockCipherEngine;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class GCMMode implements BlockCipherMode {

    private final BlockCipherEngine engine;
    private boolean forEncryption;

    private byte[] nonce;
    private int macSize;

    private byte[] H;
    private byte[] J0;
    private byte[] ghash;
    private long totalAadLen;
    private long totalDataLen;

    private final ByteArrayOutputStream aadStream = new ByteArrayOutputStream();
    private final ByteArrayOutputStream dataStream = new ByteArrayOutputStream();

    public GCMMode(BlockCipherEngine engine) {
        this.engine = engine;
    }

    @Override
    public void init(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE);

        if (!(params instanceof GCMParameterSpec)) {
            throw new InvalidAlgorithmParameterException("GCMParameterSpec is required for GCM mode");
        }

        GCMParameterSpec gcmParams = (GCMParameterSpec) params;
        this.nonce = gcmParams.getIV();
        this.macSize = gcmParams.getTLen() / 8;

        if (this.macSize < 12 || this.macSize > 16) {
            throw new InvalidAlgorithmParameterException("Invalid tag length: " + this.macSize);
        }

        engine.setKey(key.getEncoded());
        engine.setupEncRoundKeys();

        this.H = new byte[engine.getBlockSize()];
        try {
            this.engine.encrypt(new byte[engine.getBlockSize()], 0, H, 0);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Error during GCM initialization", e);
        }

        if (nonce.length == 12) {
            this.J0 = new byte[engine.getBlockSize()];
            System.arraycopy(nonce, 0, J0, 0, 12);
            J0[engine.getBlockSize() - 1] = 1;
        } else {
            this.J0 = ghash(new byte[0], nonce);
        }

        this.ghash = new byte[engine.getBlockSize()];
        this.totalAadLen = 0;
        this.totalDataLen = 0;
        aadStream.reset();
        dataStream.reset();
    }

    public void updateAAD(byte[] src, int offset, int len) {
        aadStream.write(src, offset, len);
    }

    @Override
    public byte[] update(byte[] input, int inputOffset, int inputLen) {
        dataStream.write(input, inputOffset, inputLen);
        return new byte[0];
    }

    @Override
    public int update(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        dataStream.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    public byte[] doFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        dataStream.write(input, inputOffset, inputLen);
        byte[] data = dataStream.toByteArray();
        byte[] aad = aadStream.toByteArray();
        byte[] out = new byte[getOutputSize(0)];

        try {
            process(data, aad, out, 0);
        } catch (ShortBufferException e) {
            throw new IllegalStateException(e); // Should not happen
        }
        return out;
    }

    @Override
    public int doFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        dataStream.write(input, inputOffset, inputLen);
        byte[] data = dataStream.toByteArray();
        byte[] aad = aadStream.toByteArray();

        if (output.length - outputOffset < getOutputSize(0)) {
            throw new ShortBufferException();
        }

        return process(data, aad, output, outputOffset);
    }

    private int process(byte[] data, byte[] aad, byte[] out, int outOff) throws AEADBadTagException, ShortBufferException {
        int dataLen = forEncryption ? data.length : data.length - macSize;
        if (dataLen < 0) throw new IllegalStateException("Input too short for GCM decryption");

        byte[] counter = Arrays.copyOf(J0, engine.getBlockSize());
        incrementCounter(counter);

        byte[] processedData = new byte[dataLen];
        processCtr(data, 0, dataLen, counter, processedData, 0);

        this.totalAadLen = aad.length * 8L;
        this.totalDataLen = dataLen * 8L;

        this.ghash = ghash(aad, forEncryption ? processedData : data);

        byte[] tag = new byte[engine.getBlockSize()];
        try {
            engine.encrypt(J0, 0, tag, 0);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Error during GCM tag generation", e);
        }
        xor(ghash, ghash, tag);

        if (forEncryption) {
            System.arraycopy(processedData, 0, out, outOff, dataLen);
            System.arraycopy(ghash, 0, out, outOff + dataLen, macSize);
            return dataLen + macSize;
        } else {
            byte[] receivedTag = new byte[macSize];
            System.arraycopy(data, dataLen, receivedTag, 0, macSize);
            if (!Arrays.equals(Arrays.copyOf(ghash, macSize), receivedTag)) {
                throw new AEADBadTagException("Tag mismatch!");
            }
            System.arraycopy(processedData, 0, out, outOff, dataLen);
            return dataLen;
        }
    }

    private void processCtr(byte[] data, int inOff, int inLen, byte[] counter, byte[] out, int outOff) {
        byte[] keystream = new byte[engine.getBlockSize()];
        for (int i = 0; i < inLen; i++) {
            if ((i % engine.getBlockSize()) == 0) {
                incrementCounter(counter);
                try {
                    engine.encrypt(counter, 0, keystream, 0);
                } catch (InvalidKeyException e) {
                    throw new IllegalStateException("Error during GCM CTR encryption", e);
                }
            }
            out[outOff + i] = (byte) (data[inOff + i] ^ keystream[i % engine.getBlockSize()]);
        }
    }

    private byte[] ghash(byte[]... blocks) {
        byte[] result = new byte[engine.getBlockSize()];
        for (byte[] block : blocks) {
            for (int i = 0; i < block.length; i += engine.getBlockSize()) {
                int len = Math.min(engine.getBlockSize(), block.length - i);
                byte[] temp = new byte[engine.getBlockSize()];
                System.arraycopy(block, i, temp, 0, len);
                xor(result, result, temp);
                gmult(result, H, result);
            }
        }
        byte[] lenBlock = new byte[engine.getBlockSize()];
        ByteBuffer.wrap(lenBlock).putLong(totalAadLen).putLong(totalDataLen);
        xor(result, result, lenBlock);
        gmult(result, H, result);
        return result;
    }

    private void gmult(byte[] x, byte[] y, byte[] z) {
        byte[] v = Arrays.copyOf(y, engine.getBlockSize());
        Arrays.fill(z, (byte) 0);

        for (int i = 0; i < engine.getBlockSize(); i++) {
            for (int j = 0; j < 8; j++) {
                if ((x[i] & (1 << (7 - j))) != 0) {
                    xor(z, z, v);
                }
                boolean lsb = (v[engine.getBlockSize() - 1] & 1) != 0;
                for (int k = engine.getBlockSize() - 1; k > 0; k--) {
                    v[k] = (byte) (((v[k] & 0xff) >>> 1) | ((v[k - 1] & 0xff) << 7)); // Fix: v[k+1] should be v[k-1]
                }
                v[0] = (byte) ((v[0] & 0xff) >>> 1);
                if (lsb) {
                    v[0] ^= (byte) 0xe1;
                }
            }
        }
    }

    private void incrementCounter(byte[] counter) {
        for (int i = engine.getBlockSize() - 1; i >= 12; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    private void xor(byte[] z, byte[] x, byte[] y) {
        for (int i = 0; i < engine.getBlockSize(); i++) {
            z[i] = (byte) (x[i] ^ y[i]);
        }
    }

    @Override
    public byte[] getIV() {
        return nonce.clone();
    }

    @Override
    public int getOutputSize(int inputLen) {
        int total = dataStream.size() + inputLen;
        if (forEncryption) {
            return total + macSize;
        } else {
            return total > macSize ? total - macSize : 0;
        }
    }

    @Override
    public int getBlockSize() {
        return engine.getBlockSize();
    }

    // Method to set padding, not used in AEAD modes
    public void setPadding(String paddingScheme) throws javax.crypto.NoSuchPaddingException {
        if (!paddingScheme.equalsIgnoreCase("NoPadding")) {
            throw new javax.crypto.NoSuchPaddingException("Only NoPadding is supported for AEAD modes");
        }
    }
}