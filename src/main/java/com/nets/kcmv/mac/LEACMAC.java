package com.nets.kcmv.mac;

import com.nets.kcmv.engine.blockcipher.LeaEngine;

import javax.crypto.MacSpi;
import javax.crypto.SecretKey;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class LEACMAC extends MacSpi {

    private static final int BLOCK_SIZE = 16;
    private static final byte CONSTANT_128 = (byte) 0x87;

    private final LeaEngine engine = new LeaEngine();
    private final byte[] buffer = new byte[BLOCK_SIZE];
    private int bufferOffset;
    private byte[] mac;

    private byte[] k1;
    private byte[] k2;

    @Override
    protected int engineGetMacLength() {
        return BLOCK_SIZE;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) throws InvalidKeyException, java.security.InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Key must be an instance of SecretKey");
        }
        if (params != null) {
            throw new java.security.InvalidAlgorithmParameterException("LEA-CMAC does not use parameters");
        }

        engine.setKey(key.getEncoded());
        engine.setupEncRoundKeys();

        // Generate subkeys K1 and K2
        byte[] L = new byte[BLOCK_SIZE];
        engine.encrypt(new byte[BLOCK_SIZE], 0, L, 0);

        k1 = generateSubkey(L);
        k2 = generateSubkey(k1.clone());

        engineReset();
    }

    @Override
    protected void engineUpdate(byte input) {
        if (bufferOffset == BLOCK_SIZE) {
            processBlock(buffer, 0);
            bufferOffset = 0;
        }
        buffer[bufferOffset++] = input;
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        int remaining = len;
        int currentOffset = offset;

        if (bufferOffset > 0) {
            int toCopy = Math.min(remaining, BLOCK_SIZE - bufferOffset);
            System.arraycopy(input, currentOffset, buffer, bufferOffset, toCopy);
            bufferOffset += toCopy;
            remaining -= toCopy;
            currentOffset += toCopy;

            if (bufferOffset == BLOCK_SIZE) {
                processBlock(buffer, 0);
                bufferOffset = 0;
            }
        }

        while (remaining >= BLOCK_SIZE) {
            processBlock(input, currentOffset);
            remaining -= BLOCK_SIZE;
            currentOffset += BLOCK_SIZE;
        }

        if (remaining > 0) {
            System.arraycopy(input, currentOffset, buffer, 0, remaining);
            bufferOffset = remaining;
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] finalBlock = new byte[BLOCK_SIZE];
        boolean isCompleteBlock = (bufferOffset == BLOCK_SIZE);

        if (isCompleteBlock) {
            xor(finalBlock, buffer, k1);
        } else {
            System.arraycopy(buffer, 0, finalBlock, 0, bufferOffset);
            finalBlock[bufferOffset] = (byte) 0x80;
            // The rest is already zero-padded by array initialization
            xor(finalBlock, finalBlock, k2);
        }

        processBlock(finalBlock, 0);

        byte[] result = Arrays.copyOf(mac, BLOCK_SIZE);
        engineReset();
        return result;
    }

    @Override
    protected void engineReset() {
        this.mac = new byte[BLOCK_SIZE];
        this.bufferOffset = 0;
        Arrays.fill(buffer, (byte) 0);
    }

    private void processBlock(byte[] in, int inOff) {
        xor(mac, mac, in, inOff);
        try {
            engine.encrypt(mac, 0, mac, 0);
        } catch (InvalidKeyException e) {
            // This should not happen as key is already set
            throw new RuntimeException(e);
        }
    }

    private byte[] generateSubkey(byte[] key) {
        byte[] subkey = Arrays.copyOf(key, BLOCK_SIZE);
        boolean msbSet = (subkey[0] & 0x80) != 0;

        for (int i = 0; i < BLOCK_SIZE - 1; i++) {
            subkey[i] = (byte) (((subkey[i] & 0xff) << 1) | ((subkey[i + 1] & 0xff) >>> 7));
        }
        subkey[BLOCK_SIZE - 1] = (byte) ((subkey[BLOCK_SIZE - 1] & 0xff) << 1);

        if (msbSet) {
            subkey[BLOCK_SIZE - 1] ^= CONSTANT_128;
        }
        return subkey;
    }

    private void xor(byte[] out, byte[] in1, byte[] in2) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            out[i] = (byte) (in1[i] ^ in2[i]);
        }
    }

    private void xor(byte[] out, byte[] in1, byte[] in2, int in2Off) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            out[i] = (byte) (in1[i] ^ in2[in2Off + i]);
        }
    }
}
