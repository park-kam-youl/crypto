package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.ARIAEngine;

import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class ARIACipherGCM extends CipherSpi {

    private ARIAEngine engine;
    private boolean forEncryption;
    private byte[] iv;
    private byte[] aad;
    private byte[] tag;
    private int tagLen;

    // GCM specific fields
    private byte[] H;
    private byte[] J0;
    private byte[] S;
    private byte[] counter;

    public ARIACipherGCM() {
        try {
            engine = new ARIAEngine(128);
        } catch (InvalidKeyException e) {
            // Should not happen
        }
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("GCM")) {
            throw new java.security.NoSuchAlgorithmException("Only GCM mode is supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        if (!padding.equalsIgnoreCase("NoPadding")) {
            throw new NoSuchPaddingException("Only NoPadding is supported");
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return forEncryption ? inputLen + tagLen : inputLen - tagLen;
    }

    @Override
    protected byte[] engineGetIV() {
        return iv.clone();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters() {
        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("GCM");
            params.init(new GCMParameterSpec(tagLen * 8, iv));
            return params;
        } catch (java.security.NoSuchAlgorithmException | java.security.spec.InvalidParameterSpecException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new InvalidKeyException("GCMParameterSpec required for GCM mode");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        // AlgorithmParameters not supported yet
        throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE);

        if (!(params instanceof GCMParameterSpec)) {
            throw new InvalidAlgorithmParameterException("GCMParameterSpec required for GCM mode");
        }

        GCMParameterSpec gcmParams = (GCMParameterSpec) params;
        this.iv = gcmParams.getIV();
        this.tagLen = gcmParams.getTLen() / 8;

        engine.setKey(key.getEncoded());
        engine.setupEncRoundKeys(); // GCM uses encryption for both modes

        // GCM initialization
        H = new byte[16];
        try {
            engine.encrypt(new byte[16], 0, H, 0);
        } catch (InvalidKeyException e) {
            // Should not happen
        }

        if (iv.length == 12) {
            J0 = new byte[16];
            System.arraycopy(iv, 0, J0, 0, 12);
            J0[15] = 1;
        } else {
            J0 = ghash(new byte[0], iv);
        }

        counter = Arrays.copyOf(J0, 16);
        S = new byte[16];
        aad = new byte[0];
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        byte[] newAad = new byte[aad.length + len];
        System.arraycopy(aad, 0, newAad, 0, aad.length);
        System.arraycopy(src, offset, newAad, aad.length, len);
        aad = newAad;
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        byte[] output = new byte[inputLen];
        try {
            engineUpdate(input, inputOffset, inputLen, output, 0);
        } catch (ShortBufferException e) {
            // Should not happen
        }
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        for (int i = 0; i < inputLen; i += 16) {
            incrementCounter();
            byte[] keystream = new byte[16];
            try {
                engine.encrypt(counter, 0, keystream, 0);
            } catch (InvalidKeyException e) {
                // Should not happen
            }

            int n = Math.min(16, inputLen - i);
            for (int j = 0; j < n; j++) {
                output[outputOffset + i + j] = (byte) (input[inputOffset + i + j] ^ keystream[j]);
            }
        }
        return inputLen;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        byte[] output = new byte[engineGetOutputSize(inputLen)];
        try {
            int len = engineDoFinal(input, inputOffset, inputLen, output, 0);
            if (len < output.length) {
                byte[] result = new byte[len];
                System.arraycopy(output, 0, result, 0, len);
                return result;
            }
        } catch (ShortBufferException e) {
            // Should not happen
        }
        return output;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] plainText = new byte[inputLen];
        int len = engineUpdate(input, inputOffset, inputLen, plainText, 0);

        if (forEncryption) {
            System.arraycopy(plainText, 0, output, outputOffset, len);
            S = ghash(aad, plainText);
            incrementCounter();
            byte[] T_block = new byte[16];
            try {
                engine.encrypt(J0, 0, T_block, 0);
            } catch (InvalidKeyException e) {
                // Should not happen
            }
            tag = new byte[tagLen];
            for (int i = 0; i < tagLen; i++) {
                tag[i] = (byte) (S[i] ^ T_block[i]);
            }
            System.arraycopy(tag, 0, output, outputOffset + len, tagLen);
            return len + tagLen;
        } else {
            S = ghash(aad, plainText);
            incrementCounter();
            byte[] T_block = new byte[16];
            try {
                engine.encrypt(J0, 0, T_block, 0);
            } catch (InvalidKeyException e) {
                // Should not happen
            }
            byte[] calculatedTag = new byte[tagLen];
            for (int i = 0; i < tagLen; i++) {
                calculatedTag[i] = (byte) (S[i] ^ T_block[i]);
            }

            byte[] receivedTag = new byte[tagLen];
            System.arraycopy(input, inputOffset + inputLen, receivedTag, 0, tagLen);

            if (!Arrays.equals(calculatedTag, receivedTag)) {
                throw new BadPaddingException("Tag mismatch!");
            }
            System.arraycopy(plainText, 0, output, outputOffset, len);
            return len;
        }
    }

    private void incrementCounter() {
        for (int i = 15; i >= 12; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    private byte[] ghash(byte[] a, byte[] c) {
        byte[] X = new byte[16];
        ghashBlock(X, a);
        ghashBlock(X, c);
        // Length block
        byte[] lenBlock = new byte[16];
        long a_bits = (long)a.length * 8;
        long c_bits = (long)c.length * 8;
        for (int i = 0; i < 8; i++) {
            lenBlock[i] = (byte) (a_bits >> (56 - i * 8));
            lenBlock[i+8] = (byte) (c_bits >> (56 - i * 8));
        }
        ghashBlock(X, lenBlock);
        return X;
    }

    private void ghashBlock(byte[] X, byte[] block) {
        for (int i = 0; i < block.length; i += 16) {
            int n = Math.min(16, block.length - i);
            byte[] temp = new byte[16];
            System.arraycopy(block, i, temp, 0, n);
            for (int j = 0; j < 16; j++) {
                X[j] ^= temp[j];
            }
            gmult(X, H, X);
        }
    }

    private void gmult(byte[] x, byte[] y, byte[] z) {
        byte[] v = Arrays.copyOf(y, 16);
        Arrays.fill(z, (byte) 0);

        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 8; j++) {
                if ((x[i] & (1 << (7 - j))) != 0) {
                    for (int k = 0; k < 16; k++) {
                        z[k] ^= v[k];
                    }
                }
                boolean lsb = (v[15] & 1) != 0;
                for (int k = 15; k > 0; k--) {
                    v[k] = (byte) (((v[k] & 0xff) >>> 1) | ((v[k-1] & 1) << 7));
                }
                v[0] = (byte) ((v[0] & 0xff) >>> 1);
                if (lsb) {
                    v[0] ^= (byte) 0xe1;
                }
            }
        }
    }
}
