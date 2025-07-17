package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.SEEDEngine;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class SEEDCipherCCM extends CipherSpi {

    private final SEEDEngine engine = new SEEDEngine();
    private boolean forEncryption;

    private byte[] nonce;
    private int macSize;

    private final ByteArrayOutputStream aadStream = new ByteArrayOutputStream();
    private final ByteArrayOutputStream dataStream = new ByteArrayOutputStream();

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException {
        if (!mode.equalsIgnoreCase("CCM")) {
            throw new java.security.NoSuchAlgorithmException("Only CCM mode is supported");
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
        int total = dataStream.size() + inputLen;
        if (forEncryption) {
            return total + macSize;
        } else {
            return total > macSize ? total - macSize : 0;
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return nonce.clone();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters() {
        try {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("CCM");
            params.init(new GCMParameterSpec(macSize * 8, nonce));
            return params;
        } catch (java.security.NoSuchAlgorithmException | java.security.spec.InvalidParameterSpecException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        throw new InvalidKeyException("GCMParameterSpec required for CCM mode");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("GCMParameterSpec is required");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE);

        if (!(params instanceof GCMParameterSpec)) {
            throw new InvalidAlgorithmParameterException("GCMParameterSpec is required for CCM mode");
        }

        GCMParameterSpec gcmParams = (GCMParameterSpec) params;
        this.nonce = gcmParams.getIV();
        this.macSize = gcmParams.getTLen() / 8;

        if (this.macSize < 4 || this.macSize > 16 || this.macSize % 2 != 0) {
            throw new InvalidAlgorithmParameterException("Invalid tag length: " + this.macSize);
        }

        if (this.nonce == null || this.nonce.length < 7 || this.nonce.length > 13) {
            throw new InvalidAlgorithmParameterException("Invalid nonce length: " + (this.nonce != null ? this.nonce.length : 0));
        }

        engine.setKey(key.getEncoded());
        aadStream.reset();
        dataStream.reset();
    }

    @Override
    protected void engineUpdateAAD(byte[] src, int offset, int len) {
        aadStream.write(src, offset, len);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        dataStream.write(input, inputOffset, inputLen);
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        dataStream.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        dataStream.write(input, inputOffset, inputLen);
        byte[] data = dataStream.toByteArray();
        byte[] aad = aadStream.toByteArray();
        byte[] result = new byte[engineGetOutputSize(0)];

        try {
            process(data, 0, data.length, aad, result, 0);
        } catch (ShortBufferException e) {
            throw new IllegalStateException(e); // Should not happen
        }
        return result;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        dataStream.write(input, inputOffset, inputLen);
        byte[] data = dataStream.toByteArray();
        byte[] aad = aadStream.toByteArray();

        if (output.length - outputOffset < engineGetOutputSize(0)) {
            throw new ShortBufferException();
        }

        return process(data, 0, data.length, aad, output, outputOffset);
    }

    private int process(byte[] data, int inOff, int inLen, byte[] aad, byte[] out, int outOff) throws AEADBadTagException, ShortBufferException {
        int q = 15 - nonce.length;
        if (q < 2) {
            throw new IllegalStateException("Nonce length is too long.");
        }

        byte[] b0 = formatB0(inLen, aad.length, macSize, nonce);
        byte[] mac = calculateMac(data, inOff, inLen, aad, b0);

        byte[] counter = new byte[16];
        counter[0] = (byte) (q - 1);
        System.arraycopy(nonce, 0, counter, 1, nonce.length);

        int outLen;
        if (forEncryption) {
            outLen = inLen + macSize;
            if (out.length - outOff < outLen) throw new ShortBufferException();

            byte[] macBlock = new byte[16];
            engine.encrypt(counter, 0, macBlock, 0);
            for (int i = 0; i < macSize; i++) {
                mac[i] ^= macBlock[i];
            }

            processCtr(data, inOff, inLen, counter, out, outOff);
            System.arraycopy(mac, 0, out, outOff + inLen, macSize);

        } else {
            outLen = inLen - macSize;
            if (outLen < 0) throw new IllegalStateException("Input too short for CCM decryption");
            if (out.length - outOff < outLen) throw new ShortBufferException();

            byte[] receivedMac = new byte[macSize];
            System.arraycopy(data, inOff + outLen, receivedMac, 0, macSize);

            byte[] macBlock = new byte[16];
            engine.encrypt(counter, 0, macBlock, 0);
            for (int i = 0; i < macSize; i++) {
                receivedMac[i] ^= macBlock[i];
            }

            processCtr(data, inOff, outLen, counter, out, outOff);

            byte[] calculatedMac = calculateMac(out, outOff, outLen, aad, b0);

            if (!Arrays.equals(Arrays.copyOf(calculatedMac, macSize), receivedMac)) {
                throw new AEADBadTagException("Tag mismatch");
            }
        }
        return outLen;
    }

    private void processCtr(byte[] data, int inOff, int inLen, byte[] counter, byte[] out, int outOff) {
        byte[] keystream = new byte[16];
        for (int i = 0; i < inLen; i++) {
            if ((i % 16) == 0) {
                incrementCounter(counter);
                engine.encrypt(counter, 0, keystream, 0);
            }
            out[outOff + i] = (byte) (data[inOff + i] ^ keystream[i % 16]);
        }
    }

    private byte[] calculateMac(byte[] data, int inOff, int inLen, byte[] aad, byte[] b0) {
        byte[] cbcMac = new byte[16];
        engine.encrypt(b0, 0, cbcMac, 0);

        if (aad.length > 0) {
            byte[] aadBlock = formatAad(aad);
            for (int i = 0; i < aadBlock.length; i += 16) {
                xor(cbcMac, 0, aadBlock, i, 16);
                engine.encrypt(cbcMac, 0, cbcMac, 0);
            }
        }

        for (int i = 0; i < inLen; i += 16) {
            int len = Math.min(16, inLen - i);
            byte[] block = new byte[16];
            System.arraycopy(data, inOff + i, block, 0, len);
            xor(cbcMac, 0, block, 0, 16);
            engine.encrypt(cbcMac, 0, cbcMac, 0);
        }
        return cbcMac;
    }

    private byte[] formatB0(int payloadLen, int aadLen, int macLen, byte[] nonce) {
        byte[] b0 = new byte[16];
        int q = 15 - nonce.length;
        b0[0] = (byte) ((aadLen > 0 ? 0x40 : 0) | (((macLen - 2) / 2) << 3) | (q - 1));
        System.arraycopy(nonce, 0, b0, 1, nonce.length);
        for (int i = 1 + nonce.length; i < 15; i++) {
            b0[i] = 0;
        }
        int len = payloadLen;
        for (int i = 15; i > 15 - q; i--) {
            b0[i] = (byte) len;
            len >>>= 8;
        }
        return b0;
    }

    private byte[] formatAad(byte[] aad) {
        int len = aad.length;
        int prepended;
        if (len < 0xFF00) {
            prepended = 2;
        } else {
            prepended = 6;
        }

        int totalLen = len + prepended;
        int paddedLen = (totalLen + 15) & ~15;
        byte[] formatted = new byte[paddedLen];

        if (prepended == 2) {
            formatted[0] = (byte) (len >> 8);
            formatted[1] = (byte) len;
        } else {
            formatted[0] = (byte) 0xFF;
            formatted[1] = (byte) 0xFE;
            formatted[2] = (byte) (len >> 24);
            formatted[3] = (byte) (len >> 16);
            formatted[4] = (byte) (len >> 8);
            formatted[5] = (byte) len;
        }

        System.arraycopy(aad, 0, formatted, prepended, len);
        return formatted;
    }

    private void incrementCounter(byte[] counter) {
        for (int i = 15; i >= 15 - (15 - nonce.length) + 1; i--) {
            if (++counter[i] != 0) {
                break;
            }
        }
    }

    private void xor(byte[] a, int aOff, byte[] b, int bOff, int len) {
        for (int i = 0; i < len; i++) {
            a[aOff + i] ^= b[bOff + i];
        }
    }
}
