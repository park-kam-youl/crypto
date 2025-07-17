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

public class SEEDCipherCTR extends CipherSpi
{

    private final SEEDEngine engine = new SEEDEngine();
    private byte[] counter;
    private byte[] keystreamBlock;
    private int byteCount;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public SEEDCipherCTR()
    {
        this.counter = new byte[16];
        this.keystreamBlock = new byte[16];
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException
    {
        if (!mode.equalsIgnoreCase("CTR"))
        {
            throw new java.security.NoSuchAlgorithmException("Only CTR mode is supported");
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        if (padding.equalsIgnoreCase("NoPadding"))
        {
            this.padding = new NoPadding();
        }
        else if (padding.equalsIgnoreCase("PKCS5Padding"))
        {
            this.padding = new PKCS5Padding();
        }
        else
        {
            throw new NoSuchPaddingException("Padding " + padding + " not supported");
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        return 16;
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        int total = buffer.size() + inputLen;
        // CTR mode output size is always the same as input size, padding is handled separately
        return total;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return this.counter.clone();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters()
    {
        try
        {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("SEED");
            params.init(new IvParameterSpec(counter));
            return params;
        }
        catch (java.security.NoSuchAlgorithmException | java.security.spec.InvalidParameterSpecException e)
        {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        throw new InvalidKeyException("IV required for CTR mode");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!(params instanceof IvParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for CTR mode");
        }

        byte[] iv = ((IvParameterSpec) params).getIV();
        if (iv.length != 16)
        {
            throw new InvalidAlgorithmParameterException("IV length must be 16 bytes for SEED/CTR");
        }
        System.arraycopy(iv, 0, this.counter, 0, 16);
        this.byteCount = 0;

        engine.setKey(key.getEncoded());
        buffer.reset();
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        throw new InvalidAlgorithmParameterException("AlgorithmParameters not supported");
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        byte[] output = new byte[data.length];

        for (int i = 0; i < data.length; i++)
        {
            if (byteCount == 0)
            {
                engine.encrypt(counter, 0, keystreamBlock, 0);
                incrementCounter();
            }
            output[i] = (byte) (data[i] ^ keystreamBlock[byteCount]);
            byteCount = (byteCount + 1) % 16;
        }
        buffer.reset();
        return output;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException
    {
        byte[] result = engineUpdate(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length)
        {
            throw new ShortBufferException();
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException
    {
        buffer.write(input, inputOffset, inputLen);
        byte[] data = buffer.toByteArray();
        byte[] finalOutput = new byte[data.length];

        for (int i = 0; i < data.length; i++)
        {
            if (byteCount == 0)
            {
                engine.encrypt(counter, 0, keystreamBlock, 0);
                incrementCounter();
            }
            finalOutput[i] = (byte) (data[i] ^ keystreamBlock[byteCount]);
            byteCount = (byteCount + 1) % 16;
        }

        // Apply padding/unpadding only if specified
        if (padding instanceof NoPadding)
        {
            return finalOutput;
        }
        else
        {
            return padding.unpad(finalOutput, 0, finalOutput.length, engine.getBlockSize());
        }
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        if (output.length - outputOffset < result.length)
        {
            throw new ShortBufferException();
        }
        System.arraycopy(result, 0, output, outputOffset, result.length);
        return result.length;
    }

    private void incrementCounter()
    {
        for (int i = 15; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }
}
