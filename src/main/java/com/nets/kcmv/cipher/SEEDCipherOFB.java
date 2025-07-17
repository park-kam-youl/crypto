package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.SEEDEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class SEEDCipherOFB extends CipherSpi
{

    private final SEEDEngine engine = new SEEDEngine();
    private byte[] iv;
    private byte[] feedback;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public SEEDCipherOFB()
    {
        feedback = new byte[16];
        this.padding = new NoPadding(); // Default to NoPadding
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException
    {
        if (!mode.equalsIgnoreCase("OFB"))
        {
            throw new java.security.NoSuchAlgorithmException("Only OFB mode is supported");
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
        // OFB mode output size is always the same as input size, padding is handled separately
        return total;
    }

    @Override
    protected byte[] engineGetIV()
    {
        return iv.clone();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters()
    {
        try
        {
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("SEED");
            params.init(new IvParameterSpec(iv));
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
        throw new InvalidKeyException("IV required for OFB mode");
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (!(params instanceof IvParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for OFB mode");
        }

        this.iv = ((IvParameterSpec) params).getIV();
        if (this.iv.length != 16)
        {
            throw new InvalidAlgorithmParameterException("IV length must be 16 bytes for SEED");
        }
        System.arraycopy(this.iv, 0, this.feedback, 0, 16);

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
        int blockSize = engine.getBlockSize();
        int numBlocks = data.length / blockSize;
        byte[] output = new byte[numBlocks * blockSize];

        for (int i = 0; i < numBlocks; i++)
        {
            engine.encrypt(feedback, 0, feedback, 0);
            for (int j = 0; j < blockSize; j++)
            {
                output[i * blockSize + j] = (byte) (data[i * blockSize + j] ^ feedback[j]);
            }
        }
        buffer.reset();
        buffer.write(data, numBlocks * blockSize, data.length % blockSize);
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

        for (int i = 0; i < data.length; i += engine.getBlockSize())
        {
            engine.encrypt(feedback, 0, feedback, 0);
            for (int j = 0; j < engine.getBlockSize(); j++)
            {
                finalOutput[i + j] = (byte) (data[i + j] ^ feedback[j]);
            }
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
}
