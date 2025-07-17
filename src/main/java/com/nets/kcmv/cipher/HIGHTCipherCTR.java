package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.HIGHTEngine;
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

public class HIGHTCipherCTR extends CipherSpi
{

    private final HIGHTEngine engine = new HIGHTEngine();
    private boolean forEncryption;
    private byte[] counter;
    private byte[] keystreamBlock;
    private int byteCount;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public HIGHTCipherCTR()
    {
        this.counter = new byte[engine.getBlockSize()];
        this.keystreamBlock = new byte[engine.getBlockSize()];
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
        return engine.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        int total = buffer.size() + inputLen;
        if (forEncryption)
        {
            return total + (engineGetBlockSize() - (total % engineGetBlockSize()));
        }
        else
        {
            return total; // Decryption output size is determined after unpadding
        }
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
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("HIGHT");
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
        this.forEncryption = (opmode == Cipher.ENCRYPT_MODE);

        if (!(params instanceof IvParameterSpec))
        {
            throw new InvalidAlgorithmParameterException("IvParameterSpec required for CTR mode");
        }

        byte[] iv = ((IvParameterSpec) params).getIV();
        if (iv.length != engine.getBlockSize())
        {
            throw new InvalidAlgorithmParameterException("IV length must be " + engine.getBlockSize() + " bytes for HIGHT/CTR");
        }
        System.arraycopy(iv, 0, this.counter, 0, engine.getBlockSize());
        this.byteCount = 0;

        engine.init(HIGHTEngine.Mode.ENCRYPT, key.getEncoded()); // CTR uses encryption engine for both modes
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
            byteCount = (byteCount + 1) % engine.getBlockSize();
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
        byte[] finalOutput;

        if (forEncryption)
        {
            byte[] padded = padding.pad(data, 0, data.length, engine.getBlockSize());
            finalOutput = new byte[padded.length];
            for (int i = 0; i < padded.length; i++)
            {
                if (byteCount == 0)
                {
                    engine.encrypt(counter, 0, keystreamBlock, 0);
                    incrementCounter();
                }
                finalOutput[i] = (byte) (padded[i] ^ keystreamBlock[byteCount]);
                byteCount = (byteCount + 1) % engine.getBlockSize();
            }
        }
        else
        {
            finalOutput = new byte[data.length];
            for (int i = 0; i < data.length; i++)
            {
                if (byteCount == 0)
                {
                    engine.encrypt(counter, 0, keystreamBlock, 0);
                    incrementCounter();
                }
                finalOutput[i] = (byte) (data[i] ^ keystreamBlock[byteCount]);
                byteCount = (byteCount + 1) % engine.getBlockSize();
            }
            finalOutput = padding.unpad(finalOutput, 0, finalOutput.length, engine.getBlockSize());
        }
        buffer.reset();
        return finalOutput;
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
        for (int i = engine.getBlockSize() - 1; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }
}
