package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.ARIAEngine;
import com.nets.kcmv.padding.BlockCipherPadding;
import com.nets.kcmv.padding.NoPadding;
import com.nets.kcmv.padding.PKCS5Padding;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class ARIACipherCTR extends CipherSpi
{

    private final ARIAEngine engine;
    private boolean forEncryption;
    private byte[] counter;
    private byte[] keystreamBlock;
    private int byteCount;
    private BlockCipherPadding padding;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    public ARIACipherCTR() throws InvalidKeyException
    {
        engine = new ARIAEngine(128);
        counter = new byte[16];
        keystreamBlock = new byte[16];
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
            java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("ARIA");
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
        if (iv.length != 16)
        {
            throw new InvalidAlgorithmParameterException("IV length must be 16 bytes for ARIA/CTR");
        }
        System.arraycopy(iv, 0, this.counter, 0, 16);
        this.byteCount = 0;

        engine.setKey(key.getEncoded());
        engine.setupEncRoundKeys(); // CTR uses encryption engine for both modes
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
                try
                {
                    engine.encrypt(counter, 0, keystreamBlock, 0);
                }
                catch (InvalidKeyException e)
                {
                    // Should not happen
                }
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
        byte[] finalOutput;

        if (forEncryption)
        {
            byte[] padded = padding.pad(data, 0, data.length, engineGetBlockSize());
            finalOutput = new byte[padded.length];
            for (int i = 0; i < padded.length; i++)
            {
                if (byteCount == 0)
                {
                    try
                    {
                        engine.encrypt(counter, 0, keystreamBlock, 0);
                    }
                    catch (InvalidKeyException e)
                    {
                        // Should not happen
                    }
                    incrementCounter();
                }
                finalOutput[i] = (byte) (padded[i] ^ keystreamBlock[byteCount]);
                byteCount = (byteCount + 1) % 16;
            }
        }
        else
        {
            finalOutput = new byte[data.length];
            for (int i = 0; i < data.length; i++)
            {
                if (byteCount == 0)
                {
                    try
                    {
                        engine.encrypt(counter, 0, keystreamBlock, 0);
                    }
                    catch (InvalidKeyException e)
                    {
                        // Should not happen
                    }
                    incrementCounter();
                }
                finalOutput[i] = (byte) (data[i] ^ keystreamBlock[byteCount]);
                byteCount = (byteCount + 1) % 16;
            }
            finalOutput = padding.unpad(finalOutput, 0, finalOutput.length, engineGetBlockSize());
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
        for (int i = 15; i >= 0; i--)
        {
            if (++counter[i] != 0)
            {
                break;
            }
        }
    }

}
