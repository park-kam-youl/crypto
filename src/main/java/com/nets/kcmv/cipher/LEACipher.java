package com.nets.kcmv.cipher;

import com.nets.kcmv.engine.blockcipher.LeaEngine;
import com.nets.kcmv.cipher.mode.BlockCipherMode;
import com.nets.kcmv.cipher.mode.ECBMode;
import com.nets.kcmv.cipher.mode.CBCMode;
import com.nets.kcmv.cipher.mode.CFBMode;
import com.nets.kcmv.cipher.mode.CTRMode;
import com.nets.kcmv.cipher.mode.GCMMode;
import com.nets.kcmv.cipher.mode.OFBMode;
import com.nets.kcmv.cipher.mode.CCMMode;
import com.nets.kcmv.engine.blockcipher.BlockCipher; // Import the new BlockCipher

import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class LEACipher extends CipherSpi
{

    private BlockCipherMode mode;

    private LeaEngine engine; // Add engine instance

    public LEACipher()
    {
        this.engine = new LeaEngine();
    }

    @Override
    protected void engineSetMode(String mode) throws java.security.NoSuchAlgorithmException
    {
        if (mode.equalsIgnoreCase("ECB"))
        {
            this.mode = new ECBMode(engine);
        }
        else if (mode.equalsIgnoreCase("CBC"))
        {
            this.mode = new CBCMode(engine);
        }
        else if (mode.equalsIgnoreCase("CFB"))
        {
            this.mode = new CFBMode(engine);
        }
        else if (mode.equalsIgnoreCase("CTR"))
        {
            this.mode = new CTRMode(engine);
        }
        else if (mode.equalsIgnoreCase("OFB"))
        {
            this.mode = new OFBMode(engine);
        }
        else if (mode.equalsIgnoreCase("GCM"))
        {
            this.mode = new GCMMode(engine);
        }
        else if (mode.equalsIgnoreCase("CCM"))
        {
            this.mode = new CCMMode(engine);
        }
        else
        {
            throw new java.security.NoSuchAlgorithmException("Unsupported mode: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException
    {
        if (this.mode instanceof ECBMode)
        {
            ((ECBMode) this.mode).setPadding(padding);
        }
        else if (this.mode instanceof CBCMode)
        {
            ((CBCMode) this.mode).setPadding(padding);
        }
        else if (this.mode instanceof CFBMode)
        {
            ((CFBMode) this.mode).setPadding(padding);
        }
        else if (this.mode instanceof CTRMode)
        {
            ((CTRMode) this.mode).setPadding(padding);
        }
        else if (this.mode instanceof OFBMode)
        {
            ((OFBMode) this.mode).setPadding(padding);
        }
        else if (this.mode instanceof GCMMode)
        {
            ((GCMMode) this.mode).setPadding(padding);
        }
        else if (this.mode instanceof CCMMode)
        {
            ((CCMMode) this.mode).setPadding(padding);
        }
        else
        {
            throw new NoSuchPaddingException("Padding can only be set for BlockCipherMode implementations.");
        }
    }

    @Override
    protected int engineGetBlockSize()
    {
        return mode.getBlockSize();
    }

    @Override
    protected int engineGetOutputSize(int inputLen)
    {
        return mode.getOutputSize(inputLen);
    }

    @Override
    protected byte[] engineGetIV()
    {
        return mode.getIV();
    }

    @Override
    protected java.security.AlgorithmParameters engineGetParameters()
    {
        if (mode.getIV() != null)
        {
            try
            {
                java.security.AlgorithmParameters params = java.security.AlgorithmParameters.getInstance("LEA");
                params.init(new IvParameterSpec(mode.getIV()));
                return params;
            }
            catch (java.security.NoSuchAlgorithmException | java.security.spec.InvalidParameterSpecException e)
            {
                throw new IllegalStateException(e);
            }
        }
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException
    {
        BlockCipher.Mode leaMode = (opmode == Cipher.ENCRYPT_MODE) ? BlockCipher.Mode.ENCRYPT : BlockCipher.Mode.DECRYPT;
        engine.init(leaMode, key.getEncoded());
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        BlockCipher.Mode leaMode = (opmode == Cipher.ENCRYPT_MODE) ? BlockCipher.Mode.ENCRYPT : BlockCipher.Mode.DECRYPT;
        engine.init(leaMode, key.getEncoded());
        // Handle IV for modes that require it
        if (params instanceof IvParameterSpec)
        {
            mode.init(leaMode, key.getEncoded(), ((IvParameterSpec) params).getIV());
        }
        else
        {
            mode.init(leaMode, key.getEncoded());
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
        if (params != null)
        {
            try
            {
                AlgorithmParameterSpec paramSpec = params.getParameterSpec(IvParameterSpec.class);
                BlockCipher.Mode leaMode = (opmode == Cipher.ENCRYPT_MODE) ? BlockCipher.Mode.ENCRYPT : BlockCipher.Mode.DECRYPT;
                engine.init(leaMode, key.getEncoded());
                mode.init(leaMode, key.getEncoded(), ((IvParameterSpec) paramSpec).getIV());
            }
            catch (java.security.spec.InvalidParameterSpecException e)
            {
                throw new InvalidAlgorithmParameterException(e);
            }
        }
        else
        {
            BlockCipher.Mode leaMode = (opmode == Cipher.ENCRYPT_MODE) ? BlockCipher.Mode.ENCRYPT : BlockCipher.Mode.DECRYPT;
            engine.init(leaMode, key.getEncoded());
            mode.init(leaMode, key.getEncoded());
        }
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen)
    {
        return mode.update(input, inputOffset, inputLen);
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException
    {
        return mode.update(input, inputOffset, inputLen, output, outputOffset);
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException
    {
        return mode.doFinal(input, inputOffset, inputLen);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException
    {
        return mode.doFinal(input, inputOffset, inputLen, output, outputOffset);
    }
}
