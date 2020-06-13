/******************************************************************************
MIT License

  Project: OpenFIPS201
Copyright: (c) 2017 Commonwealth of Australia
   Author: Kim O'Sullivan - Makina (kim@makina.com.au)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

package com.makina.security.OpenFIPS201;

import javacardx.crypto.*;
import javacard.security.*;
import javacard.framework.*;

/**
 * Provides functionality for asymmetric PIV key objects
 */
public final class PIVKeyObjectRSA extends PIVKeyObjectPKI {

    private static Cipher signingCipher;

    public final byte CONST_TAG_MODULUS = (byte) 0x81; // RSA - The modulus
    public final byte CONST_TAG_EXPONENT = (byte) 0x82; // RSA - The public exponent

    // The list of elements that can be updated for an asymmetric key

    // RSA Modulus Element
    public static final byte ELEMENT_RSA_N	= (byte)0x81;

    // RSA Public Exponent
    public static final byte ELEMENT_RSA_E	= (byte)0x82;

    // RSA Private Exponent
    public static final byte ELEMENT_RSA_D	= (byte)0x83;

    public PIVKeyObjectRSA(byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
        super(id, modeContact, modeContactless, mechanism, role);
        if (signingCipher == null) {
            signingCipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        }
    }

    @Override
    public void updateElement(byte element, byte[] buffer, short offset, short length) {

        switch (element) {

        // RSA Modulus Element
        case ELEMENT_RSA_N:
            if (length != getKeyLength()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            if (publicKey == null || privateKey == null) allocate();
            ((RSAPublicKey)publicKey).setModulus(buffer, offset, length);
            ((RSAPrivateKey)privateKey).setModulus(buffer, offset, length);
            break;

        // RSA Public Exponent
        case ELEMENT_RSA_E:
            if (length == (short)0) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            if (publicKey == null) allocate();
            ((RSAPublicKey)publicKey).setExponent(buffer, offset, length);
            break;

        // RSA Private Exponent
        case ELEMENT_RSA_D:
            if (length != getKeyLength()) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
            if (privateKey == null) allocate();
            ((RSAPrivateKey)privateKey).setExponent(buffer, offset, length);
            break;

        // Clear Key
        case ELEMENT_CLEAR:
            clear();
            break;

        default:
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            break;
        }

    }

    /**
     * Writes the private exponent of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @param length The length of the exponent to write
     */
    public void setPrivateExponent(byte[] buffer, short offset, short length) {
        if (privateKey == null) allocate();
        ((RSAPrivateKey)privateKey).setExponent(buffer, offset, length);
    }

    /**
     * Writes the public exponent of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @param length The length of the exponent to write
     */
    public void setPublicExponent(byte[] buffer, short offset, short length) {
        if (publicKey == null) allocate();
        ((RSAPublicKey)publicKey).setExponent(buffer, offset, length);
    }

    /**
     * Writes the modulus of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @param length The length of the modulus to write
     */
    public void setModulus(byte[] buffer, short offset, short length) {
        if (privateKey == null || publicKey == null) allocate();
        ((RSAPrivateKey)privateKey).setModulus(buffer, offset, length);
        ((RSAPublicKey)publicKey).setModulus(buffer, offset, length);
    }

    /**
     * Writes the public exponent of RSA the key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @return The length of the public exponent
     */
    public short getPublicExponent(byte[] buffer, short offset) {
        return ((RSAPublicKey)publicKey).getExponent(buffer, offset);
    }

    /**
     * Writes the modulus of the RSA key pair to the buffer
     * @param buffer The destination buffer to write to
     * @param offset The starting offset to write to
     * @return The length of the modulus
     */
    public short getModulus(byte[] buffer, short offset) {
        return ((RSAPublicKey)publicKey).getModulus(buffer, offset);
    }

    @Override
    protected void allocate() {
        short keyLength = 0;
        // Generate the appropriate key(s)
        switch (header[HEADER_MECHANISM]) {
            case PIV.ID_ALG_RSA_1024:
                keyLength = KeyBuilder.LENGTH_RSA_1024;
                break;

            case PIV.ID_ALG_RSA_2048:
                keyLength = KeyBuilder.LENGTH_RSA_2048;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
        }

        privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keyLength, false);
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keyLength, false);
    }

    @Override
    public short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        if(inLength != getBlockLength()){
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        signingCipher.init(privateKey, Cipher.MODE_ENCRYPT);
        return signingCipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    @Override
    public short marshalPublic(byte[] scratch, short offset) {
        TLVWriter tlvWriter = new TLVWriter();
        // Adding 12 to the key length to account for other overhead
        tlvWriter.init(scratch, offset, (short)(getKeyLength()*2 + 12), CONST_TAG_RESPONSE);

        // Modulus
        tlvWriter.writeTag(CONST_TAG_MODULUS);
        tlvWriter.writeLength(getKeyLength());

        // The modulus data must be written manually because of how RSAPublicKey works
        offset = tlvWriter.getOffset();
        offset += getModulus(scratch, offset);
        tlvWriter.setOffset(offset); // Move the current position forward

        // Exponent
        tlvWriter.writeTag(CONST_TAG_EXPONENT);
        tlvWriter.writeLength((short)3); // Hack! Why can't we get the size from RSAPublicKey?
        offset = tlvWriter.getOffset();
        offset += getPublicExponent(scratch, offset);
        tlvWriter.setOffset(offset); // Move the current position forward

        return tlvWriter.finish();
    }

    // TODO: We now have a proper signing algorithm so we should probably change the signing
    // logic to use sign and change the encrypt to encrypt with the public key.
    @Override
    public short encrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        if(inLength != getBlockLength()){
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        cipher.init(privateKey, Cipher.MODE_ENCRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    @Override
    public short decrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        cipher.init(privateKey, Cipher.MODE_DECRYPT);
        return cipher.doFinal(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    @Override
    public short getBlockLength() {
        // RSA blocks are the same length as their keys
        return getKeyLength();
    }

    @Override
    public short getKeyLength() {
        switch (getMechanism()) {
            case PIV.ID_ALG_RSA_1024:
                return KeyBuilder.LENGTH_RSA_1024 / 8;

            case PIV.ID_ALG_RSA_2048:
                return KeyBuilder.LENGTH_RSA_2048 / 8;

            default:
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                return (short) 0; // Keep compiler happy
        }
    }
}
