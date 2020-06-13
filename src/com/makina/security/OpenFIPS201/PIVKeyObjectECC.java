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

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.*;
import javacardx.crypto.Cipher;

/**
 * Provides functionality for asymmetric PIV key objects
 */
public final class PIVKeyObjectECC extends PIVKeyObjectPKI {

    private static Signature signer;
    public PIVKeyObjectECC(byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
        super(id, modeContact, modeContactless, mechanism, role);
        if(signer == null) {
            signer = Signature.getInstance(MessageDigest.ALG_NULL, Signature.SIG_CIPHER_ECDSA, Cipher.PAD_NULL, false);
        }
    }

    public final byte ELEMENT_ECC_POINT = (byte)0x86;
    public final byte ELEMENT_ECC_SECRET = (byte)0x87;

    // From SP 800-73-4 Part 2 3.3.2
    private static final byte CONST_POINT_UNCOMPRESSED = (byte) 0x04;
    // Uncompressed ECC public keys are marshaled as the concatenation of:
    // CONST_POINT_UNCOMPRESSED | X | Y
    // where the length of the X and Y coordinates is the byte length of the key.
    private static final short CONST_MARSHALLED_PUB_KEY_LEN_P256 = (short) ((KeyBuilder.LENGTH_EC_FP_256 / 8) * 2 + 1);
    private static final short CONST_MARSHALLED_PUB_KEY_LEN_P384 = (short) ((KeyBuilder.LENGTH_EC_FP_384 / 8) * 2 + 1);


    @Override
    public void updateElement(byte element, byte[] buffer, short offset, short length) {
        byte mechanism = getMechanism();

        switch (element) {

            // ECC Public Key
            case ELEMENT_ECC_POINT:
                switch (mechanism) {
                    case PIV.ID_ALG_ECC_P256:
                        if (length != CONST_MARSHALLED_PUB_KEY_LEN_P256) {
                            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                        }
                        break;
                    case PIV.ID_ALG_ECC_P384:
                        if (length != CONST_MARSHALLED_PUB_KEY_LEN_P384) {
                            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                        }
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        break;
                }

                // Only uncompressed points are supported
                if (buffer[offset] != CONST_POINT_UNCOMPRESSED) {
                    ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                }

                if (publicKey == null) {
                    allocate();
                }
                ((ECPublicKey) publicKey).setW(buffer, offset, length);
                break;

            // ECC Private Key
            case ELEMENT_ECC_SECRET:
                switch (mechanism) {
                    case PIV.ID_ALG_ECC_P256:
                        if (length != (short) (KeyBuilder.LENGTH_EC_FP_256 / 8)) {
                            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                        }
                        break;
                    case PIV.ID_ALG_ECC_P384:
                        if (length != (short) (KeyBuilder.LENGTH_EC_FP_384 / 8)) {
                            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                        }
                        break;
                    default:
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                        break;
                }
                if (privateKey == null) {
                    allocate();
                }
                ((ECPrivateKey) privateKey).setS(buffer, offset, length);
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

    @Override
    protected void allocate() {
        short keyLength = (short) 0;
        switch (header[HEADER_MECHANISM]) {
            case PIV.ID_ALG_ECC_P256:
                keyLength = KeyBuilder.LENGTH_EC_FP_256;
                break;

            case PIV.ID_ALG_ECC_P384:
                keyLength = KeyBuilder.LENGTH_EC_FP_384;
                break;

            default:
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                break;
        }

        publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, keyLength, false);
        privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, keyLength, false);
        setParams();
    }

    @Override
    public short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        signer.init(privateKey, Signature.MODE_SIGN);
        return signer.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
    }

    @Override
    public short encrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return 0;
    }

    @Override
    public short decrypt(Cipher cipher, byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return 0;
    }

    /*
     * Set ECC domain parameters.
     */
    protected void setParams() {
        ECParams params = null;
        switch (getMechanism()) {
            case PIV.ID_ALG_ECC_P256:
                params = new ECParamsP256();
                break;
            case PIV.ID_ALG_ECC_P384:
                params = new ECParamsP384();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        byte[] a = params.getA();
        byte[] b = params.getB();
        byte[] g = params.getG();
        byte[] p = params.getP();
        byte[] r = params.getN();
        short h = params.getH();

        ((ECPublicKey) publicKey).setA(a, (short) 0, (short) (a.length));
        ((ECPublicKey) publicKey).setB(b, (short) 0, (short) (b.length));
        ((ECPublicKey) publicKey).setG(g, (short) 0, (short) (g.length));
        ((ECPublicKey) publicKey).setR(r, (short) 0, (short) (r.length));
        ((ECPublicKey) publicKey).setFieldFP(p, (short) 0, (short) (p.length));
        ((ECPublicKey) publicKey).setK(h);

        ((ECPrivateKey) privateKey).setA(a, (short) 0, (short) (a.length));
        ((ECPrivateKey) privateKey).setB(b, (short) 0, (short) (b.length));
        ((ECPrivateKey) privateKey).setG(g, (short) 0, (short) (g.length));
        ((ECPrivateKey) privateKey).setR(r, (short) 0, (short) (r.length));
        ((ECPrivateKey) privateKey).setFieldFP(p, (short) 0, (short) (p.length));
        ((ECPrivateKey) privateKey).setK(h);
    }
    public short marshalPublic(byte[] scratch, short offset){
        TLVWriter tlvWriter = new TLVWriter();

        short keyLen = (short) 0;
        switch (getMechanism()) {
            case PIV.ID_ALG_ECC_P256:
                keyLen = CONST_MARSHALLED_PUB_KEY_LEN_P256;
                break;
            case PIV.ID_ALG_ECC_P384:
                keyLen = CONST_MARSHALLED_PUB_KEY_LEN_P384;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // adding 5 bytes to the marshaled key to account for other APDU overhead.
        tlvWriter.init(scratch, offset, (short)(keyLen + 5), CONST_TAG_RESPONSE);
        tlvWriter.writeTag(ELEMENT_ECC_POINT);
        tlvWriter.writeLength(keyLen);
        offset = tlvWriter.getOffset();
        offset += ((ECPublicKey) publicKey).getW(scratch, offset);

        tlvWriter.setOffset(offset);
        return tlvWriter.finish();
    }

    /**
     * ECC Keys don't have a block length
     * @throws ISOException reason = SW_FUNC_NOT_SUPPORTED
     */
    @Override
    public short getBlockLength() {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        return 0;
    }

    public short getKeyLength() {
        switch (getMechanism()) {
            case PIV.ID_ALG_ECC_P256:
                return KeyBuilder.LENGTH_EC_FP_256 / 8;

            case PIV.ID_ALG_ECC_P384:
                return KeyBuilder.LENGTH_EC_FP_384 / 8;

            default:
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                return (short) 0; // Keep compiler happy
        }
    }
}
