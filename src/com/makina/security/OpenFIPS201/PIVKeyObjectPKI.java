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

import javacard.framework.JCSystem;
import javacard.security.*;

public abstract class PIVKeyObjectPKI extends PIVKeyObject {
	
	protected PrivateKey privateKey;
	protected PublicKey publicKey;
	protected Signature signer;
	protected KeyAgreement keyAgreement;


	// Clear any key material from this object
	public static final byte ELEMENT_CLEAR = (byte)0xFF;

	public final short CONST_TAG_RESPONSE = (short) 0x7F49;

	protected PIVKeyObjectPKI(byte id, byte modeContact, byte modeContactless, byte mechanism, byte role) {
		super(id, modeContact, modeContactless, mechanism, role);
	}
	
	@Override
	public boolean isAsymmetric() {
		return true;
	}

	@Override
	public void clear() {
		if (privateKey != null) {
			privateKey.clearKey();
			privateKey = null;
		}
		if (publicKey != null) {
			publicKey.clearKey();
			publicKey = null;
		}
		if(JCSystem.isObjectDeletionSupported()){
			JCSystem.requestObjectDeletion();
		}
	}

	@Override
	public boolean isInitialised() {
		return (privateKey != null && privateKey.isInitialized() &&
				publicKey != null && publicKey.isInitialized());
	}

	public void generate() {
		if (privateKey == null || publicKey == null) allocate();
		new KeyPair(publicKey, privateKey).genKeyPair();
	}

	public short sign(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
		signer.init(privateKey, Signature.MODE_SIGN);
		return signer.sign(inBuffer, inOffset, inLength, outBuffer, outOffset);
	}

	protected abstract void allocate();
	public abstract short marshalPublic(byte[] scratch, short offset);
}
