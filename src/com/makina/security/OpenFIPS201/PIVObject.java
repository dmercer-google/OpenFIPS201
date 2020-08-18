/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2017 Commonwealth of Australia
 * Author: Kim O'Sullivan - Makina (kim@makina.com.au)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

package com.makina.security.OpenFIPS201;

/** Provides common functionality for all PIV objects (data and security) */
abstract class PIVObject {

  protected static final short HEADER_ID = (short) 0;
  private static final short HEADER_MODE_CONTACT = (short) 1;
  private static final short HEADER_MODE_CONTACTLESS = (short) 2;
  // We allocate some spare header space for derived attributes
  private static final short LENGTH_HEADER = (short) 8;
  // Linked list element
  public PIVObject nextObject;
  protected final byte[] header;

  protected PIVObject(byte id, byte modeContact, byte modeContactless) {
    header = new byte[LENGTH_HEADER];
    header[HEADER_ID] = id;
    header[HEADER_MODE_CONTACT] = modeContact;
    header[HEADER_MODE_CONTACTLESS] = modeContactless;
  }

  /**
   * Compares the requested identifier value to the current object's id
   *
   * @param id The id to search for
   * @return True if the object matches
   */
  public final boolean match(byte id) {
    return (header[HEADER_ID] == id);
  }

  /**
   * Returns the current object's identifier value
   *
   * @return The object identifier
   */
  public final byte getId() {
    return header[HEADER_ID];
  }

  /**
   * Returns the ACCESS MODE conditions for the contact interface
   *
   * @return The access mode for the contact interface
   */
  public final byte getModeContact() {
    return header[HEADER_MODE_CONTACT];
  }

  /**
   * Returns the ACCESS MODE conditions for the contactless interface
   *
   * @return The access mode for the contactless interface
   */
  public final byte getModeContactless() {
    return header[HEADER_MODE_CONTACTLESS];
  }

  /** Clears the current object's value */
  public abstract void clear();

  /** @return returns true if the object has been initialized */
  public abstract boolean isInitialised();
}
