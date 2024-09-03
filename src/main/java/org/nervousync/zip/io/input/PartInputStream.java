/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.nervousync.zip.io.input;

import java.io.IOException;
import java.io.InputStream;

import jakarta.annotation.Nonnull;
import org.nervousync.commons.Globals;
import org.nervousync.zip.crypto.Decryptor;
import org.nervousync.zip.crypto.impl.aes.AESDecryptor;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.commons.io.StandardFile;
import org.nervousync.zip.ZipFile;

/**
 * The type Part input stream.
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 2, 2017 10:30:23 AM $
 */
public class PartInputStream extends InputStream {

	private final ZipFile zipFile;
	private StandardFile input;
	private int currentIndex;
	private long readBytes;
	private final long length;
	private final Decryptor decryptor;
	private final byte[] oneByteBuffer = new byte[1];
	private final byte[] aesBlockBuffer = new byte[Globals.AES_BLOCK_SIZE];
	private int aesBytesReturned = 0;
	private final boolean isAESEncryptedFile;

	/**
	 * Instantiates a new Part input stream.
	 *
	 * @param zipFile            the zip file
	 * @param currentIndex       the current index
	 * @param seekPosition       the seek position
	 * @param length             the length
	 * @param decryptor          the decryptor
	 * @param isAESEncryptedFile is aes encrypted file
	 * @throws IOException the io exception
	 */
	public PartInputStream(final ZipFile zipFile, final int currentIndex, final long seekPosition,
	                       final long length, final Decryptor decryptor, final boolean isAESEncryptedFile)
			throws IOException, ZipException {
		this.zipFile = zipFile;
		this.currentIndex = currentIndex;
		this.input = this.zipFile.openSplitFile(currentIndex);
		this.input.seek(seekPosition);
		this.readBytes = 0L;
		this.length = length;
		this.decryptor = decryptor;
		this.isAESEncryptedFile = isAESEncryptedFile;
	}

	@Override
	public int read() throws IOException {
		if (this.readBytes >= this.length) {
			return Globals.DEFAULT_VALUE_INT;
		}

		if (this.isAESEncryptedFile) {
			if (this.aesBytesReturned == 0 || this.aesBytesReturned == 16) {
				if (this.read(this.aesBlockBuffer) == Globals.DEFAULT_VALUE_INT) {
					return Globals.DEFAULT_VALUE_INT;
				}
				this.aesBytesReturned = 0;
			}
			return (this.aesBlockBuffer[this.aesBytesReturned++] & 0xFF);
		} else {
			return this.read(this.oneByteBuffer, 0, 1) == Globals.DEFAULT_VALUE_INT ?
					Globals.DEFAULT_VALUE_INT : (this.oneByteBuffer[0] & 0xFF);
		}
	}

	@Override
	public synchronized int read(@Nonnull byte[] b, int off, int len) throws IOException {
		try {
			if (len > (this.length - this.readBytes)) {
				len = (int) (this.length - this.readBytes);

				if (len == 0) {
					this.checkAndReadAESMacBytes();
					return Globals.DEFAULT_VALUE_INT;
				}
			}

			if (this.decryptor instanceof AESDecryptor) {
				if ((this.readBytes + len) < this.length
						&& (len % 16 != 0)) {
					len -= (len % 16);
				}
			}

			int count = this.input.read(b, off, len);
			if ((count < len) && this.zipFile.isSplitArchive()) {
				this.input.close();
				this.currentIndex++;
				this.input = this.zipFile.openSplitFile(this.currentIndex);

				if (count < 0) {
					count = 0;
				}

				int readCount = this.input.read(b, count, len - count);
				if (readCount > 0) {
					count += readCount;
				}
			}

			if (count > 0) {
				if (this.decryptor != null) {
					try {
						this.decryptor.decryptData(b, off, count);
					} catch (ZipException e) {
						throw new IOException(e);
					}
				}

				this.readBytes += count;
			}

			if (this.readBytes >= this.length) {
				this.checkAndReadAESMacBytes();
			}

			return count;
		} catch (ZipException e) {
			throw new IOException(e);
		}
	}

	public int available() {
		long amount = this.length - this.readBytes;
		if (amount > Integer.MAX_VALUE) {
			return Integer.MAX_VALUE;
		}
		return (int) amount;
	}

	public long skip(long length) throws IOException {
		if (length < 0L) {
			throw new IllegalArgumentException();
		}

		if (length > (this.length - this.readBytes)) {
			length = this.length - this.readBytes;
		}

		this.readBytes += length;
		return length;
	}

	/**
	 * Seek.
	 *
	 * @param pos the pos
	 * @throws IOException the io exception
	 */
	public void seek(long pos) throws IOException {
		this.input.seek(pos);
	}

	public void close() throws IOException {
		this.input.close();
	}

	/**
	 * Seek to end.
	 *
	 * @throws IOException the io exception
	 */
	protected void seekToEnd() throws IOException {
		this.seek(this.length);
	}

	/**
	 * Check and read aes mac bytes.
	 *
	 * @throws IOException the io exception
	 */
	protected void checkAndReadAESMacBytes() throws IOException, ZipException {
		if (this.isAESEncryptedFile
				&& (this.decryptor instanceof AESDecryptor)) {
			if (((AESDecryptor) this.decryptor).getStoredMac() != null) {
				//	Store mac already set
				return;
			}

			byte[] storedMac = new byte[Globals.AES_AUTH_LENGTH];
			int readLength = this.input.read(storedMac);

			if (readLength != Globals.AES_AUTH_LENGTH) {
				if (this.zipFile.isSplitArchive()) {
					this.input.close();
					this.currentIndex++;
					this.input = this.zipFile.openSplitFile(this.currentIndex);
					int newReadLength = this.input.read(storedMac,
							readLength, Globals.AES_AUTH_LENGTH - readLength);

					readLength += newReadLength;
				} else {
					throw new ZipException("Error occurred while reading stored AES authentication bytes");
				}
			}

			if (readLength != Globals.AES_AUTH_LENGTH) {
				throw new ZipException("Error occurred while reading stored AES authentication bytes");
			}

			((AESDecryptor) this.decryptor).setStoredMac(storedMac);
		}
	}
}
