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
import java.util.zip.CRC32;

import jakarta.annotation.Nonnull;
import org.nervousync.commons.Globals;

/**
 * The type Zip input stream.
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 2, 2017 10:29:09 AM $
 */
public class ZipInputStream extends InputStream {

	private final CRC32 crc;
	private final InputStream inputStream;

	/**
	 * Instantiates a new Zip input stream.
	 *
	 * @param inputStream the input stream
	 */
	public ZipInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
		this.crc = new CRC32();
	}

	@Override
	public int read() throws IOException {
		int readByte = this.inputStream.read();
		if (readByte != Globals.DEFAULT_VALUE_INT) {
			this.crc.update(readByte);
		}
		return readByte;
	}

	@Override
	public int read(@Nonnull byte[] b) throws IOException {
		return this.read(b, 0, b.length);
	}

	@Override
	public int read(@Nonnull byte[] b, int off, int len) throws IOException {
		int readLength = this.inputStream.read(b, off, len);
		if (readLength != Globals.DEFAULT_VALUE_INT) {
			this.crc.update(b, off, readLength);
		}
		return readLength;
	}

	@Override
	public void close() throws IOException {
		this.inputStream.close();
	}

	/**
	 * Crc value long.
	 *
	 * @return the long
	 */
	public long crcValue() {
		return this.crc.getValue();
	}
}
