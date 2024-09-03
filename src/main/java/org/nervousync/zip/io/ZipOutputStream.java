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
package org.nervousync.zip.io;

import java.io.IOException;
import java.io.OutputStream;

import jakarta.annotation.Nonnull;
import org.nervousync.zip.ZipFile;

/**
 * The type Zip output stream.
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Dec 1, 2017 12:37:14 PM $
 */
public class ZipOutputStream extends DeflaterOutputStream {

	/**
	 * Instantiates a new Zip output stream.
	 *
	 * @param outputStream the output stream
	 * @param zipFile      the zip file
	 */
	public ZipOutputStream(OutputStream outputStream, ZipFile zipFile) {
		super(outputStream, zipFile);
	}

	public void write(int value) throws IOException {
		byte[] b = new byte[1];
		b[0] = (byte) value;
		this.write(b, 0, 1);
	}

	@Override
	public void write(@Nonnull byte[] b) throws IOException {
		this.write(b, 0, b.length);
	}

	@Override
	public void write(@Nonnull byte[] b, int off, int len) throws IOException {
		this.crc.update(b, off, len);
		this.updateTotalBytesRead(len);
		super.write(b, off, len);
	}
}
