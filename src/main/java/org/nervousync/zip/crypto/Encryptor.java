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
package org.nervousync.zip.crypto;

import org.nervousync.exceptions.zip.ZipException;

/**
 * Zip encryptor
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 29, 2017 2:45:30 PM $
 */
public interface Encryptor {

	/**
	 * Encrypt given data array
	 *
	 * @param buff data array
	 * @throws ZipException if encrypt engine was not initialized or data index out of size
	 */
	void encryptData(byte[] buff) throws ZipException;

	/**
	 * Encrypt given data array which index from start and process data length was given
	 *
	 * @param buff  data buffer
	 * @param start start index
	 * @param len   process length
	 * @throws ZipException if encrypt engine was not initialized or data index out of size
	 */
	void encryptData(byte[] buff, int start, int len) throws ZipException;

}
