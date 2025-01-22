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
package org.nervousync.zip.options;

import java.util.TimeZone;

import org.nervousync.enumerations.zip.CompressLevel;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.commons.Globals;
import org.nervousync.utils.StringUtils;

/**
 * ZIP options
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 29, 2017 3:51:12 PM $
 */
public final class ZipOptions implements Cloneable {

	/**
	 * Folder, file name and comment charset encoding
	 */
	private String charsetEncoding = Globals.DEFAULT_SYSTEM_CHARSET;
	/**
	 * Compress method
	 */
	private int compressionMethod = Globals.COMP_DEFLATE;
	/**
	 * Compress level
	 */
	private int compressionLevel = Globals.DEFLATE_LEVEL_NORMAL;
	/**
	 * Encrypt files status
	 */
	private boolean encryptFiles;
	/**
	 * Encrypt method
	 */
	private int encryptionMethod;
	/**
	 * Status of the read hidden file
	 */
	private boolean readHiddenFiles = Boolean.TRUE;
	/**
	 * Encrypt/Decrypt password
	 */
	private final char[] password;
	/**
	 * AES key length
	 */
	private final int aesKeyStrength;
	/**
	 * Include root folder
	 */
	private boolean includeRootFolder = Boolean.TRUE;
	/**
	 * Root folder path
	 */
	private String rootFolderInZip = "";
	/**
	 * Timezone setting
	 *
	 * @see java.util.TimeZone
	 */
	private TimeZone timeZone = TimeZone.getDefault();
	/**
	 * CRC
	 */
	private long sourceFileCRC = Globals.DEFAULT_VALUE_LONG;
	/**
	 * Default folder path
	 */
	private String defaultFolderPath = "";
	/**
	 * File name in zip
	 */
	private String fileNameInZip = null;
	/**
	 * Status of source external stream
	 */
	private boolean sourceExternalStream = Boolean.FALSE;

	/**
	 * Default Constructor
	 */
	private ZipOptions() {
		this(Boolean.FALSE, Globals.DEFAULT_VALUE_STRING, Globals.ENC_NO_ENCRYPTION, Globals.AES_STRENGTH_128);
	}

	/**
	 * Constructor by given password
	 *
	 * @param password password
	 */
	private ZipOptions(final String password) {
		this(Boolean.TRUE, password, Globals.ENC_METHOD_STANDARD, Globals.AES_STRENGTH_128);
	}

	/**
	 * Constructor by given password and key strength
	 *
	 * @param password       encrypt password
	 * @param aesKeyStrength AES key strength
	 */
	private ZipOptions(final String password, final int aesKeyStrength) {
		this(Boolean.TRUE, password, Globals.ENC_METHOD_AES, aesKeyStrength);
	}

	private ZipOptions(final boolean encryptFiles, final String password, final int encryptionMethod,
	                   final int aesKeyStrength) {
		this.encryptFiles = encryptFiles;
		this.password = password.toCharArray();
		this.encryptionMethod = encryptionMethod;
		this.aesKeyStrength = aesKeyStrength;
		this.compressLevel(CompressLevel.NORMAL);
	}

	/**
	 * Generate default ZipOptions instance
	 *
	 * @return generated instance
	 */
	public static ZipOptions newOptions() {
		return new ZipOptions();
	}

	/**
	 * Generate a standard encrypt ZipOptions instance by given password
	 *
	 * @param password encrypt password
	 * @return generated instance
	 * @throws ZipException if password is null
	 */
	public static ZipOptions standardEncryptOptions(final String password) throws ZipException {
		if (StringUtils.isEmpty(password)) {
			throw new ZipException(0x0000001B0006L, "Invalid_Password_Zip_Error");
		}
		return new ZipOptions(password);
	}

	/**
	 * Generate an AES encrypt ZipOptions instance by given password
	 *
	 * @param password encrypt password
	 * @return generated instance
	 * @throws ZipException if password is null
	 */
	public static ZipOptions aesEncryptOptions(final String password) throws ZipException {
		return ZipOptions.aesEncryptOptions(password, 128);
	}

	/**
	 * Generate an AES encrypt ZipOptions instance by given password and key strength
	 *
	 * @param password     encrypt password
	 * @param aesKeyLength the aes key length
	 * @return generated instance
	 * @throws ZipException if password is null
	 */
	public static ZipOptions aesEncryptOptions(final String password, final int aesKeyLength) throws ZipException {
		if (StringUtils.isEmpty(password)) {
			throw new ZipException(0x0000001B0006L, "Invalid_Password_Zip_Error");
		}

		switch (aesKeyLength) {
			case 128:
				return new ZipOptions(password, Globals.AES_STRENGTH_128);
			case 192:
				return new ZipOptions(password, Globals.AES_STRENGTH_192);
			case 256:
				return new ZipOptions(password, Globals.AES_STRENGTH_256);
			default:
				throw new ZipException(0x0000001B0005L, "Invalid_Key_Strength_AES_Zip_Error");
		}
	}

	/**
	 * Gets charset encoding.
	 *
	 * @return the charset encoding
	 */
	public String getCharsetEncoding() {
		return charsetEncoding;
	}

	/**
	 * Sets charset encoding.
	 *
	 * @param charsetEncoding the charset encoding
	 */
	public void setCharsetEncoding(final String charsetEncoding) {
		this.charsetEncoding = charsetEncoding;
	}

	/**
	 * Gets compression method.
	 *
	 * @return the compressionMethod
	 */
	public int getCompressionMethod() {
		return compressionMethod;
	}

	/**
	 * Sets compression method.
	 *
	 * @param compressionMethod the compressionMethod to set
	 */
	public void setCompressionMethod(final int compressionMethod) {
		this.compressionMethod = compressionMethod;
	}

	/**
	 * Gets compression level.
	 *
	 * @return the compressionLevel
	 */
	public int getCompressionLevel() {
		return compressionLevel;
	}

	public void compressLevel(final CompressLevel compressLevel) {
		switch (compressLevel) {
			case FASTEST:
				this.compressionLevel = Globals.DEFLATE_LEVEL_FASTEST;
				break;
			case FAST:
				this.compressionLevel = Globals.DEFLATE_LEVEL_FAST;
				break;
			case NORMAL:
				this.compressionLevel = Globals.DEFLATE_LEVEL_NORMAL;
				break;
			case MAXIMUM:
				this.compressionLevel = Globals.DEFLATE_LEVEL_MAXIMUM;
				break;
			case ULTRA:
				this.compressionLevel = Globals.DEFLATE_LEVEL_ULTRA;
				break;
			default:

		}
	}

	/**
	 * encrypt files boolean.
	 *
	 * @return the encryptFiles
	 */
	public boolean isEncryptFiles() {
		return encryptFiles;
	}

	/**
	 * Sets the encryptFiles.
	 *
	 * @param encryptFiles encryptFiles
	 */
	public void setEncryptFiles(final boolean encryptFiles) {
		this.encryptFiles = encryptFiles;
	}

	/**
	 * Gets encryption method.
	 *
	 * @return the encryptionMethod
	 */
	public int getEncryptionMethod() {
		return encryptionMethod;
	}

	/**
	 * Sets the encryptionMethod.
	 *
	 * @param encryptionMethod encryptionMethod
	 */
	public void setEncryptionMethod(final int encryptionMethod) {
		this.encryptionMethod = encryptionMethod;
	}

	/**
	 * Is read hidden files boolean.
	 *
	 * @return the readHiddenFiles
	 */
	public boolean isReadHiddenFiles() {
		return readHiddenFiles;
	}

	/**
	 * Sets read hidden files.
	 *
	 * @param readHiddenFiles the readHiddenFiles to set
	 */
	public void setReadHiddenFiles(final boolean readHiddenFiles) {
		this.readHiddenFiles = readHiddenFiles;
	}

	/**
	 * Get password char [ ].
	 *
	 * @return the password
	 */
	public char[] getPassword() {
		return password == null ? new char[0] : password.clone();
	}

	/**
	 * Gets aes key strength.
	 *
	 * @return the aesKeyStrength
	 */
	public int getAesKeyStrength() {
		return aesKeyStrength;
	}

	/**
	 * include root folder boolean.
	 *
	 * @return the includeRootFolder
	 */
	public boolean isIncludeRootFolder() {
		return includeRootFolder;
	}

	/**
	 * Sets include root folder.
	 *
	 * @param includeRootFolder the includeRootFolder to set
	 */
	public void setIncludeRootFolder(final boolean includeRootFolder) {
		this.includeRootFolder = includeRootFolder;
	}

	/**
	 * Gets root folder in zip.
	 *
	 * @return the rootFolderInZip
	 */
	public String getRootFolderInZip() {
		return rootFolderInZip;
	}

	/**
	 * Sets root folder in zip.
	 *
	 * @param rootFolderInZip the rootFolderInZip to set
	 */
	public void setRootFolderInZip(final String rootFolderInZip) {
		if (!rootFolderInZip.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
			this.rootFolderInZip = rootFolderInZip + Globals.DEFAULT_PAGE_SEPARATOR;
		}
		this.rootFolderInZip = StringUtils.replace(rootFolderInZip, Globals.DEFAULT_PAGE_SEPARATOR, "/");
	}

	/**
	 * Gets time zone.
	 *
	 * @return the timeZone
	 */
	public TimeZone getTimeZone() {
		return timeZone;
	}

	/**
	 * Sets time zone.
	 *
	 * @param timeZone the timeZone to set
	 */
	public void setTimeZone(final TimeZone timeZone) {
		this.timeZone = timeZone;
	}

	/**
	 * Gets source file crc.
	 *
	 * @return the sourceFileCRC
	 */
	public long getSourceFileCRC() {
		return sourceFileCRC;
	}

	/**
	 * Sets source file crc.
	 *
	 * @param sourceFileCRC the sourceFileCRC to set
	 */
	public void setSourceFileCRC(final long sourceFileCRC) {
		this.sourceFileCRC = sourceFileCRC;
	}

	/**
	 * Gets the default folder path.
	 *
	 * @return the defaultFolderPath
	 */
	public String getDefaultFolderPath() {
		return defaultFolderPath;
	}

	/**
	 * Sets default folder path.
	 *
	 * @param defaultFolderPath the defaultFolderPath to set
	 */
	public void setDefaultFolderPath(final String defaultFolderPath) {
		this.defaultFolderPath = defaultFolderPath;
	}

	/**
	 * Gets file name in zip.
	 *
	 * @return the fileNameInZip
	 */
	public String getFileNameInZip() {
		return fileNameInZip;
	}

	/**
	 * Sets file name in zip.
	 *
	 * @param fileNameInZip the fileNameInZip to set
	 */
	public void setFileNameInZip(final String fileNameInZip) {
		this.fileNameInZip = fileNameInZip;
	}

	/**
	 * Is source external stream boolean.
	 *
	 * @return the isSourceExternalStream
	 */
	public boolean isSourceExternalStream() {
		return sourceExternalStream;
	}

	/**
	 * Sets source external stream.
	 *
	 * @param isSourceExternalStream the isSourceExternalStream to set
	 */
	public void setSourceExternalStream(final boolean isSourceExternalStream) {
		this.sourceExternalStream = isSourceExternalStream;
	}

	public Object clone() throws CloneNotSupportedException {
		return super.clone();
	}
}
