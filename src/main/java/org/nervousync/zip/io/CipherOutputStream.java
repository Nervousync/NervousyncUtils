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

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

import jakarta.annotation.Nonnull;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.zip.options.ZipOptions;
import org.nervousync.zip.crypto.Encryptor;
import org.nervousync.zip.crypto.impl.aes.AESEncryptor;
import org.nervousync.zip.crypto.impl.standard.StandardEncryptor;
import org.nervousync.zip.crypto.impl.aes.AESEngine;
import org.nervousync.zip.models.AESExtraDataRecord;
import org.nervousync.zip.models.central.CentralDirectory;
import org.nervousync.zip.models.central.EndCentralDirectoryRecord;
import org.nervousync.zip.models.header.GeneralFileHeader;
import org.nervousync.zip.models.header.LocalFileHeader;
import org.nervousync.zip.models.header.utils.HeaderOperator;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.zip.ZipFile;
import org.nervousync.utils.DateTimeUtils;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.RawUtils;
import org.nervousync.utils.StringUtils;

/**
 * The type Cipher output stream.
 *
 * @author Steven Wee <a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 29, 2017 2:39:25 PM $
 */
public class CipherOutputStream extends OutputStream {

	/**
	 * Target output stream
	 */
	private final OutputStream outputStream;
	/**
	 * Source file
	 */
	private File sourceFile;
	private GeneralFileHeader generalFileHeader;
	private LocalFileHeader localFileHeader;
	private Encryptor encryptor;
	/**
	 * The Zip options.
	 */
	ZipOptions zipOptions;
	/**
	 * Target zip file object
	 */
	private final ZipFile zipFile;
	/**
	 * CRC
	 */
	final CRC32 crc;
	private long totalWriteBytes;
	private long totalReadBytes;
	/**
	 * The Bytes written for this file.
	 */
	long bytesWrittenForThisFile;
	private final byte[] pendingBuffer;
	private int pendingBufferLength;

	/**
	 * Instantiates a new Cipher output stream.
	 *
	 * @param outputStream the output stream
	 * @param zipFile      the zip file
	 */
	CipherOutputStream(OutputStream outputStream, ZipFile zipFile) {
		this.outputStream = outputStream;
		this.zipFile = zipFile;
		this.initZipFile();
		this.crc = new CRC32();
		this.totalWriteBytes = 0L;
		this.bytesWrittenForThisFile = 0L;
		this.totalReadBytes = 0L;
		this.pendingBuffer = new byte[Globals.AES_BLOCK_SIZE];
		this.pendingBufferLength = 0;
	}

	/**
	 * Put the next entry.
	 *
	 * @param file       the file
	 * @param zipOptions the zip options
	 * @throws ZipException the zip exception
	 */
	public void putNextEntry(File file, ZipOptions zipOptions) throws ZipException {
		if (!zipOptions.isSourceExternalStream() && file == null) {
			throw new ZipException(0x0000001B0013L, "Null_Input_File_Zip_Error");
		}

		if (!zipOptions.isSourceExternalStream() && !FileUtils.isExists(file.getAbsolutePath())) {
			throw new ZipException(0x0000001B0013L, "Null_Input_File_Zip_Error");
		}

		try {
			this.sourceFile = file;
			this.zipOptions = (ZipOptions) zipOptions.clone();

			if (this.zipOptions.isSourceExternalStream()) {
				if (StringUtils.notBlank(this.zipOptions.getFileNameInZip())) {
					if (this.zipOptions.getFileNameInZip().endsWith(Globals.DEFAULT_ZIP_PAGE_SEPARATOR)
							|| this.zipOptions.getFileNameInZip().endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
						this.zipOptions.setEncryptFiles(Boolean.FALSE);
						this.zipOptions.setEncryptionMethod(Globals.ENC_NO_ENCRYPTION);
						this.zipOptions.setCompressionMethod(Globals.COMP_STORE);
					}
				}
			} else {
				if (this.sourceFile.isDirectory()) {
					this.zipOptions.setEncryptFiles(Boolean.FALSE);
					this.zipOptions.setEncryptionMethod(Globals.ENC_NO_ENCRYPTION);
					this.zipOptions.setCompressionMethod(Globals.COMP_STORE);
				}
			}

			this.createGeneralFileHeaders();
			this.createLocalFileHeaders();

			if (this.zipFile.isSplitArchive()) {
				if (this.zipFile.getCentralDirectory() == null
						|| this.zipFile.getCentralDirectory().getFileHeaders() == null
						|| this.zipFile.getCentralDirectory().getFileHeaders().isEmpty()) {
					byte[] intBuffer = new byte[4];
					RawUtils.writeInt(intBuffer, ByteOrder.LITTLE_ENDIAN, (int) Globals.EXTSIG);
					this.outputStream.write(intBuffer);
					this.totalWriteBytes += 4L;
				}
			}

			if (this.outputStream instanceof SplitOutputStream) {
				if (this.totalWriteBytes == 4) {
					this.generalFileHeader.setOffsetLocalHeader(4L);
				} else {
					this.generalFileHeader
							.setOffsetLocalHeader(((SplitOutputStream) this.outputStream).getFilePointer());
				}
			} else {
				if (this.totalWriteBytes == 4) {
					this.generalFileHeader.setOffsetLocalHeader(4L);
				} else {
					this.generalFileHeader.setOffsetLocalHeader(this.totalWriteBytes);
				}
			}

			this.totalWriteBytes += this.writeLocalFileHeader(this.localFileHeader, this.outputStream);

			if (this.zipOptions.isEncryptFiles()) {
				this.initEncryptor();
				if (this.encryptor != null) {
					if (this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_STANDARD) {
						byte[] headerBytes = ((StandardEncryptor) this.encryptor).getHeaderBytes();
						this.outputStream.write(headerBytes);
						this.totalWriteBytes += headerBytes.length;
						this.bytesWrittenForThisFile += headerBytes.length;
					} else if (this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
						byte[] saltBytes = ((AESEncryptor) this.encryptor).getSaltBytes();
						byte[] passwordVerifier = ((AESEncryptor) this.encryptor).getDerivedPasswordVerifier();
						this.outputStream.write(saltBytes);
						this.outputStream.write(passwordVerifier);
						this.totalWriteBytes += saltBytes.length + passwordVerifier.length;
						this.bytesWrittenForThisFile += saltBytes.length + passwordVerifier.length;
					}
				}
			}

			this.crc.reset();
		} catch (ZipException e) {
			throw e;
		} catch (Exception e) {
			throw new ZipException(0x0000001B0015L, "Failed_Add_File_Zip_Error", e);
		}
	}

	@Override
	public void write(int b) throws IOException {
		byte[] buffer = new byte[1];
		buffer[0] = (byte) b;
		this.write(buffer, 0, 1);
	}

	@Override
	public void write(@Nonnull byte[] b) throws IOException {
		if (b.length == 0) {
			return;
		}

		this.write(b, 0, b.length);
	}

	@Override
	public void write(@Nonnull byte[] b, int off, int len) throws IOException {
		if (len == 0) {
			return;
		}

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
			if (this.pendingBufferLength != 0) {
				if (len >= (Globals.AES_BLOCK_SIZE - this.pendingBufferLength)) {
					System.arraycopy(b, off, this.pendingBuffer, this.pendingBufferLength,
							(Globals.AES_BLOCK_SIZE - this.pendingBufferLength));
					this.encryptAndWrite(this.pendingBuffer, 0, this.pendingBuffer.length);
					off = (Globals.AES_BLOCK_SIZE - this.pendingBufferLength);
					len -= off;
					this.pendingBufferLength = 0;
				} else {
					System.arraycopy(b, off, this.pendingBuffer, this.pendingBufferLength, len);
					this.pendingBufferLength += len;
					return;
				}
			}

			if (len % 16 != 0) {
				System.arraycopy(b, (len + off) - (len % 16), this.pendingBuffer, 0, len % 16);
				this.pendingBufferLength = len % 16;
				len -= this.pendingBufferLength;
			}
		}

		if (len != 0) {
			this.encryptAndWrite(b, off, len);
		}
	}

	/**
	 * Close entry.
	 *
	 * @throws IOException  the io exception
	 * @throws ZipException the zip exception
	 */
	public void closeEntry() throws IOException, ZipException {
		if (this.pendingBufferLength != 0) {
			this.encryptAndWrite(this.pendingBuffer, 0, this.pendingBufferLength);
			this.pendingBufferLength = 0;
		}

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
			if (this.encryptor instanceof AESEncryptor) {
				this.outputStream.write(((AESEncryptor) this.encryptor).getFinalMac());
				this.bytesWrittenForThisFile += 10;
				this.totalWriteBytes += 10;
			} else {
				throw new ZipException(0x0000001B0014L, "Invalid_Encryptor_AES_Zip_Error");
			}
		}

		this.generalFileHeader.setCompressedSize(this.bytesWrittenForThisFile);
		this.localFileHeader.setCompressedSize(this.bytesWrittenForThisFile);

		if (this.zipOptions.isSourceExternalStream()) {
			this.generalFileHeader.setOriginalSize(this.totalReadBytes);
			if (this.localFileHeader.getOriginalSize() != this.totalReadBytes) {
				this.localFileHeader.setOriginalSize(this.totalReadBytes);
			}
		}

		long crc32 = this.crc.getValue();

		if (this.generalFileHeader.isEncrypted()
				&& this.generalFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
			crc32 = 0L;
		}

		this.generalFileHeader.setCrc32(crc32);
		this.localFileHeader.setCrc32(crc32);

		this.zipFile.getLocalFileHeaderList().add(this.localFileHeader);
		this.zipFile.getCentralDirectory().getFileHeaders().add(this.generalFileHeader);

		try {
			this.totalWriteBytes +=
					HeaderOperator.writeExtendedLocalHeader(this.localFileHeader, this.outputStream);
		} catch (DataInvalidException e) {
			throw new IOException(e);
		}

		this.crc.reset();
		this.bytesWrittenForThisFile = 0L;
		this.encryptor = null;
		this.totalReadBytes = 0L;
	}

	/**
	 * Finish.
	 *
	 * @throws ZipException the zip exception
	 */
	public void finish() throws ZipException {
		this.zipFile.getEndCentralDirectoryRecord().setOffsetOfStartOfCentralDirectory(this.totalWriteBytes);
		this.zipFile.finalizeZipFile(this.outputStream);
	}

	public void close() throws IOException {
		if (this.outputStream != null) {
			this.outputStream.close();
		}
	}

	/**
	 * Update total bytes read.
	 *
	 * @param readCount the read count
	 */
	void updateTotalBytesRead(int readCount) {
		if (readCount > 0) {
			this.totalReadBytes += readCount;
		}
	}

	private void encryptAndWrite(byte[] b, int off, int len) throws IOException {
		if (this.encryptor != null) {
			try {
				this.encryptor.encryptData(b, off, len);
			} catch (ZipException e) {
				throw new IOException(e);
			}
		}

		this.outputStream.write(b, off, len);
		this.totalWriteBytes += len;
		this.bytesWrittenForThisFile += len;
	}

	private void initZipFile() {
		if (this.zipFile.getEndCentralDirectoryRecord() == null) {
			this.zipFile.setEndCentralDirectoryRecord(new EndCentralDirectoryRecord());
		}

		if (this.zipFile.getCentralDirectory() == null) {
			this.zipFile.setCentralDirectory(new CentralDirectory());
		}

		if (this.zipFile.getCentralDirectory().getFileHeaders() == null) {
			this.zipFile.getCentralDirectory().setFileHeaders(new ArrayList<>());
		}

		if (this.zipFile.getLocalFileHeaderList() == null) {
			this.zipFile.setLocalFileHeaderList(new ArrayList<>());
		}

		if (this.outputStream instanceof SplitOutputStream) {
			if (((SplitOutputStream) this.outputStream).isSplitZipFile()) {
				this.zipFile.setSplitArchive(true);
				this.zipFile.setSplitLength(((SplitOutputStream) this.outputStream).getSplitLength());
			}
		}

		this.zipFile.getEndCentralDirectoryRecord().setSignature(Globals.ENDSIG);
	}

	private void createGeneralFileHeaders() throws ZipException {
		this.generalFileHeader = new GeneralFileHeader();

		this.generalFileHeader.setSignature((int) Globals.CENSIG);
		this.generalFileHeader.setMadeVersion(20);
		this.generalFileHeader.setExtractNeeded(20);

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
			this.generalFileHeader.setCompressionMethod(Globals.ENC_METHOD_AES);
			this.generateAESExtraDataRecord();
		} else {
			this.generalFileHeader.setCompressionMethod(this.zipOptions.getCompressionMethod());
		}

		if (this.zipOptions.isEncryptFiles()) {
			this.generalFileHeader.setEncrypted(Boolean.TRUE);
			this.generalFileHeader.setEncryptionMethod(this.zipOptions.getEncryptionMethod());
		}

		String entryPath;
		if (this.zipOptions.isSourceExternalStream()) {
			this.generalFileHeader.setLastModFileTime((int) DateTimeUtils.toDosTime(System.currentTimeMillis()));
			if (this.zipOptions.getFileNameInZip() == null || this.zipOptions.getFileNameInZip().isEmpty()) {
				throw new ZipException(0x0000001B0016L, "Null_File_Name_Zip_Error");
			}
			entryPath = this.zipOptions.getFileNameInZip();
		} else {
			this.generalFileHeader.setLastModFileTime(
					(int) DateTimeUtils.toDosTime(FileUtils.lastModify(this.sourceFile.getAbsolutePath())));
			this.generalFileHeader.setOriginalSize(this.sourceFile.length());
			entryPath = ZipFile.getRelativeFileName(this.sourceFile.getAbsolutePath(),
					this.zipOptions.getRootFolderInZip(), this.zipOptions.getDefaultFolderPath());
		}

		if (entryPath == null || entryPath.isEmpty()) {
			throw new ZipException(0x0000001B0016L, "Null_File_Name_Zip_Error");
		}
		this.generalFileHeader.setEntryPath(entryPath);

		if (StringUtils.notBlank(this.zipFile.getCharsetEncoding())) {
			this.generalFileHeader.setFileNameLength(
					StringUtils.encodedStringLength(entryPath, this.zipFile.getCharsetEncoding()));
		} else {
			this.generalFileHeader.setFileNameLength(StringUtils.encodedStringLength(entryPath));
		}

		if (this.outputStream instanceof SplitOutputStream) {
			this.generalFileHeader
					.setDiskNumberStart(((SplitOutputStream) this.outputStream).getCurrentSplitFileIndex());
		} else {
			this.generalFileHeader.setDiskNumberStart(0);
		}

		int fileAttrs = 0;

		if (!this.zipOptions.isSourceExternalStream()) {
			fileAttrs = this.getFileAttributes(this.sourceFile);
		}

		byte[] externalFileAttrs = {(byte) fileAttrs, 0, 0, 0};
		this.generalFileHeader.setExternalFileAttr(externalFileAttrs);

		boolean isDirectory;
		if (this.zipOptions.isSourceExternalStream()) {
			isDirectory = entryPath.endsWith(Globals.DEFAULT_ZIP_PAGE_SEPARATOR)
					|| entryPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR);
		} else {
			isDirectory = this.sourceFile.isDirectory();
		}
		this.generalFileHeader.setDirectory(isDirectory);

		if (this.generalFileHeader.isDirectory()) {
			this.generalFileHeader.setCompressedSize(0L);
			this.generalFileHeader.setOriginalSize(0L);
		} else {
			if (!this.zipOptions.isSourceExternalStream()) {
				long fileSize = FileUtils.fileSize(this.sourceFile);
				if (this.zipOptions.getCompressionMethod() == Globals.COMP_STORE) {
					if (this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_STANDARD) {
						this.generalFileHeader.setCompressedSize(fileSize + Globals.STD_DEC_HDR_SIZE);
					} else if (this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
						int saltLength;
						switch (this.zipOptions.getAesKeyStrength()) {
							case Globals.AES_STRENGTH_128:
								saltLength = 8;
								break;
							case Globals.AES_STRENGTH_256:
								saltLength = 16;
								break;
							default:
								throw new ZipException(0x0000001B0005L, "Invalid_Key_Strength_AES_Zip_Error");
						}
						this.generalFileHeader
								.setCompressedSize(fileSize + saltLength + Globals.AES_AUTH_LENGTH + 2);
					} else {
						this.generalFileHeader.setCompressedSize(0L);
					}
				} else {
					this.generalFileHeader.setCompressedSize(0L);
				}
				this.generalFileHeader.setOriginalSize(fileSize);
			}
		}

		if (this.zipOptions.isEncryptFiles()
				&& this.zipOptions.getEncryptionMethod() == Globals.ENC_METHOD_STANDARD) {
			this.generalFileHeader.setCrc32(this.zipOptions.getSourceFileCRC());
		}

		byte[] generalPurposeFlag = new byte[2];
		int[] bitArray = this.generateGeneralPurposeBitArray(this.generalFileHeader.isEncrypted(),
				this.zipOptions.getCompressionMethod());
		generalPurposeFlag[0] = RawUtils.bitArrayToByte(bitArray);

		boolean isFileNameCharset = StringUtils.notBlank(this.zipFile.getCharsetEncoding());

		if ((isFileNameCharset && this.zipFile.getCharsetEncoding().equalsIgnoreCase(Globals.DEFAULT_ENCODING))
				|| (!isFileNameCharset && StringUtils.detectCharset(this.generalFileHeader.getEntryPath())
				.equalsIgnoreCase(Globals.DEFAULT_ENCODING))) {
			generalPurposeFlag[1] = 8;
		}

		this.generalFileHeader.setGeneralPurposeFlag(generalPurposeFlag);
	}

	private void generateAESExtraDataRecord() throws ZipException {
		if (this.zipOptions == null) {
			throw new ZipException(0x000000FF0001L, "Parameter_Invalid_Error");
		}

		AESExtraDataRecord aesExtraDataRecord = new AESExtraDataRecord();
		aesExtraDataRecord.setSignature(Globals.AESSIG);
		aesExtraDataRecord.setDataSize(7);
		aesExtraDataRecord.setVendorID("AE");

		aesExtraDataRecord.setVersionNumber(2);

		if (this.zipOptions.getAesKeyStrength() == Globals.AES_STRENGTH_128) {
			aesExtraDataRecord.setAesStrength(Globals.AES_STRENGTH_128);
		} else if (this.zipOptions.getAesKeyStrength() == Globals.AES_STRENGTH_256) {
			aesExtraDataRecord.setAesStrength(Globals.AES_STRENGTH_256);
		} else {
			throw new ZipException(0x0000001B0005L, "Invalid_Key_Strength_AES_Zip_Error");
		}

		aesExtraDataRecord.setCompressionMethod(this.zipOptions.getCompressionMethod());

		this.generalFileHeader.setAesExtraDataRecord(aesExtraDataRecord);
	}

	private int getFileAttributes(File file) throws ZipException {
		if (file == null) {
			throw new ZipException(0x000000FF0001L, "Parameter_Invalid_Error");
		}

		if (!file.exists()) {
			return 0;
		}

		if (file.isDirectory()) {
			return Globals.FOLDER_MODE_NONE;
		} else {
			if (!file.canWrite()) {
				return Globals.FILE_MODE_READ_ONLY;
			} else {
				return Globals.FILE_MODE_NONE;
			}
		}
	}

	private int[] generateGeneralPurposeBitArray(boolean isEncrypted, int compressionMethod) {
		int[] generalPurposeFlag = new int[8];

		if (isEncrypted) {
			generalPurposeFlag[0] = 1;
		} else {
			generalPurposeFlag[0] = 0;
		}

		if (compressionMethod != Globals.COMP_DEFLATE) {
			generalPurposeFlag[1] = 0;
			generalPurposeFlag[2] = 0;
		}

		generalPurposeFlag[3] = 1;

		return generalPurposeFlag;
	}

	private void createLocalFileHeaders() throws ZipException {
		if (this.generalFileHeader == null) {
			throw new ZipException(0x0000001B000FL, "Null_General_File_Header_Zip_Error");
		}

		this.localFileHeader = new LocalFileHeader();

		this.localFileHeader.setSignature((int) Globals.LOCSIG);
		this.localFileHeader.setExtractNeeded(this.generalFileHeader.getExtractNeeded());
		this.localFileHeader.setCompressionMethod(this.generalFileHeader.getCompressionMethod());
		this.localFileHeader.setLastModFileTime(this.generalFileHeader.getLastModFileTime());
		this.localFileHeader.setOriginalSize(this.generalFileHeader.getOriginalSize());
		this.localFileHeader.setFileNameLength(this.generalFileHeader.getFileNameLength());
		this.localFileHeader.setEntryPath(this.generalFileHeader.getEntryPath());
		this.localFileHeader.setEncrypted(this.generalFileHeader.isEncrypted());
		this.localFileHeader.setEncryptionMethod(this.generalFileHeader.getEncryptionMethod());
		this.localFileHeader.setAesExtraDataRecord(this.generalFileHeader.getAesExtraDataRecord());
		this.localFileHeader.setCrc32(this.generalFileHeader.getCrc32());
		this.localFileHeader.setCompressedSize(this.generalFileHeader.getCompressedSize());
		this.localFileHeader.setGeneralPurposeFlag(this.generalFileHeader.getGeneralPurposeFlag().clone());
	}

	private void initEncryptor() throws ZipException {
		if (this.zipOptions.isEncryptFiles()) {
			switch (this.zipOptions.getEncryptionMethod()) {
				case Globals.ENC_METHOD_STANDARD:
					this.encryptor = new StandardEncryptor(this.zipOptions.getPassword(),
							(this.localFileHeader.getLastModFileTime() & 0x0000FFFF) << 16);
					break;
				case Globals.ENC_METHOD_AES:
					this.encryptor = new AESEncryptor(this.zipOptions.getPassword(), this.zipOptions.getAesKeyStrength());
					break;
				default:
					throw new ZipException(0x0000001B0001L, "Not_Supported_Encryption_Mode_Zip_Error");
			}
		} else {
			this.encryptor = null;
		}
	}

	private int writeLocalFileHeader(LocalFileHeader localFileHeader,
	                                 OutputStream outputStream) throws ZipException {
		if (localFileHeader == null) {
			throw new ZipException(0x0000001B000EL, "Null_Local_File_Header_Zip_Error");
		}
		try {
			List<String> headerBytesList = new ArrayList<>();

			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];
			byte[] emptyLongBuffer = {0, 0, 0, 0, 0, 0, 0, 0};

			RawUtils.writeInt(intBuffer, ByteOrder.LITTLE_ENDIAN, localFileHeader.getSignature());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			RawUtils.writeShort(shortBuffer, ByteOrder.LITTLE_ENDIAN, (short) localFileHeader.getExtractNeeded());
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			HeaderOperator.copyByteArrayToList(localFileHeader.getGeneralPurposeFlag(), headerBytesList);

			RawUtils.writeShort(shortBuffer, ByteOrder.LITTLE_ENDIAN, (short) localFileHeader.getCompressionMethod());
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			RawUtils.writeInt(intBuffer, ByteOrder.LITTLE_ENDIAN, localFileHeader.getLastModFileTime());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			RawUtils.writeInt(intBuffer, ByteOrder.LITTLE_ENDIAN, (int) localFileHeader.getCrc32());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			boolean writingZip64Record = Boolean.FALSE;

			long originalSize = localFileHeader.getOriginalSize();
			if (originalSize + Globals.ZIP64_EXTRA_BUFFER_SIZE >= Globals.ZIP_64_LIMIT) {
				RawUtils.writeLong(longBuffer, ByteOrder.LITTLE_ENDIAN, Globals.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);

				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
				writingZip64Record = true;
				localFileHeader.setWriteCompressSizeInZip64ExtraRecord(true);
			} else {
				RawUtils.writeLong(longBuffer, ByteOrder.LITTLE_ENDIAN, localFileHeader.getCompressedSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

				RawUtils.writeLong(longBuffer, ByteOrder.LITTLE_ENDIAN, localFileHeader.getOriginalSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

				localFileHeader.setWriteCompressSizeInZip64ExtraRecord(Boolean.FALSE);
			}

			RawUtils.writeShort(shortBuffer, ByteOrder.LITTLE_ENDIAN, (short) localFileHeader.getFileNameLength());
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			int extraFieldLength = 0;
			if (writingZip64Record) {
				extraFieldLength += 20;
			}

			if (localFileHeader.getAesExtraDataRecord() != null) {
				extraFieldLength += 11;
			}

			RawUtils.writeShort(shortBuffer, ByteOrder.LITTLE_ENDIAN, (short) extraFieldLength);
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			if (StringUtils.notBlank(this.zipFile.getCharsetEncoding())) {
				byte[] fileNameBytes = localFileHeader.getEntryPath().getBytes(this.zipFile.getCharsetEncoding());
				HeaderOperator.copyByteArrayToList(fileNameBytes, headerBytesList);
			} else {
				HeaderOperator.copyByteArrayToList(localFileHeader.getEntryPath(), headerBytesList);
			}

			if (writingZip64Record) {
				RawUtils.writeShort(shortBuffer, ByteOrder.LITTLE_ENDIAN, (short) Globals.EXTRAFIELDZIP64LENGTH);
				HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

				RawUtils.writeShort(shortBuffer, ByteOrder.LITTLE_ENDIAN, (short) 16);
				HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

				RawUtils.writeLong(longBuffer, ByteOrder.LITTLE_ENDIAN, localFileHeader.getOriginalSize());
				HeaderOperator.copyByteArrayToList(longBuffer, headerBytesList);

				HeaderOperator.copyByteArrayToList(emptyLongBuffer, headerBytesList);
			}

			if (localFileHeader.getAesExtraDataRecord() != null) {
				AESEngine.processHeader(localFileHeader.getAesExtraDataRecord(), headerBytesList);
			}

			byte[] bytes = HeaderOperator.convertByteArrayListToByteArray(headerBytesList);
			outputStream.write(bytes);
			outputStream.flush();

			return bytes.length;
		} catch (Exception e) {
			throw new ZipException(0x0000001B0017L, "Write_Local_File_Header_Zip_Error", e);
		}
	}
}
