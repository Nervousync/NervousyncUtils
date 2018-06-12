/*
 * Copyright © 2003 Nervousync Studio, Inc. All rights reserved.
 * This software is the confidential and proprietary information of 
 * Nervousync Studio, Inc. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the 
 * license agreement you entered into with Nervousync Studio.
 */
package com.nervousync.commons.zip.io;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.UnsupportedCharsetException;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.CRC32;

import com.nervousync.commons.core.Globals;
import com.nervousync.commons.core.zip.ZipConstants;
import com.nervousync.commons.core.zip.ZipOptions;
import com.nervousync.commons.zip.ZipFile;
import com.nervousync.commons.zip.crypto.Encryptor;
import com.nervousync.commons.zip.crypto.impl.AESEncryptor;
import com.nervousync.commons.zip.crypto.impl.StandardEncryptor;
import com.nervousync.commons.zip.models.AESExtraDataRecord;
import com.nervousync.commons.zip.models.central.CentralDirectory;
import com.nervousync.commons.zip.models.central.EndCentralDirectoryRecord;
import com.nervousync.commons.zip.models.header.GeneralFileHeader;
import com.nervousync.commons.zip.models.header.LocalFileHeader;
import com.nervousync.commons.zip.models.header.utils.HeaderOperator;
import com.nervousync.commons.zip.operator.RawOperator;
import com.nervousync.exceptions.zip.ZipException;
import com.nervousync.utils.DateTimeUtils;
import com.nervousync.utils.FileUtils;
import com.nervousync.utils.StringUtils;

/**
 * @author Steven Wee
 *         <a href="mailto:wmkm0113@Hotmail.com">wmkm0113@Hotmail.com</a>
 * @version $Revision: 1.0 $ $Date: Nov 29, 2017 2:39:25 PM $
 */
public class CipherOutputStream extends OutputStream {

	private OutputStream outputStream;
	private File sourceFile;
	private GeneralFileHeader generalFileHeader;
	private LocalFileHeader localFileHeader;
	private Encryptor encryptor;
	protected ZipOptions zipOptions;
	private ZipFile zipFile;
	protected CRC32 crc;
	private long totalWriteBytes;
	private long totalReadBytes;
	protected long bytesWrittenForThisFile;
	private byte[] pendingBuffer;
	private int pendingBufferLength;

	public CipherOutputStream(OutputStream outputStream, ZipFile zipFile) {
		this.outputStream = outputStream;
		this.zipFile = zipFile;
		this.initZipFile();
		this.crc = new CRC32();
		this.totalWriteBytes = 0L;
		this.bytesWrittenForThisFile = 0L;
		this.totalReadBytes = 0L;
		this.pendingBuffer = new byte[ZipConstants.AES_BLOCK_SIZE];
		this.pendingBufferLength = 0;
	}

	public void putNextEntry(File file, ZipOptions zipOptions) throws ZipException {
		if (!zipOptions.isSourceExternalStream() && file == null) {
			throw new ZipException("Input file is null!");
		}
		
		if (!zipOptions.isSourceExternalStream() && !FileUtils.isExists(file.getAbsolutePath())) {
			throw new ZipException("Input file does not exists!");
		}
		
		try {
			this.sourceFile = file;
			this.zipOptions = (ZipOptions) zipOptions.clone();

			if (this.zipOptions.isSourceExternalStream()) {
				if (this.zipOptions.getFileNameInZip() != null) {
					if (this.zipOptions.getFileNameInZip().endsWith("/")
							|| this.zipOptions.getFileNameInZip().endsWith("\\")) {
						this.zipOptions.setCompressionMethod(ZipConstants.COMP_STORE);
					}
				}
			} else {
				if (this.sourceFile.isDirectory()) {
					this.zipOptions.setCompressionMethod(ZipConstants.COMP_STORE);
				}
			}
			
			this.createGeneralFileHeaders();
			this.createLocalFileHeaders();
			
			if (this.zipFile.isSplitArchive()) {
				if (this.zipFile.getCentralDirectory() == null
						|| this.zipFile.getCentralDirectory().getFileHeaders() == null
						|| this.zipFile.getCentralDirectory().getFileHeaders().size() == 0) {
					byte[] intBuffer = new byte[4];
					RawOperator.writeIntFromLittleEndian(intBuffer, 0, (int) ZipConstants.SPLITSIG);
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
					if (this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_STANDARD) {
						byte[] headerBytes = ((StandardEncryptor) this.encryptor).getHeaderBytes();
						this.outputStream.write(headerBytes);
						this.totalWriteBytes += headerBytes.length;
						this.bytesWrittenForThisFile += headerBytes.length;
					} else if (this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
						byte[] saltBytes = ((AESEncryptor) this.encryptor).getSaltBytes();
						byte[] passwordVerifier = ((AESEncryptor) this.encryptor).getDerviedPasswordVerifier();
						this.outputStream.write(saltBytes);
						this.outputStream.write(passwordVerifier);
						this.totalWriteBytes += saltBytes.length + passwordVerifier.length;
						this.bytesWrittenForThisFile += saltBytes.length + passwordVerifier.length;
					}
				}
			}

			this.crc.reset();
		} catch (CloneNotSupportedException e) {
			throw new ZipException(e);
		} catch (ZipException e) {
			throw e;
		} catch (Exception e) {
			throw new ZipException(e);
		}
	}

	@Override
	public void write(int b) throws IOException {
		byte[] buffer = new byte[1];
		buffer[0] = (byte) b;
		this.write(buffer, 0, 1);
	}

	@Override
	public void write(byte[] b) throws IOException {
		if (b == null) {
			throw new NullPointerException();
		}

		if (b.length == 0) {
			return;
		}

		this.write(b, 0, b.length);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		if (len == 0) {
			return;
		}

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
			if (this.pendingBufferLength != 0) {
				if (len >= (ZipConstants.AES_BLOCK_SIZE - this.pendingBufferLength)) {
					System.arraycopy(b, off, this.pendingBuffer, this.pendingBufferLength,
							(ZipConstants.AES_BLOCK_SIZE - this.pendingBufferLength));
					this.encryptAndWrite(this.pendingBuffer, 0, this.pendingBuffer.length);
					off = (ZipConstants.AES_BLOCK_SIZE - this.pendingBufferLength);
					len -= off;
					this.pendingBufferLength = 0;
				} else {
					System.arraycopy(b, off, this.pendingBuffer, this.pendingBufferLength, len);
					this.pendingBufferLength += len;
					return;
				}
			}

			if (len != 0 && len % 16 != 0) {
				System.arraycopy(b, (len + off) - (len % 16), this.pendingBuffer, 0, len % 16);
				this.pendingBufferLength = len % 16;
				len -= this.pendingBufferLength;
			}
		}

		if (len != 0) {
			this.encryptAndWrite(b, off, len);
		}
	}

	public void closeEntry() throws IOException, ZipException {
		if (this.pendingBufferLength != 0) {
			this.encryptAndWrite(this.pendingBuffer, 0, this.pendingBufferLength);
			this.pendingBufferLength = 0;
		}

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
			if (this.encryptor instanceof AESEncryptor) {
				this.outputStream.write(((AESEncryptor) this.encryptor).getFinalMac());
				this.bytesWrittenForThisFile += 10;
				this.totalWriteBytes += 10;
			} else {
				throw new ZipException("invalid encrypter for AES encrypted file");
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

		if (this.generalFileHeader.isEncrypted()) {
			if (this.generalFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
				crc32 = 0;
			}
		}

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
			this.generalFileHeader.setCrc32(0L);
			this.localFileHeader.setCrc32(0L);
		} else {
			this.generalFileHeader.setCrc32(crc32);
			this.localFileHeader.setCrc32(crc32);
		}

		this.zipFile.getLocalFileHeaderList().add(this.localFileHeader);
		this.zipFile.getCentralDirectory().getFileHeaders().add(this.generalFileHeader);

		this.totalWriteBytes += 
				HeaderOperator.writeExtendedLocalHeader(this.localFileHeader, this.outputStream);

		this.crc.reset();
		this.bytesWrittenForThisFile = 0L;
		this.encryptor = null;
		this.totalReadBytes = 0L;
	}

	public void finish() throws IOException, ZipException {
		this.zipFile.getEndCentralDirectoryRecord().setOffsetOfStartOfCentralDirectory(this.totalWriteBytes);
		this.zipFile.finalizeZipFile(this.outputStream);
	}

	public void close() throws IOException {
		if (this.outputStream != null) {
			this.outputStream.close();
		}
	}

	protected void updateTotalBytesRead(int readCount) {
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
			this.zipFile.getCentralDirectory().setFileHeaders(new ArrayList<GeneralFileHeader>());
		}

		if (this.zipFile.getLocalFileHeaderList() == null) {
			this.zipFile.setLocalFileHeaderList(new ArrayList<LocalFileHeader>());
		}

		if (this.outputStream instanceof SplitOutputStream) {
			if (((SplitOutputStream) this.outputStream).isSplitZipFile()) {
				this.zipFile.setSplitArchive(true);
				this.zipFile.setSplitLength(((SplitOutputStream) this.outputStream).getSplitLength());
			}
		}

		this.zipFile.getEndCentralDirectoryRecord().setSignature(ZipConstants.ENDSIG);
	}

	private void createGeneralFileHeaders() throws ZipException {
		this.generalFileHeader = new GeneralFileHeader();

		this.generalFileHeader.setSignature((int) ZipConstants.CENSIG);
		this.generalFileHeader.setMadeVersion(20);
		this.generalFileHeader.setExtractNeeded(20);

		if (this.zipOptions.isEncryptFiles() && this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
			this.generalFileHeader.setCompressionMethod(ZipConstants.ENC_METHOD_AES);
			this.generateAESExtraDataRecord();
		} else {
			this.generalFileHeader.setCompressionMethod(this.zipOptions.getCompressionMethod());
		}

		if (this.zipOptions.isEncryptFiles()) {
			this.generalFileHeader.setEncrypted(true);
			this.generalFileHeader.setEncryptionMethod(this.zipOptions.getEncryptionMethod());
		}

		String entryPath = null;
		if (this.zipOptions.isSourceExternalStream()) {
			this.generalFileHeader.setLastModFileTime((int) DateTimeUtils.toDosTime(System.currentTimeMillis()));
			if (this.zipOptions.getFileNameInZip() == null || this.zipOptions.getFileNameInZip().length() == 0) {
				throw new ZipException("fileNameInZip is null or empty");
			}
			entryPath = this.zipOptions.getFileNameInZip();
		} else {
			this.generalFileHeader.setLastModFileTime(
					(int) DateTimeUtils.toDosTime(FileUtils.lastModify(this.sourceFile.getAbsolutePath())));
			this.generalFileHeader.setOriginalSize(this.sourceFile.length());
			entryPath = ZipFile.getRelativeFileName(this.sourceFile.getAbsolutePath(),
					this.zipOptions.getRootFolderInZip(), this.zipOptions.getDefaultFolderPath());
		}

		if (entryPath == null || entryPath.length() == 0) {
			throw new ZipException("fileName is null or empty. unable to create file header");
		}
		this.generalFileHeader.setEntryPath(entryPath);

		if (StringUtils.isNotNullAndNotEmpty(this.zipFile.getFileNameCharset())) {
			this.generalFileHeader.setFileNameLength(
					StringUtils.getEncodedStringLength(entryPath, this.zipFile.getFileNameCharset()));
		} else {
			this.generalFileHeader.setFileNameLength(StringUtils.getEncodedStringLength(entryPath));
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

		byte[] externalFileAttrs = { (byte) fileAttrs, 0, 0, 0 };
		this.generalFileHeader.setExternalFileAttr(externalFileAttrs);
		
		boolean isDirectory = Globals.DEFAULT_VALUE_BOOLEAN;
		if (this.zipOptions.isSourceExternalStream()) {
			isDirectory = entryPath.endsWith(ZipConstants.ZIP_FILE_SEPARATOR) 
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
				long fileSize = FileUtils.getFileSize(this.sourceFile);
				if (this.zipOptions.getCompressionMethod() == ZipConstants.COMP_STORE) {
					if (this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_STANDARD) {
						this.generalFileHeader.setCompressedSize(fileSize + ZipConstants.STD_DEC_HDR_SIZE);
					} else if (this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
						int saltLength = 0;
						switch (this.zipOptions.getAesKeyStrength()) {
						case ZipConstants.AES_STRENGTH_128:
							saltLength = 8;
							break;
						case ZipConstants.AES_STRENGTH_256:
							saltLength = 16;
							break;
						default:
							throw new ZipException("invalid aes key strength, cannot determine key sizes");
						}
						this.generalFileHeader
								.setCompressedSize(fileSize + saltLength + ZipConstants.AES_AUTH_LENGTH + 2);
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
				&& this.zipOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_STANDARD) {
			this.generalFileHeader.setCrc32(this.zipOptions.getSourceFileCRC());
		}

		byte[] generalPurposeFlag = new byte[2];
		int[] bitArray = this.generateGeneralPurposeBitArray(this.generalFileHeader.isEncrypted(),
				this.zipOptions.getCompressionMethod());
		generalPurposeFlag[0] = RawOperator.convertBitArrayToByte(bitArray);

		boolean isFileNameCharset = StringUtils.isNotNullAndNotEmpty(this.zipFile.getFileNameCharset());

		if ((isFileNameCharset && this.zipFile.getFileNameCharset().equalsIgnoreCase(Globals.DEFAULT_ENCODING))
				|| (!isFileNameCharset && StringUtils.detectCharSet(this.generalFileHeader.getEntryPath())
						.equalsIgnoreCase(Globals.DEFAULT_ENCODING))) {
			generalPurposeFlag[1] = 8;
		} else {
			generalPurposeFlag[1] = 0;
		}

		this.generalFileHeader.setGeneralPurposeFlag(generalPurposeFlag);
	}

	private void generateAESExtraDataRecord() throws ZipException {
		if (this.zipOptions == null) {
			throw new ZipException("zip parameters are null, cannot generate AES Extra Data record");
		}

		AESExtraDataRecord aesExtraDataRecord = new AESExtraDataRecord();
		aesExtraDataRecord.setSignature(ZipConstants.AESSIG);
		aesExtraDataRecord.setDataSize(7);
		aesExtraDataRecord.setVendorID("AE");

		aesExtraDataRecord.setVersionNumber(2);

		if (this.zipOptions.getAesKeyStrength() == ZipConstants.AES_STRENGTH_128) {
			aesExtraDataRecord.setAesStrength(ZipConstants.AES_STRENGTH_128);
		} else if (this.zipOptions.getAesKeyStrength() == ZipConstants.AES_STRENGTH_256) {
			aesExtraDataRecord.setAesStrength(ZipConstants.AES_STRENGTH_256);
		} else {
			throw new ZipException("invalid AES key strength, cannot generate AES Extra data record");
		}

		aesExtraDataRecord.setCompressionMethod(this.zipOptions.getCompressionMethod());

		this.generalFileHeader.setAesExtraDataRecord(aesExtraDataRecord);
	}

	private int getFileAttributes(File file) throws ZipException {
		if (file == null) {
			throw new ZipException("input file is null, cannot get file attributes");
		}

		if (!file.exists()) {
			return 0;
		}

		if (file.isDirectory()) {
			return ZipConstants.FOLDER_MODE_NONE;
		} else {
			if (!file.canWrite()) {
				return ZipConstants.FILE_MODE_READ_ONLY;
			} else {
				return ZipConstants.FILE_MODE_NONE;
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

		if (compressionMethod == ZipConstants.COMP_DEFLATE) {
			// Set flag for deflate
		} else {
			generalPurposeFlag[1] = 0;
			generalPurposeFlag[2] = 0;
		}

		generalPurposeFlag[3] = 1;

		return generalPurposeFlag;
	}

	private void createLocalFileHeaders() throws ZipException {
		if (this.generalFileHeader == null) {
			throw new ZipException("file header is null, cannot create local file header");
		}

		this.localFileHeader = new LocalFileHeader();

		this.localFileHeader.setSignature((int) ZipConstants.LOCSIG);
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
		this.localFileHeader.setGeneralPurposeFlag((byte[]) this.generalFileHeader.getGeneralPurposeFlag().clone());
	}

	private void initEncryptor() throws ZipException {
		if (this.zipOptions.isEncryptFiles()) {
			switch (this.zipOptions.getEncryptionMethod()) {
			case ZipConstants.ENC_METHOD_STANDARD:
				this.encryptor = new StandardEncryptor(this.zipOptions.getPassword(),
						(this.localFileHeader.getLastModFileTime() & 0x0000FFFF) << 16);
				break;
			case ZipConstants.ENC_METHOD_AES:
				this.encryptor = new AESEncryptor(this.zipOptions.getPassword(), this.zipOptions.getAesKeyStrength());
				break;
			default:
				throw new ZipException("invalid encprytion method");
			}
		} else {
			this.encryptor = null;
		}
	}
	
	private int writeLocalFileHeader(LocalFileHeader localFileHeader,
			OutputStream outputStream) throws ZipException {
		if (localFileHeader == null) {
			throw new ZipException("Local file header is null, cannot write!");
		}
		try {
			List<String> byteArrayList = new ArrayList<String>();

			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];
			byte[] emptyLongBuffer = { 0, 0, 0, 0, 0, 0, 0, 0 };

			RawOperator.writeIntFromLittleEndian(intBuffer, 0, localFileHeader.getSignature());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, byteArrayList);

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) localFileHeader.getExtractNeeded());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

			HeaderOperator.copyByteArrayToArrayList(localFileHeader.getGeneralPurposeFlag(), byteArrayList);

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) localFileHeader.getCompressionMethod());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

			RawOperator.writeIntFromLittleEndian(intBuffer, 0, localFileHeader.getLastModFileTime());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, byteArrayList);

			RawOperator.writeIntFromLittleEndian(intBuffer, 0, (int) localFileHeader.getCrc32());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, byteArrayList);

			boolean writingZip64Record = Globals.DEFAULT_VALUE_BOOLEAN;

			long originalSize = localFileHeader.getOriginalSize();
			if (originalSize + ZipConstants.ZIP64_EXTRA_BUFFER_SIZE >= ZipConstants.ZIP_64_LIMIT) {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, ZipConstants.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);

				HeaderOperator.copyByteArrayToArrayList(intBuffer, byteArrayList);
				writingZip64Record = true;
				localFileHeader.setWriteComprSizeInZip64ExtraRecord(true);
			} else {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, localFileHeader.getCompressedSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToArrayList(intBuffer, byteArrayList);

				RawOperator.writeLongFromLittleEndian(longBuffer, 0, localFileHeader.getOriginalSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToArrayList(intBuffer, byteArrayList);

				localFileHeader.setWriteComprSizeInZip64ExtraRecord(Globals.DEFAULT_VALUE_BOOLEAN);
			}

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) localFileHeader.getFileNameLength());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

			int extraFieldLength = 0;
			if (writingZip64Record) {
				extraFieldLength += 20;
			}

			if (localFileHeader.getAesExtraDataRecord() != null) {
				extraFieldLength += 11;
			}

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) extraFieldLength);
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

			if (StringUtils.isNotNullAndNotEmpty(this.zipFile.getFileNameCharset())) {
				byte[] fileNameBytes = localFileHeader.getEntryPath().getBytes(this.zipFile.getFileNameCharset());
				HeaderOperator.copyByteArrayToArrayList(fileNameBytes, byteArrayList);
			} else {
				HeaderOperator.copyByteArrayToArrayList(StringUtils.convertCharset(localFileHeader.getEntryPath()), byteArrayList);
			}

			if (writingZip64Record) {
				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) ZipConstants.EXTRAFIELDZIP64LENGTH);
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) 16);
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

				RawOperator.writeLongFromLittleEndian(longBuffer, 0, localFileHeader.getOriginalSize());
				HeaderOperator.copyByteArrayToArrayList(longBuffer, byteArrayList);

				HeaderOperator.copyByteArrayToArrayList(emptyLongBuffer, byteArrayList);
			}

			if (localFileHeader.getAesExtraDataRecord() != null) {
				AESExtraDataRecord aesExtraDataRecord = localFileHeader.getAesExtraDataRecord();

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) aesExtraDataRecord.getSignature());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) aesExtraDataRecord.getDataSize());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) aesExtraDataRecord.getVersionNumber());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);

				HeaderOperator.copyByteArrayToArrayList(aesExtraDataRecord.getVendorID().getBytes(), byteArrayList);

				byte[] aesStrengthBytes = new byte[1];
				aesStrengthBytes[0] = (byte) aesExtraDataRecord.getAesStrength();
				HeaderOperator.copyByteArrayToArrayList(aesStrengthBytes, byteArrayList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0,
						(short) aesExtraDataRecord.getCompressionMethod());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, byteArrayList);
			}

			byte[] bytes = HeaderOperator.convertByteArrayListToByteArray(byteArrayList);
			outputStream.write(bytes);

			return bytes.length;
		} catch (UnsupportedCharsetException e) {
			throw new ZipException(e);
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}
}
