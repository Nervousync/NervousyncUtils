/*
 * Copyright © 2003 Nervousync Studio, Inc. All rights reserved.
 * This software is the confidential and proprietary information of 
 * Nervousync Studio, Inc. You shall not disclose such Confidential
 * Information and shall use it only in accordance with the terms of the 
 * license agreement you entered into with Nervousync Studio.
 */
package com.nervousync.commons.zip;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nervousync.commons.core.Globals;
import com.nervousync.commons.core.zip.ZipConstants;
import com.nervousync.commons.core.zip.ZipOptions;
import com.nervousync.commons.io.NervousyncRandomAccessFile;
import com.nervousync.commons.zip.crypto.Decryptor;
import com.nervousync.commons.zip.crypto.impl.AESDecryptor;
import com.nervousync.commons.zip.crypto.impl.StandardDecryptor;
import com.nervousync.commons.zip.io.SplitOutputStream;
import com.nervousync.commons.zip.io.ZipOutputStream;
import com.nervousync.commons.zip.io.input.InflaterInputStream;
import com.nervousync.commons.zip.io.input.PartInputStream;
import com.nervousync.commons.zip.io.input.ZipInputStream;
import com.nervousync.commons.zip.models.AESExtraDataRecord;
import com.nervousync.commons.zip.models.ArchiveExtraDataRecord;
import com.nervousync.commons.zip.models.ExtraDataRecord;
import com.nervousync.commons.zip.models.Zip64ExtendInfo;
import com.nervousync.commons.zip.models.central.CentralDirectory;
import com.nervousync.commons.zip.models.central.DigitalSignature;
import com.nervousync.commons.zip.models.central.EndCentralDirectoryRecord;
import com.nervousync.commons.zip.models.central.Zip64EndCentralDirectoryLocator;
import com.nervousync.commons.zip.models.central.Zip64EndCentralDirectoryRecord;
import com.nervousync.commons.zip.models.header.FileHeader;
import com.nervousync.commons.zip.models.header.GeneralFileHeader;
import com.nervousync.commons.zip.models.header.LocalFileHeader;
import com.nervousync.commons.zip.models.header.utils.HeaderOperator;
import com.nervousync.commons.zip.operator.RawOperator;
import com.nervousync.exceptions.zip.ZipException;
import com.nervousync.utils.DateTimeUtils;
import com.nervousync.utils.FileUtils;
import com.nervousync.utils.StringUtils;

/**
 * @author Steven Wee	<a href="mailto:wmkm0113@Hotmail.com">wmkm0113@Hotmail.com</a>
 * @version $Revision: 1.0 $ $Date: Nov 28, 2017 5:01:20 PM $
 */
public final class ZipFile implements Cloneable {

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

	private String filePath = null;
	private String fileNameCharset = null;
	private List<LocalFileHeader> localFileHeaderList = null;
	private ArchiveExtraDataRecord archiveExtraDataRecord = null;
	private CentralDirectory centralDirectory = null;
	private EndCentralDirectoryRecord endCentralDirectoryRecord = null;
	private Zip64EndCentralDirectoryLocator zip64EndCentralDirectoryLocator = null;
	private Zip64EndCentralDirectoryRecord zip64EndCentralDirectoryRecord = null;
	private Decryptor decryptor = null;
	private boolean splitArchive = Globals.DEFAULT_VALUE_BOOLEAN;
	private long splitLength = Globals.DEFAULT_VALUE_LONG;
	private int currentSplitIndex = 0;
	private boolean zip64Format = Globals.DEFAULT_VALUE_BOOLEAN;
	
	public ZipFile(String filePath) throws ZipException {
		this(filePath, null);
	}
	
	public ZipFile(File file) throws ZipException {
		this(file == null ? null : file.getPath());
	}

	public ZipFile(File file, String fileNameCharset) throws ZipException {
		this(file == null ? null : file.getPath(), fileNameCharset);
	}

	public ZipFile(String filePath, String fileNameCharset) throws ZipException {
		this.filePath = filePath;
		this.fileNameCharset = fileNameCharset;
		if (FileUtils.isExists(this.filePath)) {
			if (!FileUtils.canRead(this.filePath)) {
				throw new ZipException("Current file doesn't have read access!");
			}
			
			this.readHeaders();
		}
	}
	
	public static ZipFile createZipFile(String filePath, ZipOptions zipOptions, 
			String... addFiles) throws ZipException {
		return ZipFile.createZipFile(filePath, null, zipOptions, 
				Globals.DEFAULT_VALUE_BOOLEAN, Globals.DEFAULT_VALUE_LONG, addFiles);
	}
	
	public static ZipFile createZipFile(String filePath, String charsetName, ZipOptions zipOptions, 
			String... addFiles) throws ZipException {
		return ZipFile.createZipFile(filePath, charsetName, zipOptions, 
				Globals.DEFAULT_VALUE_BOOLEAN, Globals.DEFAULT_VALUE_LONG, addFiles);
	}
	
	public static ZipFile createZipFile(String filePath, ZipOptions zipOptions, 
			boolean splitArchive, long splitLength, String... addFiles) throws ZipException {
		return ZipFile.createZipFile(filePath, null, zipOptions, splitArchive, splitLength, addFiles);
	}

	public static ZipFile createZipFile(String filePath, String charsetName, ZipOptions zipOptions, 
			boolean splitArchive, long splitLength, String... addFiles) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(filePath)) {
			throw new ZipException("zip file path is empty");
		}

		if (FileUtils.isExists(filePath)) {
			throw new ZipException("zip file: " + filePath 
					+ " already exists. To add files to existing zip file use addFile method");
		}

		if (addFiles == null || addFiles.length == 0) {
			throw new ZipException("Zip file entity is null");
		}
		
		ZipFile zipFile = new ZipFile(filePath, charsetName);
		zipFile.createZipFile(Arrays.asList(addFiles), zipOptions, splitArchive, splitLength);
		return zipFile;
	}

	public static ZipFile createZipFileFromFolder(String filePath, ZipOptions zipOptions, 
			String folderPath) throws ZipException {
		return ZipFile.createZipFileFromFolder(filePath, null, zipOptions, 
				Globals.DEFAULT_VALUE_BOOLEAN, Globals.DEFAULT_VALUE_LONG, folderPath);
	}
	
	public static ZipFile createZipFileFromFolder(String filePath, String charsetName, ZipOptions zipOptions, 
			String folderPath) throws ZipException {
		return ZipFile.createZipFileFromFolder(filePath, charsetName, zipOptions, 
				Globals.DEFAULT_VALUE_BOOLEAN, Globals.DEFAULT_VALUE_LONG, folderPath);
	}
	
	public static ZipFile createZipFileFromFolder(String filePath, ZipOptions zipOptions, 
			boolean splitArchive, long splitLength, String folderPath) throws ZipException {
		return ZipFile.createZipFileFromFolder(filePath, null, zipOptions, splitArchive, splitLength, folderPath);
	}
	
	public static ZipFile createZipFileFromFolder(String filePath, String charsetName, ZipOptions zipOptions, 
			boolean splitArchive, long splitLength, String folderPath) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(filePath)) {
			throw new ZipException("zip file path is empty");
		}

		if (FileUtils.isExists(filePath)) {
			throw new ZipException("zip file: " + filePath 
					+ " already exists. To add files to existing zip file use addFile method");
		}

		if (!StringUtils.isNotNullAndNotEmpty(folderPath)) {
			throw new ZipException("Zip file entity is null");
		}
		
		ZipFile zipFile = new ZipFile(filePath, charsetName);
		zipFile.addFolder(folderPath, zipOptions, Globals.DEFAULT_VALUE_BOOLEAN);
		if (zipOptions.getPassword() != null) {
			zipFile.setPassword(zipOptions.getPassword());
		}
		return zipFile;
	}

	public static String getRelativeFileName(String file, String rootFolderInZip, String rootFolderPath) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(file)) {
			throw new ZipException("input file path/name is empty, cannot calculate relative file name");
		}
		
		String fileName = null;
		
		if (StringUtils.isNotNullAndNotEmpty(rootFolderPath)) {
			File rootFolderFile = new File(rootFolderPath);
			
			String rootFolderFileRef = rootFolderFile.getPath();
			
			if (!rootFolderFileRef.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				rootFolderFileRef += Globals.DEFAULT_PAGE_SEPARATOR;
			}
			
			String tmpFileName = file.substring(rootFolderFileRef.length());
			if (tmpFileName.startsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				tmpFileName = tmpFileName.substring(1);
			}
			
			File tmpFile = new File(file);
			
			if (tmpFile.isDirectory()) {
				tmpFileName = StringUtils.replace(tmpFileName, Globals.DEFAULT_PAGE_SEPARATOR, 
						ZipConstants.ZIP_FILE_SEPARATOR);
				if (!tmpFileName.endsWith(ZipConstants.ZIP_FILE_SEPARATOR)) {
					tmpFileName += ZipConstants.ZIP_FILE_SEPARATOR;
				}
			} else {
				String bkFileName = tmpFileName.substring(0, tmpFileName.lastIndexOf(tmpFile.getName()));
				bkFileName = StringUtils.replace(bkFileName, Globals.DEFAULT_PAGE_SEPARATOR, 
						ZipConstants.ZIP_FILE_SEPARATOR);
				tmpFileName = bkFileName + tmpFile.getName();
			}
			
			fileName = tmpFileName;
		} else {
			File relFile = new File(file);
			if (relFile.isDirectory()) {
				fileName = relFile.getName() + ZipConstants.ZIP_FILE_SEPARATOR;
			} else {
				fileName = getFileNameFromFilePath(relFile);
			}
		}
		
		if (!StringUtils.isNotNullAndNotEmpty(rootFolderInZip)) {
			fileName = rootFolderInZip + fileName;
		}
		
		if (!StringUtils.isNotNullAndNotEmpty(fileName)) {
			throw new ZipException("Error determining file name");
		}
		
		return fileName;
	}

	public List<String> entryList() {
		List<String> entryList = new ArrayList<String>();
		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			entryList.add(generalFileHeader.getEntryPath());
		}
		return entryList;
	}
	
	public boolean isEntryExists(String entryPath) {
		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			if (generalFileHeader.getEntryPath().equals(entryPath)) {
				return true;
			}
		}
		return Globals.DEFAULT_VALUE_BOOLEAN;
	}
	
	public byte[] readEntry(String entryPath) throws ZipException {
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException("This is a split archive. Zip file format does not allow updating split/spanned files");
		}

		return this.readEntry(this.retrieveGeneralFileHeader(entryPath));
	}
	
	public void addFile(File file) throws ZipException {
		this.addFile(file, ZipOptions.newOptions());
	}
	
	public void addFile(File file, ZipOptions zipOptions) throws ZipException {
		this.addFiles(Arrays.asList(file.getAbsolutePath()), zipOptions);
	}
	
	public void addFiles(List<String> fileList) throws ZipException {
		this.addFiles(fileList, ZipOptions.newOptions());
	}
	
	public void addFiles(List<String> fileList, ZipOptions zipOptions) throws ZipException {
		if (fileList == null || fileList.isEmpty()) {
			throw new ZipException("Input file array list is null!");
		}

		if (zipOptions == null) {
			throw new ZipException("Zip options is null!");
		}
		
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException("This is a split archive. Zip file format does not allow updating split/spanned files");
		}

		this.addFilesToZip(fileList, zipOptions);
	}
	
	public void addStream(InputStream inputStream) throws ZipException {
		this.addStream(inputStream, ZipOptions.newOptions());
	}
	
	public void addStream(InputStream inputStream, ZipOptions zipOptions) throws ZipException {
		if (inputStream == null) {
			throw new ZipException("Input stream is null! ");
		}
		
		if (zipOptions == null) {
			throw new ZipException("Zip options is null!");
		}
		
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException("This is a split archive. Zip file format does not allow updating split/spanned files");
		}
		
		this.addStreamToZip(inputStream, zipOptions);
	}

	public void addFolder(String folderPath) throws ZipException {
		this.addFolder(folderPath, ZipOptions.newOptions(), true);
	}
	
	public void addFolder(String folderPath, ZipOptions zipOptions) throws ZipException {
		this.addFolder(folderPath, zipOptions, true);
	}
	
	public void extractAll(String destPath) throws ZipException {
		this.extractAll(destPath, Globals.DEFAULT_VALUE_BOOLEAN);
	}
	
	public void extractAll(String destPath, boolean ignoreFileAttr) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(destPath)) {
			throw new ZipException("Destination path is null!");
		}

		if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null) {
			throw new ZipException("Invalid central directory in zip entity");
		}
		
		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			this.extractFile(generalFileHeader, destPath, ignoreFileAttr);
		}
	}
	
	public void extractFile(String entryPath, String destPath) throws ZipException {
		this.extractFile(entryPath, destPath, Globals.DEFAULT_VALUE_BOOLEAN);
	}
	
	public void extractFile(String entryPath, String destPath, boolean ignoreFileAttr) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(entryPath)) {
			throw new ZipException("extract file name is null!");
		}
		
		if (!StringUtils.isNotNullAndNotEmpty(destPath)) {
			throw new ZipException("Destination path is null!");
		}

		this.extractFile(this.retrieveGeneralFileHeader(entryPath), destPath, ignoreFileAttr);
	}
	
	public void removeFolder(String folderPath) throws ZipException {
		if (this.isDirectory(folderPath)) {
			this.removeFilesIfExists(this.listFolderGeneralFileHeaders(folderPath));
		}
		throw new ZipException("Entry path: " + folderPath + " is not directory entry!");
	}
	
	public void removeExistsEntry(String entryPath) throws ZipException {
		this.removeExistsEntries(new String[]{entryPath});
	}
	
	public void removeExistsEntries(String... existsEntries) throws ZipException {
		if (existsEntries == null) {
			throw new ZipException("Input entry path is null!");
		}
		
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException("This is a split archive. Zip file format does not allow updating split/spanned files");
		}
		
		this.removeFilesIfExists(Arrays.asList(existsEntries));
		
		if (this.isNoEntry()) {
			FileUtils.removeFile(this.filePath);
		}
	}
	
	public void setPassword(String password) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(password)) {
			throw new ZipException("Password is null");
		}
		this.setPassword(password.toCharArray());
	}
	
	public void setPassword(char[] password) throws ZipException {
		if (this.centralDirectory == null 
				|| this.centralDirectory.getFileHeaders() == null) {
			throw new ZipException("Invalid zip file");
		}
		
		for (int i = 0 ; i < this.centralDirectory.getFileHeaders().size() ; i++) {
			if (this.centralDirectory.getFileHeaders().get(i) != null
					&& this.centralDirectory.getFileHeaders().get(i).isEncrypted()) {
				this.centralDirectory.getFileHeaders().get(i).setPassword(password);
			}
		}
	}
	
	public void setComment(String comment) throws ZipException {
		if (comment == null) {
			throw new ZipException("input comment is null, cannot update zip file");
		}
		
		if (!FileUtils.isExists(this.filePath)) {
			throw new ZipException("zip file does not exist, cannot set comment for zip file");
		}
		
		if (this.endCentralDirectoryRecord == null) {
			throw new ZipException("end of central directory is null, cannot set comment");
		}
		
		String encodedComment = null;
		byte[] commentBytes = null;
		int commentLength = Globals.DEFAULT_VALUE_INT;
		
		if (StringUtils.supportedCharset(ZipConstants.CHARSET_COMMENTS_DEFAULT)) {
			try {
				encodedComment = new String(comment.getBytes(ZipConstants.CHARSET_COMMENTS_DEFAULT), ZipConstants.CHARSET_COMMENTS_DEFAULT);
				commentBytes = encodedComment.getBytes(ZipConstants.CHARSET_COMMENTS_DEFAULT);
			} catch (UnsupportedEncodingException e) {
				encodedComment = comment;
			}
		} else {
			encodedComment = comment;
		}
		
		if (commentBytes == null) {
			commentBytes = encodedComment.getBytes();
		}
		
		commentLength = commentBytes.length;

		if (commentLength > ZipConstants.MAX_ALLOWED_ZIP_COMMENT_LENGTH) {
			throw new ZipException("comment length exceeds maximum length");
		}
		
		this.endCentralDirectoryRecord.setCommentBytes(commentBytes);
		this.endCentralDirectoryRecord.setCommentLength(commentLength);
		
		SplitOutputStream outputStream = null;
		
		try {
			outputStream = new SplitOutputStream(this.filePath);
			
			if (this.zip64Format) {
				outputStream.seek(this.zip64EndCentralDirectoryRecord.getOffsetStartCenDirWRTStartDiskNo());
			} else {
				outputStream.seek(this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory());
			}
			
			this.finalizeZipFileWithoutValidations(outputStream);
		} catch (FileNotFoundException e) {
			throw new ZipException(e);
		} catch (IOException e) {
			throw new ZipException(e);
		} finally {
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
					//	Ignore
				}
			}
		}
	}
	
	public String getComment() throws ZipException {
		return this.getComment(null);
	}
	
	public String getComment(String charset) throws ZipException {
		if (charset == null) {
			if (StringUtils.supportedCharset(ZipConstants.CHARSET_COMMENTS_DEFAULT)) {
				charset = ZipConstants.CHARSET_COMMENTS_DEFAULT;
			} else {
				charset = Globals.DEFAULT_SYSTEM_CHARSET;
			}
		}
		
		if (!FileUtils.isExists(this.filePath)) {
			throw new ZipException("Zip file does not exists!");
		}
		
		if (this.endCentralDirectoryRecord == null) {
			throw new ZipException("end of central directory is null, cannot set comment");
		}
		
		if (this.endCentralDirectoryRecord.getCommentBytes() == null 
				|| this.endCentralDirectoryRecord.getCommentBytes().length == 0) {
			return null;
		}
		
		try {
			return new String(this.endCentralDirectoryRecord.getCommentBytes(), charset);
		} catch (UnsupportedEncodingException e) {
			throw new ZipException(e);
		}
	}

	public void mergeSplitFile(String outputPath) throws ZipException {
		if (!this.splitArchive) {
			throw new ZipException("archive not a split zip file");
		}
		
		if (this.endCentralDirectoryRecord.getIndexOfThisDisk() <= 0) {
			throw new ZipException("corrupt zip entity, archive not a split zip file");
		}
		
		OutputStream outputStream = null;
		NervousyncRandomAccessFile input = null;
		List<Long> sizeList = new ArrayList<Long>();
		long totalWriteBytes = 0L;
		boolean removeSplitSig = Globals.DEFAULT_VALUE_BOOLEAN;
		
		try {
			outputStream = this.openMergeOutputStream(outputPath);
			
			for (int i = 0 ; i <= this.endCentralDirectoryRecord.getIndexOfThisDisk() ; i++) {
				input = this.openSplitFile(i);
				int start = 0;
				
				if (i == 0) {
					if (this.centralDirectory != null 
							&& this.centralDirectory.getFileHeaders() != null 
							&& this.centralDirectory.getFileHeaders().size() > 0) {
						byte[] buffer = new byte[4];
						
						input.seek(0L);
						input.read(buffer);
						
						if (RawOperator.readIntFromLittleEndian(buffer, 0) == ZipConstants.SPLITSIG) {
							start = 4;
							removeSplitSig = true;
						}
					}
				}

				long end = input.length();
				
				if (i == this.endCentralDirectoryRecord.getIndexOfThisDisk()) {
					end = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();
				}
				
				this.copyFile(input, outputStream, start, end);
				totalWriteBytes += (end - start);
				
				sizeList.add(end);
			}
			
			ZipFile newFile = (ZipFile)this.clone();
			newFile.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(totalWriteBytes);
			
			newFile.updateSplitZipEntity(sizeList, removeSplitSig);
			newFile.finalizeZipFileWithoutValidations(outputStream);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		} finally {
			try {
				if (input != null) {
					input.close();
				}
			} catch (IOException e) {
			}
		}
	}

	public void finalizeZipFile(OutputStream outputStream) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("input parameters is null, cannot finalize zip file");
		}
		
		this.processHeaderData(outputStream);
		
		long offsetCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();

		List<String> headerBytesList = new ArrayList<String>();

		int sizeOfCentralDirectory = this.writeCentralDirectory(outputStream, headerBytesList);

		if (this.zip64Format) {
			if (this.zip64EndCentralDirectoryRecord == null) {
				this.zip64EndCentralDirectoryRecord = new Zip64EndCentralDirectoryRecord();
			}

			if (this.zip64EndCentralDirectoryLocator == null) {
				this.zip64EndCentralDirectoryLocator = new Zip64EndCentralDirectoryLocator();
			}

			this.zip64EndCentralDirectoryLocator
					.setOffsetZip64EndOfCentralDirectoryRecord(offsetCentralDirectory + sizeOfCentralDirectory);

			if (outputStream instanceof SplitOutputStream) {
				this.zip64EndCentralDirectoryLocator.setIndexOfZip64EndOfCentralDirectoryRecord(
						((SplitOutputStream) outputStream).getCurrentSplitFileIndex());
				this.zip64EndCentralDirectoryLocator
						.setTotalNumberOfDiscs(((SplitOutputStream) outputStream).getCurrentSplitFileIndex() + 1);
			} else {
				this.zip64EndCentralDirectoryLocator.setIndexOfZip64EndOfCentralDirectoryRecord(0);
				this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(1);
			}

			this.writeZip64EndOfCentralDirectoryRecord(outputStream, sizeOfCentralDirectory,
					offsetCentralDirectory, headerBytesList);
			this.writeZip64EndOfCentralDirectoryLocator(outputStream, headerBytesList);
		}

		this.writeEndOfCentralDirectoryRecord(outputStream, sizeOfCentralDirectory, offsetCentralDirectory, headerBytesList);
		this.writeZipHeaderBytes(outputStream, HeaderOperator.convertByteArrayListToByteArray(headerBytesList));
	}

	public NervousyncRandomAccessFile startNextSplitFile() throws IOException, ZipException {
		String currentSplitFile = null;
		
		if (this.currentSplitIndex == this.endCentralDirectoryRecord.getIndexOfThisDisk()) {
			currentSplitFile = this.filePath;
		} else {
			currentSplitFile = this.filePath.substring(0, this.filePath.lastIndexOf('.'));
			if (this.currentSplitIndex < 9) {
				currentSplitFile += (".zip.0" + (this.currentSplitIndex + 1));
			} else {
				currentSplitFile += (".zip." + (this.currentSplitIndex + 1));
			}
		}
		
		this.currentSplitIndex++;
		
		if (currentSplitFile == null || !FileUtils.isExists(currentSplitFile)) {
			throw new ZipException("Next split file not found!");
		}

		return new NervousyncRandomAccessFile(currentSplitFile, Globals.WRITE_MODE);
	}
	
	/**
	 * @return the centralDirectory
	 */
	public CentralDirectory getCentralDirectory() {
		return centralDirectory;
	}

	/**
	 * @param centralDirectory the centralDirectory to set
	 */
	public void setCentralDirectory(CentralDirectory centralDirectory) {
		this.centralDirectory = centralDirectory;
	}

	/**
	 * @return the fileNameCharset
	 */
	public String getFileNameCharset() {
		return fileNameCharset;
	}

	/**
	 * @return the localFileHeaderList
	 */
	public List<LocalFileHeader> getLocalFileHeaderList() {
		return localFileHeaderList;
	}

	/**
	 * @param localFileHeaderList the localFileHeaderList to set
	 */
	public void setLocalFileHeaderList(List<LocalFileHeader> localFileHeaderList) {
		this.localFileHeaderList = localFileHeaderList;
	}

	/**
	 * @return the archiveExtraDataRecord
	 */
	public ArchiveExtraDataRecord getArchiveExtraDataRecord() {
		return archiveExtraDataRecord;
	}

	/**
	 * @param archiveExtraDataRecord the archiveExtraDataRecord to set
	 */
	public void setArchiveExtraDataRecord(ArchiveExtraDataRecord archiveExtraDataRecord) {
		this.archiveExtraDataRecord = archiveExtraDataRecord;
	}

	/**
	 * @return the endCentralDirectoryRecord
	 */
	public EndCentralDirectoryRecord getEndCentralDirectoryRecord() {
		return endCentralDirectoryRecord;
	}

	/**
	 * @param endCentralDirectoryRecord the endCentralDirectoryRecord to set
	 */
	public void setEndCentralDirectoryRecord(EndCentralDirectoryRecord endCentralDirectoryRecord) {
		this.endCentralDirectoryRecord = endCentralDirectoryRecord;
	}

	public boolean isSplitArchive() throws ZipException {
		return this.splitArchive;
	}

	/**
	 * @param splitArchive the splitArchive to set
	 */
	public void setSplitArchive(boolean splitArchive) {
		this.splitArchive = splitArchive;
	}

	/**
	 * @param splitLength the splitLength to set
	 */
	public void setSplitLength(long splitLength) {
		this.splitLength = splitLength;
	}

	private void createZipFile(List<String> fileList, ZipOptions zipOptions, 
			boolean splitArchive, long splitLength) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(this.filePath)) {
			throw new ZipException("zip file path is empty");
		}
		
		if (FileUtils.isExists(this.filePath)) {
			throw new ZipException("zip file: " + this.filePath
					+ " already exists. To add files to existing zip file use addFile method");
		}
		
		if (fileList == null || fileList.size() == 0) {
			throw new ZipException("Zip file entity is null");
		}
		
		this.splitArchive = splitArchive;
		this.splitLength = splitLength;
		this.addFiles(fileList, zipOptions);
	}
	
	private void addFolder(String folderPath, ZipOptions zipOptions, boolean checkSplitArchive) throws ZipException {
		if (folderPath == null) {
			throw new ZipException("Input folder path is null! ");
		}
		
		if (zipOptions == null) {
			throw new ZipException("Zip options is null!");
		}
		
		if (checkSplitArchive && this.splitArchive) {
			throw new ZipException("This is a split archive. Zip file format does not allow updating split/spanned files");
		}
		
		this.addFolderToZip(folderPath, zipOptions);
	}

	private static String getFileNameFromFilePath(File file) throws ZipException {
		if (file == null) {
			throw new ZipException("input file is null, cannot get file name");
		}
		
		if (file.isDirectory()) {
			return null;
		}
		
		return file.getName();
	}
	private boolean isNoEntry() {
		return this.centralDirectory.getFileHeaders().size() == 0;
	}
	
	private boolean isDirectory(String entryPath) {
		GeneralFileHeader generalFileHeader = this.retrieveGeneralFileHeader(entryPath);
		if (generalFileHeader != null) {
			return generalFileHeader.isDirectory();
		}
		return Globals.DEFAULT_VALUE_BOOLEAN;
	}
	
	private List<String> listFolderGeneralFileHeaders(String folderPath) {
		if (StringUtils.isNotNullAndNotEmpty(folderPath)) {
			if (this.centralDirectory == null) {
				throw new ZipException("central directory is null, cannot determine file header with exact match for entry path: " + folderPath);
			}
			return this.centralDirectory.listFolderGeneralFileHeaders(folderPath);
		}
		throw new ZipException("file name is null, cannot determine file header for entry path: " + folderPath);
	}

	private GeneralFileHeader retrieveGeneralFileHeader(String entryPath) throws ZipException {
		if (StringUtils.isNotNullAndNotEmpty(entryPath)) {
			if (this.centralDirectory == null) {
				throw new ZipException("central directory is null, cannot determine file header with exact match for entry path: " + entryPath);
			}
			return this.centralDirectory.retrieveGeneralFileHeader(entryPath);
		}
		throw new ZipException("file name is null, cannot determine file header for entry path: " + entryPath);
	}

	private void removeFilesIfExists(List<String> entryList) throws ZipException {
		if (this.centralDirectory == null 
				|| this.centralDirectory.getFileHeaders() == null                           
				|| this.centralDirectory.getFileHeaders().size() == 0) {
			//	This file is new zip file
			return;
		}

		for (String entryPath : entryList) {
			GeneralFileHeader generalFileHeader = this.retrieveGeneralFileHeader(entryPath);
			if (generalFileHeader != null) {
				this.removeExistsFile(generalFileHeader);
			}
		}
	}
	
	private void addStreamToZip(InputStream inputStream, ZipOptions zipOptions) throws ZipException {
		if (zipOptions == null) {
			throw new ZipException("Zip options is null!");
		}
		
		if (inputStream == null) {
			throw new ZipException("No data to added");
		}
		
		ZipOutputStream outputStream = null;
		
		try {
			this.checkOptions(zipOptions);
			
			SplitOutputStream splitOutputStream = new SplitOutputStream(this.filePath, this.splitLength);
			outputStream = new ZipOutputStream(splitOutputStream, this);
			
			if (FileUtils.isExists(this.filePath)) {
				if (this.endCentralDirectoryRecord == null) {
					throw new ZipException("invalid end of central directory record");
				}
				splitOutputStream.seek(this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory());
			}
			
			byte[] readBuffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
			int readLength = Globals.DEFAULT_VALUE_INT;
			
			outputStream.putNextEntry(null, zipOptions);
			
			if (!zipOptions.getFileNameInZip().endsWith(ZipConstants.ZIP_FILE_SEPARATOR) 
					&& !zipOptions.getFileNameInZip().endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				while ((readLength = inputStream.read(readBuffer)) != Globals.DEFAULT_VALUE_INT) {
					outputStream.write(readBuffer, 0, readLength);
				}
			}
			
			outputStream.closeEntry();
			outputStream.finish();
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		} finally {
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
					//	Ignore
				}
			}
		}
	}
	
	private void addFolderToZip(String folderPath, ZipOptions zipOptions) throws ZipException {
		if (folderPath == null || !FileUtils.isExists(folderPath)) {
			throw new ZipException("No folder to added!");
		}
		
		if (!FileUtils.isDirectory(folderPath)) {
			throw new ZipException("Given path is not folder path");
		}
		
		if (!FileUtils.canRead(folderPath)) {
			throw new ZipException("Cannot read folder: " + folderPath);
		}

		if (zipOptions == null) {
			throw new ZipException("Zip options is null!");
		}
		
		String rootFolderPath = null;
		
		if (zipOptions.isIncludeRootFolder()) {
			try {
				File file = FileUtils.getFile(folderPath);
				if (file.getAbsoluteFile() != null) {
					rootFolderPath = file.getAbsoluteFile().getParentFile() != null ? file.getAbsoluteFile().getParentFile().getAbsolutePath() : "";
				} else {
					rootFolderPath = file.getAbsolutePath();
				}
			} catch (FileNotFoundException e) {
				throw new ZipException("Cannot read folder: " + folderPath);
			}
		} else {
			rootFolderPath = folderPath;
		}
		
		zipOptions.setDefaultFolderPath(rootFolderPath);
		
		List<String> fileList = new ArrayList<String>();
		try {
			File folder = FileUtils.getFile(folderPath);
			if (zipOptions.isIncludeRootFolder()) {
				fileList.add(folderPath);
			}
			fileList.addAll(FileUtils.listFiles(folder, zipOptions.isReadHiddenFiles(), zipOptions.isIncludeRootFolder()));
		} catch (Exception e) {
			throw new ZipException(e);
		}
		
		this.addFiles(fileList, zipOptions);
	}
	
	private void finalizeZipFileWithoutValidations(OutputStream outputStream)
			throws ZipException {
		if (outputStream == null) {
			throw new ZipException("Output stream parameter is null, cannot finalize zip file");
		}

		try {
			List<String> headerBytesList = new ArrayList<String>();

			long offsetCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();

			int sizeOfCentralDirectory = this.writeCentralDirectory(outputStream, headerBytesList);

			if (this.zip64Format) {
				if (this.zip64EndCentralDirectoryRecord == null) {
					this.zip64EndCentralDirectoryRecord = new Zip64EndCentralDirectoryRecord();
				}

				if (this.zip64EndCentralDirectoryLocator == null) {
					this.zip64EndCentralDirectoryLocator = new Zip64EndCentralDirectoryLocator();
				}

				this.zip64EndCentralDirectoryLocator
						.setOffsetZip64EndOfCentralDirectoryRecord(offsetCentralDirectory + sizeOfCentralDirectory);

				this.writeZip64EndOfCentralDirectoryRecord(outputStream, sizeOfCentralDirectory,
						offsetCentralDirectory, headerBytesList);
				this.writeZip64EndOfCentralDirectoryLocator(outputStream, headerBytesList);
			}

			this.writeEndOfCentralDirectoryRecord(outputStream, sizeOfCentralDirectory, offsetCentralDirectory,
					headerBytesList);
			this.writeZipHeaderBytes(outputStream, HeaderOperator.convertByteArrayListToByteArray(headerBytesList));
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException(e);
			}
		}
	}

	private void extractFile(GeneralFileHeader generalFileHeader, String destPath, 
			boolean ignoreFileAttr) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException("General file header is null!");
		}

		try {
			if (!destPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				destPath += Globals.DEFAULT_PAGE_SEPARATOR;
			}
			
			if (generalFileHeader.isDirectory()) {
				if (!FileUtils.makeDir(destPath + generalFileHeader.getEntryPath())) {
					throw new ZipException("Create output folder error!");
				}
			} else {
				if (!FileUtils.isExists(destPath)) {
					FileUtils.makeDir(destPath);
				}
				
				if (!FileUtils.isDirectory(destPath)) {
					throw new ZipException("Output folder is not exists");
				}

				this.extractFileToPath(generalFileHeader, destPath, ignoreFileAttr);
			}
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		}
	}
	
	private void addFilesToZip(List<String> fileList, ZipOptions zipOptions) throws ZipException {
		if (fileList == null || fileList.isEmpty()) {
			throw new ZipException("No file to added");
		}
		
		if (!FileUtils.canWrite(this.filePath)) {
			throw new ZipException("Zip file cannot writeable");
		}
		
		if (this.endCentralDirectoryRecord == null) {
			this.endCentralDirectoryRecord = new EndCentralDirectoryRecord();
			this.endCentralDirectoryRecord.setSignature(ZipConstants.ENDSIG);
			this.endCentralDirectoryRecord.setIndexOfThisDisk(0);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectory(0);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectoryOnThisDisk(0);
			this.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(0);
		}
		
		ZipOutputStream outputStream = null;
		InputStream inputStream = null;
		
		try {
			this.checkOptions(zipOptions);
			List<String> entryList = new ArrayList<String>();
			for (String filePath : fileList) {
				entryList.add(ZipFile.getRelativeFileName(filePath, 
						zipOptions.getRootFolderInZip(), zipOptions.getDefaultFolderPath()));
			}
			this.removeFilesIfExists(entryList);
			
			SplitOutputStream splitOutputStream = new SplitOutputStream(this.filePath, this.splitLength);
			outputStream = new ZipOutputStream(splitOutputStream, this);
			
			if (FileUtils.isExists(this.filePath)) {
				if (this.endCentralDirectoryRecord == null) {
					throw new ZipException("invalid end of central directory record");
				}
				splitOutputStream.seek(this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory());
			}
			
			byte[] readBuffer = new byte[ZipConstants.BUFFER_SIZE];
			int readLength = Globals.DEFAULT_VALUE_INT;
			
			for (String filePath : fileList) {
				ZipOptions fileOptions = (ZipOptions)zipOptions.clone();
				
				if (!FileUtils.isDirectory(filePath)) {
					if (fileOptions.isEncryptFiles() 
							&& fileOptions.getEncryptionMethod() == ZipConstants.ENC_METHOD_STANDARD) {
						fileOptions.setSourceFileCRC(FileUtils.calcFileCRC(filePath));
					}
					
					if (FileUtils.getFileSize(filePath) == 0L) {
						fileOptions.setCompressionMethod(ZipConstants.COMP_STORE);
					}
				}
				
				outputStream.putNextEntry(FileUtils.getFile(filePath), fileOptions);
				if (FileUtils.isDirectory(filePath)) {
					outputStream.closeEntry();
					continue;
				}
				
				inputStream = FileUtils.loadFile(filePath);
				if (inputStream == null) {
					throw new ZipException("Load file error!");
				}
				
				while ((readLength = inputStream.read(readBuffer)) != Globals.DEFAULT_VALUE_INT) {
					outputStream.write(readBuffer, 0, readLength);
				}
				
				outputStream.closeEntry();
				inputStream.close();
			}
			
			outputStream.finish();
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		} finally {
			if (inputStream != null) {
				try {
					inputStream.close();
				} catch (IOException e) {
				}
			}
			if (outputStream != null) {
				try {
					outputStream.close();
				} catch (IOException e) {
				}
			}
		}
	}
	
	private void checkOptions(ZipOptions zipOptions) throws ZipException {
		if (zipOptions == null) {
			throw new ZipException("Zip options is null!");
		}
		
		if (zipOptions.getCompressionMethod() != ZipConstants.COMP_STORE 
				&& zipOptions.getCompressionMethod() != ZipConstants.COMP_DEFLATE) {
			throw new ZipException("Unsupported compression type!");
		}

		if (zipOptions.getCompressionMethod() == ZipConstants.COMP_DEFLATE 
				&& (zipOptions.getCompressionLevel() < 0 && zipOptions.getCompressionLevel() > 9)) {
			throw new ZipException("invalid compression level. compression level dor deflate should be in the range of 0-9");
		}
		
		if (zipOptions.isEncryptFiles()) {
			if (zipOptions.getEncryptionMethod() != ZipConstants.ENC_METHOD_STANDARD 
					&& zipOptions.getEncryptionMethod() != ZipConstants.ENC_METHOD_STRONG
					&& zipOptions.getEncryptionMethod() != ZipConstants.ENC_METHOD_AES) {
				throw new ZipException("Unsupported encryption method!");
			}
			
			if (zipOptions.getPassword() == null || zipOptions.getPassword().length == 0) {
				throw new ZipException("Need password for encrypt!");
			}
		}
	}

	private void removeExistsFile(GeneralFileHeader generalFileHeader) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException("input parameters is null in maintain zip file, cannot remove file from archive");
		}

		if (this.splitArchive) {
			throw new ZipException("Unsupported updating split/spanned zip file! ");
		}
		
		SplitOutputStream outputStream = null;
		NervousyncRandomAccessFile input = null;
		boolean success = Globals.DEFAULT_VALUE_BOOLEAN;
		String tempFileName = this.filePath + System.currentTimeMillis() % 1000L;
		
		try {
			int indexOfHeader = this.retrieveIndexOfGeneralFileHeader(generalFileHeader);
			if (indexOfHeader < 0) {
				throw new ZipException("File header not found in zip entity, cannot remove file!");
			}
			
			while (FileUtils.isExists(tempFileName)) {
				tempFileName = this.filePath + System.currentTimeMillis() % 1000L;
			}
			
			try {
				outputStream = new SplitOutputStream(tempFileName);
			} catch (FileNotFoundException e) {
				throw new ZipException(e);
			}
			
			input = this.createFileHandler(Globals.READ_MODE);
			
			LocalFileHeader localFileHeader = 
					this.readLocalFileHeader(input, generalFileHeader);
			
			if (localFileHeader == null) {
				throw new ZipException("invalid local file header, cannot remove file from archive");
			}
			
			if (!localFileHeader.verifyPassword(input)) {
				throw new ZipException("Wrong password or Unsupported encryption method!");
			}
			
			long offsetLocalFileHeader = generalFileHeader.getOffsetLocalHeader();
			if (generalFileHeader.getZip64ExtendInfo() != null 
					&& generalFileHeader.getZip64ExtendInfo().getOffsetLocalHeader() != Globals.DEFAULT_VALUE_LONG) {
				offsetLocalFileHeader = generalFileHeader.getZip64ExtendInfo().getOffsetLocalHeader();
			}
			
			long offsetStartCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();
			if (this.zip64Format && this.zip64EndCentralDirectoryRecord != null) {
				offsetStartCentralDirectory = this.zip64EndCentralDirectoryRecord.getOffsetStartCenDirWRTStartDiskNo();
			}
			
			long offsetEndOfCompressedFile = Globals.DEFAULT_VALUE_LONG;
			
			List<GeneralFileHeader> fileHeaders = this.centralDirectory.getFileHeaders();
			if (indexOfHeader == fileHeaders.size() - 1) {
				offsetEndOfCompressedFile = offsetStartCentralDirectory - 1;
			} else {
				GeneralFileHeader nextFileHeader = fileHeaders.get(indexOfHeader + 1);
				if (nextFileHeader != null) {
					offsetEndOfCompressedFile = nextFileHeader.getOffsetLocalHeader() - 1;
					if (nextFileHeader.getZip64ExtendInfo() != null 
							&& nextFileHeader.getZip64ExtendInfo().getOffsetLocalHeader() != Globals.DEFAULT_VALUE_LONG) {
						offsetEndOfCompressedFile = nextFileHeader.getZip64ExtendInfo().getOffsetLocalHeader() - 1;
					}
				}
			}
			
			if (offsetLocalFileHeader < 0L || offsetEndOfCompressedFile < 0L) {
				throw new ZipException("invalid offset for start and end of local file, cannot remove file");
			}
			
			if (indexOfHeader == 0) {
				if (this.centralDirectory.getFileHeaders().size() > 1) {
					this.copyFile(input, outputStream, offsetEndOfCompressedFile + 1L, offsetStartCentralDirectory);
				}
			} else if (indexOfHeader == (fileHeaders.size() - 1)) {
				this.copyFile(input, outputStream, 0, offsetLocalFileHeader);
			} else {
				this.copyFile(input, outputStream, 0, offsetLocalFileHeader);
				this.copyFile(input, outputStream, offsetEndOfCompressedFile + 1L, offsetStartCentralDirectory);
			}
			
			this.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(outputStream.getFilePointer());
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectory(this.endCentralDirectoryRecord.getTotalOfEntriesInCentralDirectory() - 1);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectoryOnThisDisk(this.endCentralDirectoryRecord.getTotalOfEntriesInCentralDirectoryOnThisDisk() - 1);
			
			this.centralDirectory.getFileHeaders().remove(indexOfHeader);
			
			for (int i = indexOfHeader ; i < this.centralDirectory.getFileHeaders().size() ; i++) {
				long offsetLocalHeader = this.centralDirectory.getFileHeaders().get(i).getOffsetLocalHeader();
				if (this.centralDirectory.getFileHeaders().get(i).getZip64ExtendInfo() != null
						&& this.centralDirectory.getFileHeaders().get(i).getZip64ExtendInfo().getOffsetLocalHeader() != Globals.DEFAULT_VALUE_LONG) {
					offsetLocalHeader = this.centralDirectory.getFileHeaders().get(i).getZip64ExtendInfo().getOffsetLocalHeader();
				}
				
				this.centralDirectory.getFileHeaders().get(i).setOffsetLocalHeader(offsetLocalHeader - (offsetEndOfCompressedFile - offsetLocalFileHeader) - 1);
			}
			
			this.finalizeZipFile(outputStream);
			success = true;
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		} finally {
			try {
				if (input != null) {
					input.close();
				}
			} catch (IOException e) {
				throw new ZipException(e);
			}

			try {
				if (outputStream != null) {
					outputStream.close();
				}
			} catch (IOException e) {
				throw new ZipException(e);
			}
			
			if (success) {
				FileUtils.copyFile(tempFileName, this.filePath);
			}
			
			if (FileUtils.isExists(tempFileName)) {
				FileUtils.removeFile(tempFileName);
			}
		}
	}
	
	private int retrieveIndexOfGeneralFileHeader(GeneralFileHeader generalFileHeader) {
		if (generalFileHeader == null) {
			throw new ZipException("File header is null!");
		}

		if (this.centralDirectory == null) {
			throw new ZipException("central directory is null, cannot determine index of file header");
		}
		
		return this.centralDirectory.retrieveIndexOfGeneralFileHeader(generalFileHeader);
	}
	
	private NervousyncRandomAccessFile createFileHandler(String mode) throws FileNotFoundException {
		if (StringUtils.isNotNullAndNotEmpty(this.filePath)) {
			return new NervousyncRandomAccessFile(this.filePath, mode);
		}
		
		throw new ZipException("cannot create file handler to remove file");
	}
	
	private void copyFile(NervousyncRandomAccessFile input, 
			OutputStream outputStream, long start, long end) throws ZipException {
		if (input == null) {
			throw new ZipException("Input stream is null!");
		}
		
		if (outputStream == null) {
			throw new ZipException("Output stream is null!");
		}
		
		if (start < 0 || end < 0 || start > end) {
			throw new IndexOutOfBoundsException();
		}
		
		if (start == end) {
			return;
		}
		
		try {
			input.seek(start);
			
			int bufferSize = Globals.DEFAULT_BUFFER_SIZE;
			if ((end - start) < Globals.DEFAULT_BUFFER_SIZE) {
				bufferSize = (int)(end - start);
			}
			
			int readLength = Globals.DEFAULT_VALUE_INT;
			byte[] readBuffer = new byte[bufferSize];
			long totalRead = 0L;
			long limitRead = end - start;
			
			do {
				readLength = input.read(readBuffer);
				
				outputStream.write(readBuffer, 0, readLength);
				
				totalRead += readLength;
				if (totalRead == limitRead) {
					break;
				}
				
				if (totalRead + readBuffer.length > limitRead) {
					readBuffer = new byte[(int)(limitRead - totalRead)];
				}
			} while (readLength != Globals.DEFAULT_VALUE_INT);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		}
	}
	
	private void extractFileToPath(GeneralFileHeader generalFileHeader, 
			String destPath, boolean ignoreFileAttr) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException("General file header is null!");
		}
		
		ZipInputStream inputStream = null;
		OutputStream outputStream = null;
		
		try {
			inputStream = this.openInputStream(generalFileHeader);
			outputStream = this.openOutputStream(destPath, generalFileHeader.getEntryPath());
			
			byte[] buffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
			int readLength = Globals.DEFAULT_VALUE_INT; ;
			
			while ((readLength = inputStream.read(buffer)) != Globals.DEFAULT_VALUE_INT) {
				outputStream.write(buffer, 0, readLength);
			}
			
			if (generalFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
				if (this.decryptor != null && (this.decryptor instanceof AESDecryptor)) {
					byte[] tempMacBytes = ((AESDecryptor)this.decryptor).calculateAuthenticationBytes();
					byte[] storedMac = ((AESDecryptor)this.decryptor).getStoredMac();
					byte[] calculateMac = new byte[ZipConstants.AES_AUTH_LENGTH];
					
					if (calculateMac == null || storedMac == null) {
						throw new ZipException("CRC check failed!");
					}
					
					System.arraycopy(tempMacBytes, 0, calculateMac, 0, ZipConstants.AES_AUTH_LENGTH);
					
					if (!Arrays.equals(calculateMac, storedMac)) {
						throw new ZipException("CRC check failed!");
					}
				}
			} else {
				long calculatedCRC = inputStream.crcValue();
				if (calculatedCRC != generalFileHeader.getCrc32()) {
					throw new ZipException("CRC check failed!");
				}
			}
		} catch (IOException e) {
			throw new ZipException(e);
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
					inputStream = null;
				}
			} catch (IOException e) {
				throw new ZipException(e);
			} finally {
				if (outputStream != null) {
					try {
						outputStream.close();
						outputStream = null;
					} catch (IOException e) {
						
					}
				}
			}
		}
		
		try {
			String filePath = destPath + generalFileHeader.getEntryPath();
			if (generalFileHeader.getExternalFileAttr() != null && !ignoreFileAttr) {
				if (generalFileHeader.getExternalFileAttr()[0] == ZipConstants.FILE_MODE_READ_ONLY) {
					setFileReadOnly(FileUtils.getFile(filePath));
				}
				
				setFileLastModify(FileUtils.getFile(filePath), 
						DateTimeUtils.dosToJavaTme(generalFileHeader.getLastModFileTime()));
			}
		} catch (FileNotFoundException e) {
			throw new ZipException(e);
		}
	}

	private byte[] readEntry(GeneralFileHeader generalFileHeader) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException("General file header is null!");
		}
		
		ZipInputStream inputStream = null;
		OutputStream outputStream = null;

		try {
			byte[] buffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
			int readLength = Globals.DEFAULT_VALUE_INT;
			
			inputStream = this.openInputStream(generalFileHeader);
			outputStream = new ByteArrayOutputStream((int)generalFileHeader.getOriginalSize());
			
			while ((readLength = inputStream.read(buffer)) != Globals.DEFAULT_VALUE_INT) {
				outputStream.write(buffer, 0, readLength);
			}
			
			if (generalFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
				if (this.decryptor != null && (this.decryptor instanceof AESDecryptor)) {
					byte[] tempMacBytes = ((AESDecryptor)this.decryptor).calculateAuthenticationBytes();
					byte[] storedMac = ((AESDecryptor)this.decryptor).getStoredMac();
					byte[] calculateMac = new byte[ZipConstants.AES_AUTH_LENGTH];
					
					if (calculateMac == null || storedMac == null) {
						throw new ZipException("CRC check failed!");
					}
					
					System.arraycopy(tempMacBytes, 0, calculateMac, 0, ZipConstants.AES_AUTH_LENGTH);
					
					if (!Arrays.equals(calculateMac, storedMac)) {
						throw new ZipException("CRC check failed!");
					}
				}
			} else {
				long calculatedCRC = inputStream.crcValue();
				if (calculatedCRC != generalFileHeader.getCrc32()) {
					throw new ZipException("CRC check failed!");
				}
			}
			
			return ((ByteArrayOutputStream)outputStream).toByteArray();
		} catch (IOException e) {
			throw new ZipException(e);
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
					inputStream = null;
				}
			} catch (IOException e) {
				throw new ZipException(e);
			} finally {
				if (outputStream != null) {
					try {
						outputStream.close();
						outputStream = null;
					} catch (IOException e) {
						
					}
				}
			}
		}
	}
	
	private ZipInputStream openInputStream(GeneralFileHeader generalFileHeader) throws ZipException {
		NervousyncRandomAccessFile input = null;
		try {
			input = this.createFileHandler(Globals.READ_MODE);
			
			LocalFileHeader localFileHeader = 
					this.readLocalFileHeader(input, generalFileHeader);
			
			if (localFileHeader == null) {
				throw new ZipException("Error reading local header!");
			}
			
			if (localFileHeader.getCompressionMethod() != generalFileHeader.getCompressionMethod()) {
				throw new ZipException("local header does not matched with general header");
			}
			
			if (localFileHeader.isEncrypted()) {
				if (localFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
					byte[] salt = null;
					if (localFileHeader.getAesExtraDataRecord() != null) {
						int saltLength = Globals.DEFAULT_VALUE_INT;
						
						switch (localFileHeader.getAesExtraDataRecord().getAesStrength()) {
						case ZipConstants.AES_STRENGTH_128:
							saltLength = 8;
							break;
						case ZipConstants.AES_STRENGTH_192:
							saltLength = 12;
							break;
						case ZipConstants.AES_STRENGTH_256:
							saltLength = 16;
							break;
							default:
								throw new ZipException("unable to determine salt length: invalid aes key strength");
						}
						salt = new byte[saltLength];
						input.seek(localFileHeader.getOffsetStartOfData());
						input.read(salt);
					}
					
					byte[] passwordBytes = new byte[2];
					input.read(passwordBytes);
					this.decryptor = new AESDecryptor(localFileHeader, salt, passwordBytes);
				} else if (localFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_STANDARD) {
					byte[] decryptorHeader = new byte[ZipConstants.STD_DEC_HDR_SIZE];
					input.seek(localFileHeader.getOffsetStartOfData());
					input.read(decryptorHeader);
					this.decryptor = new StandardDecryptor(localFileHeader, decryptorHeader);
				} else {
					throw new ZipException("Unsupported encryption method");
				}
			}
			
			long compressedSize = localFileHeader.getCompressedSize();
			long offsetStartOfData = localFileHeader.getOffsetStartOfData();
			
			if (localFileHeader.isEncrypted()) {
				if (localFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
					if (this.decryptor instanceof AESDecryptor) {
						compressedSize -= (((AESDecryptor)this.decryptor).getSaltLength() + 
								ZipConstants.PASSWORD_VERIFIER_LENGTH + 10);
						offsetStartOfData += (((AESDecryptor)this.decryptor).getSaltLength() + 
								ZipConstants.PASSWORD_VERIFIER_LENGTH);
					} else {
						throw new ZipException("invalid decryptor when trying to calculate " +
								"compressed size for AES encrypted file: " + localFileHeader.getEntryPath());
					}
				} else if (localFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_STANDARD) {
					compressedSize -= ZipConstants.STD_DEC_HDR_SIZE;
					offsetStartOfData += ZipConstants.STD_DEC_HDR_SIZE;
				}
			}
			
			int compressionMethod = localFileHeader.getCompressionMethod();
			if (generalFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES) {
				if (generalFileHeader.getAesExtraDataRecord() == null) {
					throw new ZipException("AES extra data record does not exists!");
				}
				compressionMethod = generalFileHeader.getAesExtraDataRecord().getCompressionMethod();
			}
			input.seek(offsetStartOfData);

			boolean isAESEncryptedFile = generalFileHeader.isEncrypted() 
						&& generalFileHeader.getEncryptionMethod() == ZipConstants.ENC_METHOD_AES;
			switch (compressionMethod) {
			case ZipConstants.COMP_STORE:
				return new ZipInputStream(new PartInputStream(this, input, 
						compressedSize, this.decryptor, isAESEncryptedFile));
			case ZipConstants.COMP_DEFLATE:
				return new ZipInputStream(new InflaterInputStream(this, input, 
						compressedSize, generalFileHeader.getOriginalSize(), this.decryptor, isAESEncryptedFile));
				default:
					throw new ZipException("Compression type not supported");
			}
		} catch (Exception e) {
			if (input != null) {
				try {
					input.close();
				}catch (IOException ex) {
				}
			}
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		}
	}
	
	private FileOutputStream openOutputStream(String folderPath, String fileName) throws ZipException {
		if (!StringUtils.isNotNullAndNotEmpty(folderPath)) {
			throw new ZipException("Output path is null");
		}
		
		if (!StringUtils.isNotNullAndNotEmpty(fileName)) {
			throw new ZipException("Output file name is null");
		}
		
		if (!FileUtils.makeHome(folderPath)) {
			throw new ZipException("Create output folder error");
		}
		
		try {
			if (!folderPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				folderPath += Globals.DEFAULT_PAGE_SEPARATOR;
			}
			
			String fullPath = folderPath + fileName;
			fullPath = StringUtils.replace(fullPath, ZipConstants.ZIP_FILE_SEPARATOR, Globals.DEFAULT_PAGE_SEPARATOR);
			FileUtils.makeHome(fullPath.substring(0, fullPath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR)));
			return new FileOutputStream(FileUtils.getFile(fullPath));
		} catch (FileNotFoundException e) {
			throw new ZipException(e);
		}
	}
	
	private OutputStream openMergeOutputStream(String outputPath) throws ZipException {
		if (outputPath == null) {
			throw new ZipException("Output path is null, cannot create outputstream");
		}
		
		try {
			return new FileOutputStream(FileUtils.getFile(outputPath));
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		}
	}

	private NervousyncRandomAccessFile openSplitFile(int index) throws ZipException {
		if (index < 0) {
			throw new ZipException("invlaid index, cannot create split file handler");
		}
		
		try {
			String currentSplitFile = null;
			
			if (index == this.endCentralDirectoryRecord.getIndexOfThisDisk()) {
				currentSplitFile = this.filePath;
			} else {
				currentSplitFile = this.filePath.substring(0, this.filePath.lastIndexOf('.'));
				if (this.currentSplitIndex < 9) {
					currentSplitFile += (".zip.0" + (this.currentSplitIndex + 1));
				} else {
					currentSplitFile += (".zip." + (this.currentSplitIndex + 1));
				}
			}
			
			if (!FileUtils.isExists(currentSplitFile)) {
				throw new ZipException("Split file not found!");
			}
			
			return new NervousyncRandomAccessFile(currentSplitFile, Globals.READ_MODE);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		}
	}
	
	private void updateSplitZipEntity(List<Long> sizeList, 
			boolean removeSplitSig) throws ZipException {
		this.splitArchive = Globals.DEFAULT_VALUE_BOOLEAN;
		this.updateSplitZipHeader(sizeList, removeSplitSig);
		this.updateSplitEndCentralDirectory();
		
		if (this.zip64Format) {
			this.updateSplitZip64EndCentralDirectoryLocator(sizeList);
			this.updateSplitZip64EndCentralDirectoryRecord(sizeList);
		}
	}
	
	private void updateSplitZipHeader(List<Long> sizeList, 
			boolean removeSplitSig) throws ZipException {
		if (this.centralDirectory == null) {
			throw new ZipException("corrupt zip entity, cannot update split zip model");
		}
		
		int splitSigOverhead = 0;
		if (removeSplitSig) {
			splitSigOverhead = 4;
		}
		
		List<GeneralFileHeader> newFileHeaders = new ArrayList<GeneralFileHeader>();
		
		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			long offsetHeaderToAdd = 0L;
			
			for (int i = 0 ; i < generalFileHeader.getDiskNumberStart() ; i++) {
				offsetHeaderToAdd += sizeList.get(i);
			}
			
			generalFileHeader.setOffsetLocalHeader(generalFileHeader.getOffsetLocalHeader() + offsetHeaderToAdd - splitSigOverhead);
			generalFileHeader.setDiskNumberStart(0);
			
			newFileHeaders.add(generalFileHeader);
		}
		
		this.centralDirectory.setFileHeaders(newFileHeaders);
	}
	
	private void updateSplitEndCentralDirectory() throws ZipException {
		if (this.centralDirectory == null) {
			throw new ZipException("corrupt zip entity, cannot update split zip model");
		}
		
		this.endCentralDirectoryRecord.setIndexOfThisDisk(0);
		this.endCentralDirectoryRecord.setIndexOfThisDiskStartOfCentralDirectory(0);
		this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectory(
				this.centralDirectory.getFileHeaders().size());
		this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectoryOnThisDisk(
				this.centralDirectory.getFileHeaders().size());
	}
	
	private void updateSplitZip64EndCentralDirectoryLocator(List<Long> sizeList) throws ZipException {
		if (this.zip64EndCentralDirectoryLocator == null) {
			return;
		}
		this.zip64EndCentralDirectoryLocator.setIndexOfZip64EndOfCentralDirectoryRecord(0);
		long offsetZip64EndCentralDirRec = 0;
		
		for (Long recordSize : sizeList) {
			offsetZip64EndCentralDirRec += recordSize.longValue();
		}
		this.zip64EndCentralDirectoryLocator.setOffsetZip64EndOfCentralDirectoryRecord(
				this.zip64EndCentralDirectoryLocator.getOffsetZip64EndOfCentralDirectoryRecord() + 
				offsetZip64EndCentralDirRec);
		this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(1);
	}
	
	private void updateSplitZip64EndCentralDirectoryRecord(List<Long> sizeList) throws ZipException {
		if (this.zip64EndCentralDirectoryRecord == null) {
			return;
		}
		this.zip64EndCentralDirectoryRecord.setIndex(0);
		this.zip64EndCentralDirectoryRecord.setStartOfCentralDirectory(0);
		this.zip64EndCentralDirectoryRecord.setTotalEntriesInCentralDirectoryOnThisDisk(
				this.endCentralDirectoryRecord.getTotalOfEntriesInCentralDirectory());
		
		long offsetStartCenDirWRTStartDiskNo = 0;

		for (Long recordSize : sizeList) {
			offsetStartCenDirWRTStartDiskNo += recordSize.longValue();
		}
		
		this.zip64EndCentralDirectoryRecord.setOffsetStartCenDirWRTStartDiskNo(
				this.zip64EndCentralDirectoryRecord.getOffsetStartCenDirWRTStartDiskNo() + 
				offsetStartCenDirWRTStartDiskNo);
	}
	
	private void readHeaders() throws ZipException {
		NervousyncRandomAccessFile input = null;
		
		try {
			input = new NervousyncRandomAccessFile(this.filePath, Globals.READ_MODE);
			this.readEndOfCentralDirectoryRecord(input);

			// Check and set zip64 format
			this.readZip64EndCentralDirectoryLocator(input);

			if (this.zip64Format) {
				this.readZip64EndCentralDirectoryRecord(input);
			}

			this.readCentralDirectory(input);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException)e;
			} else {
				throw new ZipException(e);
			}
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					if (this.logger.isDebugEnabled()) {
						this.logger.debug("Close random access file error! ", e);
					}
				}
			}
		}
	}
	
	private LocalFileHeader readLocalFileHeader(NervousyncRandomAccessFile input,
			GeneralFileHeader generalFileHeader) throws ZipException {
		if (generalFileHeader == null || input == null) {
			throw new ZipException("invalid read parameters for local header");
		}
		try {
			long localHeaderOffset = generalFileHeader.getOffsetLocalHeader();

			if (generalFileHeader.getZip64ExtendInfo() != null
					&& generalFileHeader.getZip64ExtendInfo().getOffsetLocalHeader() > 0L) {
				localHeaderOffset = generalFileHeader.getZip64ExtendInfo().getOffsetLocalHeader();
			}

			if (localHeaderOffset < 0) {
				throw new ZipException("Invalid local header offset");
			}
			
			input.seek(localHeaderOffset + 26);
			byte[] tempBuffer = new byte[4];
			input.read(tempBuffer);
			
			byte[] shortBuffer = new byte[2];
			System.arraycopy(tempBuffer, 0, shortBuffer, 0, 2);
			int fileNameLength = RawOperator.readShortFromLittleEndian(shortBuffer, 0);
			System.arraycopy(tempBuffer, 2, shortBuffer, 0, 2);
			int extraFieldLength = RawOperator.readShortFromLittleEndian(shortBuffer, 0);
			
			input.seek(localHeaderOffset);

			int length = 0;
			LocalFileHeader localFileHeader = new LocalFileHeader();
			
			byte[] readBuffer = new byte[30 + fileNameLength + extraFieldLength];
			input.read(readBuffer);
			
			byte[] intBuffer = new byte[4];

			// Signature
			System.arraycopy(readBuffer, 0, intBuffer, 0, 4);
			int signature = RawOperator.readIntFromLittleEndian(intBuffer, 0);
			if (signature != ZipConstants.LOCSIG) {
				throw new ZipException("invalid local header signature for file: " + generalFileHeader.getEntryPath());
			}
			localFileHeader.setSignature(signature);
			length += 4;

			// Extract needed
			System.arraycopy(readBuffer, 4, shortBuffer, 0, 2);
			localFileHeader.setExtractNeeded(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
			length += 2;

			// General purpose bit flag
			System.arraycopy(readBuffer, 6, shortBuffer, 0, 2);
			localFileHeader.setFileNameUTF8Encoded(
					(RawOperator.readShortFromLittleEndian(shortBuffer, 0) & ZipConstants.UFT8_NAMES_FLAG) != 0);
			int firstByte = shortBuffer[0];
			if ((firstByte & 1) != 0) {
				localFileHeader.setEncrypted(true);
			}
			localFileHeader.setGeneralPurposeFlag(shortBuffer);
			length += 2;

			// Check if data descriptor exists for local file header
			String binaryData = Integer.toBinaryString(firstByte);
			if (binaryData.length() >= 4) {
				localFileHeader.setDataDescriptorExists(binaryData.charAt(3) == '1');
			}

			// Compression method
			System.arraycopy(readBuffer, 8, shortBuffer, 0, 2);
			localFileHeader.setCompressionMethod(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
			length += 2;

			// Lase modify time
			System.arraycopy(readBuffer, 10, intBuffer, 0, 4);
			localFileHeader.setLastModFileTime(RawOperator.readIntFromLittleEndian(intBuffer, 0));
			length += 4;

			// CRC
			System.arraycopy(readBuffer, 14, intBuffer, 0, 4);
			localFileHeader.setCrc32(RawOperator.readIntFromLittleEndian(intBuffer, 0));
			localFileHeader.setCrcBuffer(intBuffer.clone());
			length += 4;

			// Compressed size
			System.arraycopy(readBuffer, 18, intBuffer, 0, 4);
			localFileHeader.setCompressedSize(RawOperator.readLongFromLittleEndian(readLongByteFromIntByte(intBuffer), 0));
			length += 4;

			// Original size
			System.arraycopy(readBuffer, 22, intBuffer, 0, 4);
			localFileHeader.setOriginalSize(RawOperator.readLongFromLittleEndian(readLongByteFromIntByte(intBuffer), 0));
			length += 4;

			// File name length
			localFileHeader.setFileNameLength(fileNameLength);
			length += 2;

			// Extra field length
			localFileHeader.setExtraFieldLength(extraFieldLength);
			length += 2;

			// File name
			if (fileNameLength > 0) {
				byte[] fileNameBuffer = new byte[fileNameLength];
				System.arraycopy(readBuffer, 30, fileNameBuffer, 0, fileNameLength);

				String entryPath = null;

				try {
					if (localFileHeader.isFileNameUTF8Encoded()) {
						entryPath = new String(fileNameBuffer, Globals.DEFAULT_ENCODING);
					} else {
						entryPath = new String(fileNameBuffer, ZipConstants.CHARSET_CP850);
					}
				} catch (UnsupportedEncodingException e) {
					entryPath = new String(fileNameBuffer);
				}

				if (entryPath.indexOf(ZipConstants.ZIP_ENTRY_SEPARATOR) >= 0) {
					entryPath = entryPath.substring(entryPath.indexOf(ZipConstants.ZIP_ENTRY_SEPARATOR) 
							+ ZipConstants.ZIP_ENTRY_SEPARATOR.length());
				}

				localFileHeader.setEntryPath(entryPath);
				length += fileNameLength;
			} else {
				localFileHeader.setEntryPath(null);
			}
			
			// Extra field
			if (localFileHeader.getExtraFieldLength() > 0) {
				byte[] extraFieldBuffer = new byte[extraFieldLength];
				System.arraycopy(readBuffer, 30 + fileNameLength, extraFieldBuffer, 0, extraFieldLength);
				localFileHeader.setExtraDataRecords(readExtraDataRecords(extraFieldBuffer, extraFieldLength));
			}
			length += extraFieldLength;

			localFileHeader.setOffsetStartOfData(localHeaderOffset + length);
			
			// Copy password
			localFileHeader.setPassword(generalFileHeader.getPassword());

			readAndSaveZip64ExtendInfo(localFileHeader);
			readAndSaveAESExtraDataRecord(localFileHeader);

			if (localFileHeader.isEncrypted() && localFileHeader.getEncryptionMethod() != ZipConstants.ENC_METHOD_AES) {
				if ((firstByte & 64) == 64) {
					localFileHeader.setEncryptionMethod(ZipConstants.ENC_METHOD_STRONG);
				} else {
					localFileHeader.setEncryptionMethod(ZipConstants.ENC_METHOD_STANDARD);
				}
			}

			if (localFileHeader.getCrc32() <= 0L) {
				localFileHeader.setCrc32(generalFileHeader.getCrc32());
				localFileHeader.setCrcBuffer(generalFileHeader.getCrcBuffer());
			}

			if (localFileHeader.getCompressedSize() <= 0L) {
				localFileHeader.setCompressedSize(generalFileHeader.getCompressedSize());
			}

			if (localFileHeader.getOriginalSize() <= 0L) {
				localFileHeader.setOriginalSize(generalFileHeader.getOriginalSize());
			}

			return localFileHeader;
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}

	private void processHeaderData(OutputStream outputStream) throws ZipException {
		try {
			int currentSplitFileCount = 0;
			if (outputStream instanceof SplitOutputStream) {
				this.endCentralDirectoryRecord
						.setOffsetOfStartOfCentralDirectory(((SplitOutputStream) outputStream).getFilePointer());
				currentSplitFileCount = ((SplitOutputStream) outputStream).getCurrentSplitFileIndex();
			}

			if (this.zip64Format) {
				if (this.zip64EndCentralDirectoryRecord == null) {
					this.zip64EndCentralDirectoryRecord = new Zip64EndCentralDirectoryRecord();
				}

				if (this.zip64EndCentralDirectoryLocator == null) {
					this.zip64EndCentralDirectoryLocator = new Zip64EndCentralDirectoryLocator();
				}

				this.zip64EndCentralDirectoryLocator
						.setIndexOfZip64EndOfCentralDirectoryRecord(currentSplitFileCount);
				this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(currentSplitFileCount + 1);
			}

			this.endCentralDirectoryRecord.setIndexOfThisDisk(currentSplitFileCount);
			this.endCentralDirectoryRecord.setIndexOfThisDiskStartOfCentralDirectory(currentSplitFileCount);
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}

	private int writeCentralDirectory(OutputStream outputStream,
			List<String> headerBytesList) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("output parameters is null, cannot write central directory");
		}

		if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null
				|| this.centralDirectory.getFileHeaders().size() <= 0) {
			return 0;
		}

		int sizeOfCentralDirectory = 0;

		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			sizeOfCentralDirectory += writeFileHeader(generalFileHeader, outputStream, headerBytesList);
		}
		return sizeOfCentralDirectory;
	}

	private int writeFileHeader(GeneralFileHeader generalFileHeader,
			OutputStream outputStream, List<String> headerBytesList) throws ZipException {
		if (generalFileHeader == null || outputStream == null) {
			throw new ZipException("input parameters is null, cannot write local file header");
		}

		try {
			int sizeOfFileHeader = 0;

			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			final byte[] EMPTY_SHORT_BUFFER = { 0, 0 };
			final byte[] EMPTY_INT_BUFFER = { 0, 0, 0, 0 };

			boolean writeZip64FileSize = false;
			boolean writeZip64OffsetLocalHeader = false;

			RawOperator.writeIntFromLittleEndian(intBuffer, 0, generalFileHeader.getSignature());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
			sizeOfFileHeader += 4;

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) generalFileHeader.getMadeVersion());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) generalFileHeader.getExtractNeeded());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			HeaderOperator.copyByteArrayToArrayList(generalFileHeader.getGeneralPurposeFlag(), headerBytesList);
			sizeOfFileHeader += 2;

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) generalFileHeader.getCompressionMethod());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			RawOperator.writeIntFromLittleEndian(intBuffer, 0, generalFileHeader.getLastModFileTime());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
			sizeOfFileHeader += 4;

			RawOperator.writeIntFromLittleEndian(intBuffer, 0, (int) (generalFileHeader.getCrc32()));
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
			sizeOfFileHeader += 4;

			if (generalFileHeader.getCompressedSize() >= ZipConstants.ZIP_64_LIMIT
					|| generalFileHeader.getOriginalSize()
							+ ZipConstants.ZIP64_EXTRA_BUFFER_SIZE >= ZipConstants.ZIP_64_LIMIT) {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, ZipConstants.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);

				HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;

				HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;

				writeZip64FileSize = true;
			} else {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, generalFileHeader.getCompressedSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;

				RawOperator.writeLongFromLittleEndian(longBuffer, 0, generalFileHeader.getOriginalSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;
			}

			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) generalFileHeader.getFileNameLength());
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			// Compute offset bytes before extra field is written for Zip64
			// compatibility
			// NOTE: this data is not written now, but written at a later point
			byte[] offsetLocalHeaderBytes = new byte[4];
			if (generalFileHeader.getOffsetLocalHeader() > ZipConstants.ZIP_64_LIMIT) {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, ZipConstants.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, offsetLocalHeaderBytes, 0, 4);
				writeZip64OffsetLocalHeader = true;
			} else {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, generalFileHeader.getOffsetLocalHeader());
				System.arraycopy(longBuffer, 0, offsetLocalHeaderBytes, 0, 4);
			}

			// extra field length
			int extraFieldLength = 0;
			if (writeZip64FileSize || writeZip64OffsetLocalHeader) {
				extraFieldLength += 4;
				if (writeZip64FileSize)
					extraFieldLength += 16;
				if (writeZip64OffsetLocalHeader)
					extraFieldLength += 8;
			}
			if (generalFileHeader.getAesExtraDataRecord() != null) {
				extraFieldLength += 11;
			}
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) (extraFieldLength));
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			// Skip file comment length for now
			HeaderOperator.copyByteArrayToArrayList(EMPTY_SHORT_BUFFER, headerBytesList);
			sizeOfFileHeader += 2;

			// Skip disk number start for now
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) (generalFileHeader.getDiskNumberStart()));
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			// Skip internal file attributes for now
			HeaderOperator.copyByteArrayToArrayList(EMPTY_SHORT_BUFFER, headerBytesList);
			sizeOfFileHeader += 2;

			// External file attributes
			if (generalFileHeader.getExternalFileAttr() != null) {
				HeaderOperator.copyByteArrayToArrayList(generalFileHeader.getExternalFileAttr(), headerBytesList);
			} else {
				HeaderOperator.copyByteArrayToArrayList(EMPTY_INT_BUFFER, headerBytesList);
			}
			sizeOfFileHeader += 4;

			// offset local header
			// this data is computed above
			HeaderOperator.copyByteArrayToArrayList(offsetLocalHeaderBytes, headerBytesList);
			sizeOfFileHeader += 4;

			if (StringUtils.isNotNullAndNotEmpty(this.fileNameCharset)) {
				byte[] fileNameBytes = generalFileHeader.getEntryPath().getBytes(this.fileNameCharset);
				HeaderOperator.copyByteArrayToArrayList(fileNameBytes, headerBytesList);
				sizeOfFileHeader += fileNameBytes.length;
			} else {
				HeaderOperator.copyByteArrayToArrayList(StringUtils.convertCharset(generalFileHeader.getEntryPath()), headerBytesList);
				sizeOfFileHeader += StringUtils.getEncodedStringLength(generalFileHeader.getEntryPath());
			}

			if (writeZip64FileSize || writeZip64OffsetLocalHeader) {
				this.zip64Format = true;

				// Zip64 header
				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) ZipConstants.EXTRAFIELDZIP64LENGTH);
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
				sizeOfFileHeader += 2;

				// Zip64 extra data record size
				int dataSize = 0;

				if (writeZip64FileSize) {
					dataSize += 16;
				}
				if (writeZip64OffsetLocalHeader) {
					dataSize += 8;
				}

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) dataSize);
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
				sizeOfFileHeader += 2;

				if (writeZip64FileSize) {
					RawOperator.writeLongFromLittleEndian(longBuffer, 0, generalFileHeader.getOriginalSize());
					HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);
					sizeOfFileHeader += 8;

					RawOperator.writeLongFromLittleEndian(longBuffer, 0, generalFileHeader.getCompressedSize());
					HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);
					sizeOfFileHeader += 8;
				}

				if (writeZip64OffsetLocalHeader) {
					RawOperator.writeLongFromLittleEndian(longBuffer, 0, generalFileHeader.getOffsetLocalHeader());
					HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);
					sizeOfFileHeader += 8;
				}
			}

			if (generalFileHeader.getAesExtraDataRecord() != null) {
				AESExtraDataRecord aesExtraDataRecord = generalFileHeader.getAesExtraDataRecord();

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) aesExtraDataRecord.getSignature());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) aesExtraDataRecord.getDataSize());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) aesExtraDataRecord.getVersionNumber());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

				HeaderOperator.copyByteArrayToArrayList(aesExtraDataRecord.getVendorID().getBytes(), headerBytesList);

				byte[] aesStrengthBytes = new byte[1];
				aesStrengthBytes[0] = (byte) aesExtraDataRecord.getAesStrength();
				HeaderOperator.copyByteArrayToArrayList(aesStrengthBytes, headerBytesList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0,
						(short) aesExtraDataRecord.getCompressionMethod());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

				sizeOfFileHeader += 11;
			}

			return sizeOfFileHeader;
		} catch (Exception e) {
			throw new ZipException(e);
		}
	}

	private void writeZip64EndOfCentralDirectoryRecord(OutputStream outputStream,
			int sizeOfCentralDirectory, long offsetCentralDirectory, List<String> headerBytesList) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("Output stream is null, cannot write zip64 end of central directory record");
		}

		try {
			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			final byte[] EMPTY_SHORT_BUFFER = { 0, 0 };

			// zip64 end of central dir signature
			RawOperator.writeIntFromLittleEndian(intBuffer, 0, (int) ZipConstants.ZIP64ENDCENDIRREC);
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);

			// size of zip64 end of central directory record
			RawOperator.writeLongFromLittleEndian(longBuffer, 0, (long) 44);
			HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);

			// version made by
			// version needed to extract
			if (this.centralDirectory != null && this.centralDirectory.getFileHeaders() != null
					&& this.centralDirectory.getFileHeaders().size() > 0) {
				RawOperator.writeShortFromLittleEndian(shortBuffer, 0,
						(short) this.centralDirectory.getFileHeaders().get(0).getMadeVersion());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

				RawOperator.writeShortFromLittleEndian(shortBuffer, 0,
						(short) this.centralDirectory.getFileHeaders().get(0).getExtractNeeded());
				HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);
			} else {
				HeaderOperator.copyByteArrayToArrayList(EMPTY_SHORT_BUFFER, headerBytesList);
				HeaderOperator.copyByteArrayToArrayList(EMPTY_SHORT_BUFFER, headerBytesList);
			}

			// number of this disk
			RawOperator.writeIntFromLittleEndian(intBuffer, 0,
					this.endCentralDirectoryRecord.getIndexOfThisDisk());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);

			// number of the disk with start of central directory
			RawOperator.writeIntFromLittleEndian(intBuffer, 0,
					this.endCentralDirectoryRecord.getIndexOfThisDiskStartOfCentralDirectory());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);

			// total number of entries in the central directory on this disk
			int numEntries = 0;
			int numEntriesOnThisDisk = 0;
			if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null) {
				throw new ZipException(
						"invalid central directory/file headers, " + "cannot write end of central directory record");
			} else {
				numEntries = this.centralDirectory.getFileHeaders().size();
				if (this.splitArchive) {
					countNumberOfFileHeaderEntriesOnDisk(this.centralDirectory.getFileHeaders(),
							this.endCentralDirectoryRecord.getIndexOfThisDisk());
				} else {
					numEntriesOnThisDisk = numEntries;
				}
			}
			RawOperator.writeLongFromLittleEndian(longBuffer, 0, numEntriesOnThisDisk);
			HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);

			// Total number of entries in central directory
			RawOperator.writeLongFromLittleEndian(longBuffer, 0, numEntries);
			HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);

			// Size of central directory
			RawOperator.writeLongFromLittleEndian(longBuffer, 0, sizeOfCentralDirectory);
			HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);

			// offset of start of central directory with respect to the starting
			// disk number
			RawOperator.writeLongFromLittleEndian(longBuffer, 0, offsetCentralDirectory);
			HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw e;
			} else {
				throw new ZipException(e);
			}
		}
	}

	private void writeZip64EndOfCentralDirectoryLocator(OutputStream outputStream,
			List<String> headerBytesList) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("Output stream is null, cannot write zip64 end of central directory locator");
		}

		try {
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			// zip64 end of central dir locator signature
			RawOperator.writeIntFromLittleEndian(intBuffer, 0, (int) ZipConstants.ZIP64ENDCENDIRLOC);
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);

			// number of the disk with the start of the zip64 end of central
			// directory
			RawOperator.writeIntFromLittleEndian(intBuffer, 0,
					this.zip64EndCentralDirectoryLocator.getIndexOfZip64EndOfCentralDirectoryRecord());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);

			// relative offset of the zip64 end of central directory record
			RawOperator.writeLongFromLittleEndian(longBuffer, 0,
					this.zip64EndCentralDirectoryLocator.getOffsetZip64EndOfCentralDirectoryRecord());
			HeaderOperator.copyByteArrayToArrayList(longBuffer, headerBytesList);

			// total number of disks
			RawOperator.writeIntFromLittleEndian(intBuffer, 0,
					this.zip64EndCentralDirectoryLocator.getTotalNumberOfDiscs());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw e;
			} else {
				throw new ZipException(e);
			}
		}
	}

	private void writeEndOfCentralDirectoryRecord(OutputStream outputStream,
			int sizeOfCentralDirectory, long offsetCentralDirectory, List<String> headerBytesList) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("Output stream is null, cannot write end of central directory record");
		}

		try {
			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			// End of central directory signature
			RawOperator.writeIntFromLittleEndian(intBuffer, 0,
					(int) this.endCentralDirectoryRecord.getSignature());
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);

			// number of this disk
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0,
					(short) (this.endCentralDirectoryRecord.getIndexOfThisDisk()));
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

			// number of the disk with start of central directory
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0,
					(short) (this.endCentralDirectoryRecord.getIndexOfThisDiskStartOfCentralDirectory()));
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

			// Total number of entries in central directory on this disk
			int numEntries = 0;
			int numEntriesOnThisDisk = 0;
			if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null) {
				throw new ZipException(
						"invalid central directory/file headers, " + "cannot write end of central directory record");
			} else {
				numEntries = this.centralDirectory.getFileHeaders().size();
				if (this.splitArchive) {
					numEntriesOnThisDisk = countNumberOfFileHeaderEntriesOnDisk(
							this.centralDirectory.getFileHeaders(),
							this.endCentralDirectoryRecord.getIndexOfThisDisk());
				} else {
					numEntriesOnThisDisk = numEntries;
				}
			}
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) numEntriesOnThisDisk);
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

			// Total number of entries in central directory
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) numEntries);
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

			// Size of central directory
			RawOperator.writeIntFromLittleEndian(intBuffer, 0, sizeOfCentralDirectory);
			HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
			
			// Offset central directory
			if (offsetCentralDirectory > ZipConstants.ZIP_64_LIMIT) {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, ZipConstants.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
			} else {
				RawOperator.writeLongFromLittleEndian(longBuffer, 0, offsetCentralDirectory);
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToArrayList(intBuffer, headerBytesList);
			}

			// Zip File comment length
			int commentLength = 0;
			if (this.endCentralDirectoryRecord.getCommentBytes() != null) {
				commentLength = this.endCentralDirectoryRecord.getCommentLength();
			}
			RawOperator.writeShortFromLittleEndian(shortBuffer, 0, (short) commentLength);
			HeaderOperator.copyByteArrayToArrayList(shortBuffer, headerBytesList);

			// Comment
			if (commentLength > 0) {
				HeaderOperator.copyByteArrayToArrayList(this.endCentralDirectoryRecord.getCommentBytes(), headerBytesList);
			}
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw e;
			} else {
				throw new ZipException(e);
			}
		}
	}

	private void writeZipHeaderBytes(OutputStream outputStream, byte[] buffer)
			throws ZipException {
		if (buffer == null) {
			throw new ZipException("invalid buffer to write as zip headers");
		}

		try {
			if (outputStream instanceof SplitOutputStream) {
				if (((SplitOutputStream) outputStream).checkBufferSizeAndStartNextSplitFile(buffer.length)) {
					this.finalizeZipFile(outputStream);
					return;
				}
			}
			outputStream.write(buffer);
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}
	
	private void readEndOfCentralDirectoryRecord(NervousyncRandomAccessFile input)
			throws ZipException {
		if (input == null) {
			throw new ZipException("Random access file is null!");
		}
		
		try {
			byte[] buffer = new byte[4];
			long position = Globals.DEFAULT_VALUE_LONG;
			try {
				position = input.length();
			} catch (IOException e) {
				position = Globals.DEFAULT_VALUE_LONG;
			}
			
			if (position == Globals.DEFAULT_VALUE_LONG) {
				throw new ZipException("Read end of central directory record error! ");
			}
			position -= ZipConstants.ENDHDR;

			this.endCentralDirectoryRecord = new EndCentralDirectoryRecord();

			int count = 0;
			do {
				input.seek(position--);
				count++;
			} while ((readIntFromDataInput(input, buffer) != ZipConstants.ENDSIG)
					&& count <= 3000);
			
			if (RawOperator.readIntFromLittleEndian(buffer, 0) != ZipConstants.ENDSIG) {
				throw new ZipException("zip headers not found. probably not a zip file");
			}
			
			byte[] readBuffer = new byte[18];
			input.read(readBuffer);
			
			byte[] intBuffer = new byte[4];
			byte[] shortBuffer = new byte[2];

			this.endCentralDirectoryRecord.setSignature(ZipConstants.ENDSIG);

			System.arraycopy(readBuffer, 0, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord.setIndexOfThisDisk(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

			System.arraycopy(readBuffer, 2, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord
					.setIndexOfThisDiskStartOfCentralDirectory(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

			System.arraycopy(readBuffer, 4, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectoryOnThisDisk(
					RawOperator.readShortFromLittleEndian(shortBuffer, 0));

			System.arraycopy(readBuffer, 6, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord
					.setTotalOfEntriesInCentralDirectory(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

			System.arraycopy(readBuffer, 8, intBuffer, 0, 4);
			this.endCentralDirectoryRecord.setSizeOfCentralDirectory(RawOperator.readIntFromLittleEndian(intBuffer, 0));

			System.arraycopy(readBuffer, 12, intBuffer, 0, 4);
			this.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(
					RawOperator.readLongFromLittleEndian(readLongByteFromIntByte(intBuffer), 0));
			
			System.arraycopy(readBuffer, 16, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord.setCommentLength(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
			
			if (this.endCentralDirectoryRecord.getCommentLength() > 0) {
				byte[] commentBuffer = new byte[endCentralDirectoryRecord.getCommentLength()];
				input.read(commentBuffer);
				endCentralDirectoryRecord.setCommentBytes(commentBuffer);
			}

			if (this.endCentralDirectoryRecord.getIndexOfThisDisk() > 0) {
				this.splitArchive = true;
			} else {
				this.splitArchive = false;
			}
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}

	private void readZip64EndCentralDirectoryLocator(NervousyncRandomAccessFile input)
			throws ZipException {
		try {
			this.zip64EndCentralDirectoryLocator = new Zip64EndCentralDirectoryLocator();
			byte[] buffer = new byte[4];
			long position = Globals.DEFAULT_VALUE_LONG;
			try {
				position = input.length();
			} catch (Exception e) {
				position = Globals.DEFAULT_VALUE_LONG;
			}
			
			if (position == Globals.DEFAULT_VALUE_LONG) {
				throw new ZipException("Read end of central directory record error! ");
			}
			position -= ZipConstants.ENDHDR;
			
			do {
				input.seek(position--);
			} while (readIntFromDataInput(input, buffer) != ZipConstants.ENDSIG);
			
			// Now the file pointer is at the end of signature of Central Dir
			// Rec
			// Seek back with the following values
			// 4 -> total number of disks
			// 8 -> relative offset of the zip64 end of central directory record
			// 4 -> number of the disk with the start of the zip64 end of
			// central directory
			// 4 -> zip64 end of central dir locator signature
			// Refer to Appnote for more information
			input.seek(position - 4 - 8 - 4 - 4);

			byte[] readBuffer = new byte[20];
			input.read(readBuffer);
			
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];
			
			System.arraycopy(readBuffer, 0, intBuffer, 0, 4);
			int signature = RawOperator.readIntFromLittleEndian(intBuffer, 0);
			if (signature == ZipConstants.ZIP64ENDCENDIRLOC) {
				this.zip64Format = true;
				this.zip64EndCentralDirectoryLocator.setSignature(signature);
			} else {
				this.zip64Format = false;
				return;
			}

			System.arraycopy(readBuffer, 4, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryLocator
					.setIndexOfZip64EndOfCentralDirectoryRecord(RawOperator.readIntFromLittleEndian(intBuffer, 0));

			System.arraycopy(readBuffer, 8, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryLocator
					.setOffsetZip64EndOfCentralDirectoryRecord(RawOperator.readLongFromLittleEndian(longBuffer, 0));

			System.arraycopy(readBuffer, 16, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(RawOperator.readIntFromLittleEndian(intBuffer, 0));
		} catch (Exception e) {
			throw new ZipException(e);
		}
	}

	private void readCentralDirectory(NervousyncRandomAccessFile input)
			throws ZipException {
		if (this.endCentralDirectoryRecord == null) {
			throw new ZipException("End Central Record is null!");
		}

		try {
			List<GeneralFileHeader> fileHeaderList = new ArrayList<GeneralFileHeader>();

			long offsetOfStartOfCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();
			int centralDirectoryEntryCount = this.endCentralDirectoryRecord.getTotalOfEntriesInCentralDirectory();

			if (this.zip64Format) {
				offsetOfStartOfCentralDirectory = this.zip64EndCentralDirectoryRecord.getOffsetStartCenDirWRTStartDiskNo();
				centralDirectoryEntryCount = (int)this.zip64EndCentralDirectoryRecord.getTotalEntriesInCentralDirectory();
			}
			
			input.seek(offsetOfStartOfCentralDirectory);
			
			long bufferSize = input.length() - offsetOfStartOfCentralDirectory;
			byte[] readBuffer = new byte[(int)bufferSize];
			input.read(readBuffer);
			
			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			
			int pos = 0;
			for (int i = 0; i < centralDirectoryEntryCount; i++) {
				GeneralFileHeader fileHeader = new GeneralFileHeader();
				
				System.arraycopy(readBuffer, pos + 0, intBuffer, 0, 4);
				int signature = RawOperator.readIntFromLittleEndian(intBuffer, 0);
				if (signature != ZipConstants.CENSIG) {
					throw new ZipException("Expected central directory entry not found! Index: " + i);
				}

				fileHeader.setSignature(signature);
				
				// Made version
				System.arraycopy(readBuffer, pos + 4, shortBuffer, 0, 2);
				fileHeader.setMadeVersion(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
				
				// Extract needed
				System.arraycopy(readBuffer, pos + 6, shortBuffer, 0, 2);
				fileHeader.setExtractNeeded(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

				// Purpose bit flag
				System.arraycopy(readBuffer, pos + 8, shortBuffer, 0, 2);
				fileHeader.setFileNameUTF8Encoded(
						(RawOperator.readShortFromLittleEndian(shortBuffer, 0) & ZipConstants.UFT8_NAMES_FLAG) != 0);
				if ((shortBuffer[0] & 1) != 0) {
					fileHeader.setEncrypted(true);
				}
				fileHeader.setGeneralPurposeFlag(shortBuffer.clone());
				fileHeader.setDataDescriptorExists((shortBuffer[0] >> 3) == 1);

				// Compression method
				System.arraycopy(readBuffer, pos + 10, shortBuffer, 0, 2);
				fileHeader.setCompressionMethod(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

				// Last modify file time
				System.arraycopy(readBuffer, pos + 12, intBuffer, 0, 4);
				fileHeader.setLastModFileTime(RawOperator.readIntFromLittleEndian(intBuffer, 0));

				// Crc32
				System.arraycopy(readBuffer, pos + 16, intBuffer, 0, 4);
				fileHeader.setCrc32(RawOperator.readIntFromLittleEndian(intBuffer, 0));
				fileHeader.setCrcBuffer(intBuffer.clone());

				// Compressed size
				System.arraycopy(readBuffer, pos + 20, intBuffer, 0, 4);
				fileHeader.setCompressedSize(RawOperator.readLongFromLittleEndian(readLongByteFromIntByte(intBuffer), 0));

				// Original size
				System.arraycopy(readBuffer, pos + 24, intBuffer, 0, 4);
				fileHeader.setOriginalSize(RawOperator.readLongFromLittleEndian(readLongByteFromIntByte(intBuffer), 0));

				// File name length
				System.arraycopy(readBuffer, pos + 28, shortBuffer, 0, 2);
				fileHeader.setFileNameLength(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

				// Extra field length
				System.arraycopy(readBuffer, pos + 30, shortBuffer, 0, 2);
				fileHeader.setExtraFieldLength(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

				// Comment length
				System.arraycopy(readBuffer, pos + 32, shortBuffer, 0, 2);
				fileHeader.setFileCommentLength(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
				
				// Disk number of start
				System.arraycopy(readBuffer, pos + 34, shortBuffer, 0, 2);
				fileHeader.setDiskNumberStart(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
				
				// Internal file attributes
				System.arraycopy(readBuffer, pos + 36, shortBuffer, 0, 2);
				fileHeader.setInternalFileAttr(shortBuffer.clone());

				// External file attributes
				System.arraycopy(readBuffer, pos + 38, intBuffer, 0, 4);
				fileHeader.setExternalFileAttr(intBuffer.clone());

				// Relative offset of local header
				System.arraycopy(readBuffer, pos + 42, intBuffer, 0, 4);
				fileHeader.setOffsetLocalHeader(
						RawOperator.readLongFromLittleEndian(readLongByteFromIntByte(intBuffer), 0) & 0xFFFFFFFFL);
				
				if (fileHeader.getFileNameLength() > 0) {
					byte[] fileNameBuffer = new byte[fileHeader.getFileNameLength()];
					System.arraycopy(readBuffer, pos + 46, fileNameBuffer, 0, fileHeader.getFileNameLength());

					String entryPath = null;

					if (this.fileNameCharset != null) {
						entryPath = new String(fileNameBuffer, this.fileNameCharset);
					} else {
						if (fileHeader.isFileNameUTF8Encoded()) {
							entryPath = new String(fileNameBuffer, Globals.DEFAULT_ENCODING);
						} else {
							entryPath = new String(fileNameBuffer);
						}
					}

					if (entryPath.indexOf(ZipConstants.ZIP_ENTRY_SEPARATOR) >= 0) {
						entryPath = entryPath.substring(entryPath.indexOf(ZipConstants.ZIP_ENTRY_SEPARATOR) 
								+ ZipConstants.ZIP_ENTRY_SEPARATOR.length());
					}
					
					fileHeader.setEntryPath(entryPath);
					if (entryPath.endsWith(ZipConstants.ZIP_FILE_SEPARATOR) 
							|| entryPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
						fileHeader.setDirectory(true);
					} else {
						fileHeader.setDirectory(Globals.DEFAULT_VALUE_BOOLEAN);
					}
				} else {
					fileHeader.setEntryPath(null);
				}
				
				// Extra field
				if (fileHeader.getExtraFieldLength() > 0) {
					byte[] extraFieldBuffer = new byte[fileHeader.getExtraFieldLength()];
					System.arraycopy(readBuffer, pos + 46 + fileHeader.getFileNameLength(), extraFieldBuffer, 0, fileHeader.getExtraFieldLength());
					fileHeader.setExtraDataRecords(readExtraDataRecords(extraFieldBuffer, fileHeader.getExtraFieldLength()));
				}
				
				// Read zip64 extra data record if exists
				readAndSaveZip64ExtendInfo(fileHeader);
				
				// Read AES Extra data record if exists
				readAndSaveAESExtraDataRecord(fileHeader);
				
				if (fileHeader.getFileCommentLength() > 0) {
					byte[] commentBuffer = new byte[fileHeader.getFileCommentLength()];
					System.arraycopy(readBuffer, pos + 46 + fileHeader.getFileNameLength() + fileHeader.getExtraFieldLength(), commentBuffer, 0, fileHeader.getFileCommentLength());
					fileHeader.setFileComment(new String(commentBuffer));
				}
				fileHeaderList.add(fileHeader);
				pos += (46 + fileHeader.getFileNameLength() + fileHeader.getExtraFieldLength() + fileHeader.getFileCommentLength());
			}

			this.centralDirectory = new CentralDirectory();

			this.centralDirectory.setFileHeaders(fileHeaderList);
			
			System.arraycopy(readBuffer, pos, intBuffer, 0, 4);
			int signature = RawOperator.readIntFromLittleEndian(intBuffer, 0);
			if (signature == ZipConstants.DIGSIG) {
				DigitalSignature digitalSignature = new DigitalSignature();
				
				digitalSignature.setSignature(signature);

				System.arraycopy(readBuffer, pos + 4, shortBuffer, 0, 2);
				digitalSignature.setDataSize(RawOperator.readShortFromLittleEndian(shortBuffer, 0));
				
				if (digitalSignature.getDataSize() > 0) {
					byte[] signatureDataBuffer = new byte[digitalSignature.getDataSize()];
					System.arraycopy(readBuffer, pos + 6, signatureDataBuffer, 0, digitalSignature.getDataSize());
					digitalSignature.setSignatureData(new String(signatureDataBuffer));
				}
				
				this.centralDirectory.setDigitalSignature(digitalSignature);
			}
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}

	private void readZip64EndCentralDirectoryRecord(NervousyncRandomAccessFile input)
			throws ZipException {
		if (this.zip64EndCentralDirectoryLocator == null) {
			throw new ZipException("Invalid zip64 end of central directory locator");
		}

		try {
			long offsetZip64EndOfCentralDirectoryRecord = 
					this.zip64EndCentralDirectoryLocator.getOffsetZip64EndOfCentralDirectoryRecord();

			if (offsetZip64EndOfCentralDirectoryRecord < 0L) {
				throw new ZipException("Invalid offset for start of end of central directory record");
			}
			
			input.seek(offsetZip64EndOfCentralDirectoryRecord);

			this.zip64EndCentralDirectoryRecord = new Zip64EndCentralDirectoryRecord();

			byte[] readBuffer = new byte[56];
			input.read(readBuffer);
			
			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];
			
			System.arraycopy(readBuffer, 0, intBuffer, 0, 4);
			int signature = RawOperator.readIntFromLittleEndian(intBuffer, 0);
			if (signature != ZipConstants.ZIP64ENDCENDIRREC) {
				throw new ZipException("Invalid signature for zip64 end of central directory record");
			}
			this.zip64EndCentralDirectoryRecord.setSignature(signature);

			// Read size of zip64 end of central directory record
			System.arraycopy(readBuffer, 4, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord.setRecordSize(RawOperator.readLongFromLittleEndian(longBuffer, 0));

			// Made version
			System.arraycopy(readBuffer, 12, shortBuffer, 0, 2);
			this.zip64EndCentralDirectoryRecord.setMadeVersion(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

			// Extract needed
			System.arraycopy(readBuffer, 14, shortBuffer, 0, 2);
			this.zip64EndCentralDirectoryRecord.setExtractNeeded(RawOperator.readShortFromLittleEndian(shortBuffer, 0));

			// Number of this disk
			System.arraycopy(readBuffer, 16, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryRecord.setIndex(RawOperator.readIntFromLittleEndian(intBuffer, 0));

			// Start of central directory
			System.arraycopy(readBuffer, 20, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryRecord
					.setStartOfCentralDirectory(RawOperator.readIntFromLittleEndian(intBuffer, 0));

			// Total of entries in the central directory on this disk
			System.arraycopy(readBuffer, 24, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setTotalEntriesInCentralDirectoryOnThisDisk(RawOperator.readLongFromLittleEndian(longBuffer, 0));

			// Total of entries in the central directory
			System.arraycopy(readBuffer, 32, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setTotalEntriesInCentralDirectory(RawOperator.readLongFromLittleEndian(longBuffer, 0));

			// Size of the central directory
			System.arraycopy(readBuffer, 40, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setSizeOfCentralDirectory(RawOperator.readLongFromLittleEndian(longBuffer, 0));

			// Offset of start of central directory with respect to the starting
			// disk number
			System.arraycopy(readBuffer, 48, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setOffsetStartCenDirWRTStartDiskNo(RawOperator.readLongFromLittleEndian(longBuffer, 0));

			// Zip64 extensible data sector
			long extDataSize = zip64EndCentralDirectoryRecord.getRecordSize() - 44L;
			if (extDataSize > 0) {
				byte[] extensibleDataSector = new byte[(int) extDataSize];
				input.read(extensibleDataSector);
				this.zip64EndCentralDirectoryRecord.setExtensibleDataSector(extensibleDataSector);
			}
			
			if (this.zip64EndCentralDirectoryRecord.getIndex() > 0) {
				this.splitArchive = true;
			} else {
				this.splitArchive = false;
			}
		} catch (IOException e) {
			throw new ZipException(e);
		}
	}
	
	private static void readAndSaveAESExtraDataRecord(FileHeader fileHeader) throws ZipException {
		if (fileHeader == null) {
			throw new ZipException("File header is null!");
		}

		if (fileHeader.getExtraDataRecords() != null && fileHeader.getExtraDataRecords().size() > 0) {
			for (ExtraDataRecord extraDataRecord : fileHeader.getExtraDataRecords()) {
				if (extraDataRecord != null) {
					if (extraDataRecord.getHeader() == ZipConstants.AESSIG) {
						if (extraDataRecord.getDataContent() == null) {
							throw new ZipException("Corrput AES extra data records");
						}

						AESExtraDataRecord aesExtraDataRecord = new AESExtraDataRecord();
						
						aesExtraDataRecord.setSignature(ZipConstants.AESSIG);
						aesExtraDataRecord.setDataSize(extraDataRecord.getDataSize());
						
						byte[] aesData = extraDataRecord.getDataContent();
						aesExtraDataRecord.setVersionNumber(RawOperator.readShortFromLittleEndian(aesData, 0));
						
						byte[] vendorIDBuffer = new byte[2];
						System.arraycopy(aesData, 2, vendorIDBuffer, 0, 2);
						aesExtraDataRecord.setVendorID(new String(vendorIDBuffer));
						aesExtraDataRecord.setAesStrength((int) (aesData[4] & 0xFF));
						aesExtraDataRecord.setCompressionMethod(RawOperator.readShortFromLittleEndian(aesData, 5));

						fileHeader.setAesExtraDataRecord(aesExtraDataRecord);
						fileHeader.setEncryptionMethod(ZipConstants.ENC_METHOD_AES);
						break;
					}
				}
			}
		}
	}

	private static Zip64ExtendInfo readZip64ExtendInfo(List<ExtraDataRecord> extraDataRecords, long originalSize,
			long compressedSize, long offsetLocalHeader, int diskNumberStart) throws ZipException {
		for (ExtraDataRecord extraDataRecord : extraDataRecords) {
			Zip64ExtendInfo zip64ExtendInfo = new Zip64ExtendInfo();
			if (extraDataRecord.getHeader() == 0x0001) {
				if (extraDataRecord.getDataSize() <= 0) {
					break;
				}

				byte[] intBuffer = new byte[4];
				byte[] longBuffer = new byte[8];
				int count = 0;
				boolean addValue = false;

				if (((originalSize & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
					System.arraycopy(extraDataRecord.getDataContent(), count, longBuffer, 0, 8);
					zip64ExtendInfo.setOriginalSize(RawOperator.readLongFromLittleEndian(longBuffer, 0));
					count += 8;
					addValue = true;
				}

				if (((compressedSize & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
					System.arraycopy(extraDataRecord.getDataContent(), count, longBuffer, 0, 8);
					zip64ExtendInfo.setCompressedSize(RawOperator.readLongFromLittleEndian(longBuffer, 0));
					count += 8;
					addValue = true;
				}

				if (((offsetLocalHeader & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
					System.arraycopy(extraDataRecord.getDataContent(), count, longBuffer, 0, 8);
					zip64ExtendInfo.setOffsetLocalHeader(RawOperator.readLongFromLittleEndian(longBuffer, 0));
					count += 8;
					addValue = true;
				}

				if (((diskNumberStart & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
					System.arraycopy(extraDataRecord.getDataContent(), count, intBuffer, 0, 4);
					zip64ExtendInfo.setDiskNumberStart(RawOperator.readIntFromLittleEndian(intBuffer, 0));
					count += 8;
					addValue = true;
				}

				if (addValue) {
					return zip64ExtendInfo;
				}

				break;
			}
		}

		return null;
	}

	private static void readAndSaveZip64ExtendInfo(FileHeader fileHeader) throws ZipException {
		if (fileHeader == null) {
			throw new ZipException("File header is null");
		}
		if (fileHeader instanceof GeneralFileHeader) {
			if (fileHeader.getExtraDataRecords() != null && fileHeader.getExtraDataRecords().size() > 0) {
				Zip64ExtendInfo zip64ExtendInfo = readZip64ExtendInfo(fileHeader.getExtraDataRecords(),
						fileHeader.getOriginalSize(), fileHeader.getCompressedSize(),
						((GeneralFileHeader) fileHeader).getOffsetLocalHeader(),
						((GeneralFileHeader) fileHeader).getDiskNumberStart());
				if (zip64ExtendInfo != null) {
					fileHeader.setZip64ExtendInfo(zip64ExtendInfo);
					if (zip64ExtendInfo.getOriginalSize() != -1) {
						fileHeader.setOriginalSize(zip64ExtendInfo.getOriginalSize());
					}

					if (zip64ExtendInfo.getCompressedSize() != -1) {
						fileHeader.setCompressedSize(zip64ExtendInfo.getCompressedSize());
					}

					if (zip64ExtendInfo.getOffsetLocalHeader() != -1) {
						((GeneralFileHeader) fileHeader).setOffsetLocalHeader(zip64ExtendInfo.getOffsetLocalHeader());
					}

					if (zip64ExtendInfo.getDiskNumberStart() != -1) {
						((GeneralFileHeader) fileHeader).setDiskNumberStart(zip64ExtendInfo.getDiskNumberStart());
					}
				}
			}
		} else if (fileHeader instanceof LocalFileHeader) {
			if (fileHeader.getExtraDataRecords() == null || fileHeader.getExtraDataRecords().size() == 0) {
				return;
			}

			Zip64ExtendInfo zip64ExtendInfo = readZip64ExtendInfo(fileHeader.getExtraDataRecords(),
					fileHeader.getOriginalSize(), fileHeader.getCompressedSize(), Globals.DEFAULT_VALUE_LONG,
					Globals.DEFAULT_VALUE_INT);
			if (zip64ExtendInfo != null) {
				fileHeader.setZip64ExtendInfo(zip64ExtendInfo);
				if (zip64ExtendInfo.getOriginalSize() != -1) {
					fileHeader.setOriginalSize(zip64ExtendInfo.getOriginalSize());
				}

				if (zip64ExtendInfo.getCompressedSize() != -1) {
					fileHeader.setCompressedSize(zip64ExtendInfo.getCompressedSize());
				}
			}
		} else {
			throw new ZipException("Unknown file header");
		}
	}

	private static List<ExtraDataRecord> readExtraDataRecords(byte[] extraFieldBuffer, int extraFieldLength)
			throws ZipException {
		int count = 0;
		List<ExtraDataRecord> extraDataRecords = new ArrayList<ExtraDataRecord>();

		while (count < extraFieldLength) {
			ExtraDataRecord extraDataRecord = new ExtraDataRecord();
			
			extraDataRecord.setHeader(RawOperator.readShortFromLittleEndian(extraFieldBuffer, count));

			count += 2;

			int dataSize = RawOperator.readShortFromLittleEndian(extraFieldBuffer, count);

			if ((dataSize + 2) > extraFieldLength) {
				dataSize = RawOperator.readShortFromBigEndian(extraFieldBuffer, count);
				if ((dataSize + 2) > extraFieldLength) {
					break;
				}
			}

			extraDataRecord.setDataSize(dataSize);
			count += 2;

			if (dataSize > 0) {
				byte[] dataContent = new byte[dataSize];
				System.arraycopy(extraFieldBuffer, count, dataContent, 0, dataSize);
				extraDataRecord.setDataContent(dataContent);
			}

			count += dataSize;
			extraDataRecords.add(extraDataRecord);
		}

		if (extraDataRecords.size() > 0) {
			return extraDataRecords;
		}
		
		return null;
	}

	private static int countNumberOfFileHeaderEntriesOnDisk(List<GeneralFileHeader> fileHeaders, int numOfDisk)
			throws ZipException {
		if (fileHeaders == null) {
			throw new ZipException("file headers are null, cannot calculate number of entries on this disk");
		}

		int noEntries = 0;
		for (GeneralFileHeader generalFileHeader : fileHeaders) {
			if (generalFileHeader.getDiskNumberStart() == numOfDisk) {
				noEntries++;
			}
		}
		return noEntries;
	}

	private static byte[] readLongByteFromIntByte(byte[] intByte) throws ZipException {
		if (intByte == null) {
			throw new ZipException("int bytes is null");
		}

		if (intByte.length != 4) {
			throw new ZipException("Invalid byte length");
		}

		byte[] longBuffer = { intByte[0], intByte[1], intByte[2], intByte[3], 0, 0, 0, 0 };
		return longBuffer;
	}

	private static int readIntFromDataInput(NervousyncRandomAccessFile input, byte[] bytes) throws ZipException {
		try {
			input.read(bytes, 0, 4);
		} catch (IOException e) {
			throw new ZipException(e);
		}
		return RawOperator.readIntFromLittleEndian(bytes, 0);
	}

	private static void setFileReadOnly(File file) throws ZipException {
		if (file == null) {
			throw new ZipException("input file is null. cannot set read only file attribute");
		}
		
		if (file.exists()) {
			file.setReadOnly();
		}
	}
	
	private static void setFileLastModify(File file, long lastModify) throws ZipException {
		if (file == null) {
			throw new ZipException("input file is null. cannot set read only file attribute");
		}
		
		if (lastModify < 0L) {
			throw new ZipException("last modify time invalid");
		}
		
		if (file.exists()) {
			file.setLastModified(lastModify);
		}
	}
}
