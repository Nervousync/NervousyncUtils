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
package org.nervousync.zip;

import org.nervousync.commons.Globals;
import org.nervousync.commons.io.StandardFile;
import org.nervousync.exceptions.crypto.CryptoException;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.utils.*;
import org.nervousync.zip.crypto.Decryptor;
import org.nervousync.zip.crypto.impl.aes.AESDecryptor;
import org.nervousync.zip.crypto.impl.aes.AESEngine;
import org.nervousync.zip.crypto.impl.standard.StandardDecryptor;
import org.nervousync.zip.io.SplitOutputStream;
import org.nervousync.zip.io.ZipOutputStream;
import org.nervousync.zip.io.input.InflaterInputStream;
import org.nervousync.zip.io.input.PartInputStream;
import org.nervousync.zip.io.input.ZipInputStream;
import org.nervousync.zip.models.AESExtraDataRecord;
import org.nervousync.zip.models.ArchiveExtraDataRecord;
import org.nervousync.zip.models.ExtraDataRecord;
import org.nervousync.zip.models.Zip64ExtendInfo;
import org.nervousync.zip.models.central.*;
import org.nervousync.zip.models.header.FileHeader;
import org.nervousync.zip.models.header.GeneralFileHeader;
import org.nervousync.zip.models.header.LocalFileHeader;
import org.nervousync.zip.models.header.utils.HeaderOperator;
import org.nervousync.zip.options.ZipOptions;

import java.io.*;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Zip File
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 28, 2017 5:01:20 PM $
 */
public final class ZipFile implements Cloneable {

	private final byte[] EMPTY_SHORT_BUFFER = {0, 0};
	private final byte[] EMPTY_INT_BUFFER = {0, 0, 0, 0};

	/**
	 * Zip file path
	 */
	private final String filePath;
	/**
	 * Charset encoding
	 */
	private final String charsetEncoding;
	private boolean numberFormattedName = Boolean.FALSE;
	/**
	 * List of local file headers
	 */
	private List<LocalFileHeader> localFileHeaderList = null;
	/**
	 * Record of archive extra data
	 *
	 * @see ArchiveExtraDataRecord
	 */
	private ArchiveExtraDataRecord archiveExtraDataRecord = null;
	/**
	 * Object of central directory
	 *
	 * @see CentralDirectory
	 */
	private CentralDirectory centralDirectory = null;
	/**
	 * Record of end central directory
	 *
	 * @see EndCentralDirectoryRecord
	 */
	private EndCentralDirectoryRecord endCentralDirectoryRecord = null;
	/**
	 * Locator of Zip64 end central directory
	 *
	 * @see Zip64EndCentralDirectoryLocator
	 */
	private Zip64EndCentralDirectoryLocator zip64EndCentralDirectoryLocator = null;
	/**
	 * Record of Zip64 end central directory
	 *
	 * @see Zip64EndCentralDirectoryRecord
	 */
	private Zip64EndCentralDirectoryRecord zip64EndCentralDirectoryRecord = null;
	/**
	 * Decryptor instance
	 *
	 * @see Decryptor
	 */
	private Decryptor decryptor = null;
	/**
	 * Archive is split file status
	 */
	private boolean splitArchive;
	/**
	 * Maximum length of split item
	 */
	private long splitLength;
	private int splitCount = Globals.INITIALIZE_INT_VALUE;
	/**
	 * Is Zip64 format
	 */
	private boolean zip64Format = Boolean.FALSE;

	/**
	 * ZipFile Constructor
	 *
	 * @param filePath        Zip file path
	 * @param charsetEncoding Charset encoding
	 * @throws ZipException Zip file cannot access and read
	 */
	private ZipFile(String filePath, String charsetEncoding) throws ZipException {
		this(filePath, charsetEncoding, Boolean.FALSE, Globals.DEFAULT_VALUE_LONG);
	}

	/**
	 * ZipFile Constructor
	 *
	 * @param filePath        Zip file path
	 * @param charsetEncoding Charset encoding
	 * @param splitArchive    Split archive
	 * @param splitLength     Split length
	 */
	private ZipFile(String filePath, String charsetEncoding, boolean splitArchive, long splitLength)
			throws ZipException {
		this.filePath = filePath;
		this.charsetEncoding = charsetEncoding == null ? Globals.DEFAULT_ENCODING : charsetEncoding;
		this.splitArchive = splitArchive;
		this.splitLength = splitLength;
		if (FileUtils.isExists(this.filePath)) {
			if (!FileUtils.canRead(this.filePath)) {
				throw new ZipException(0x0000001B001AL, "Read_Access_Failed_Zip_Error");
			}
			this.readHeaders();
		}
	}

	/**
	 * Open zip file
	 *
	 * @param filePath the file path
	 * @return the zip file
	 * @throws ZipException the zip exception
	 */
	public static ZipFile openZipFile(String filePath) throws ZipException {
		return openZipFile(filePath, Globals.DEFAULT_ENCODING);
	}

	/**
	 * Open zip file
	 *
	 * @param filePath        the file path
	 * @param charsetEncoding the charset encoding
	 * @return the zip file
	 * @throws ZipException the zip exception
	 */
	public static ZipFile openZipFile(String filePath, String charsetEncoding) throws ZipException {
		return new ZipFile(filePath, charsetEncoding);
	}

	/**
	 * Create the zip file using default character encoding
	 *
	 * @param filePath   Zip file path
	 * @param zipOptions Zip options
	 * @param addFiles   List of files in the zip file
	 * @return ZipFile instance
	 * @throws ZipException If the target file exists or add files is null or empty
	 * @see ZipOptions
	 */
	public static ZipFile createZipFile(String filePath, ZipOptions zipOptions, String... addFiles) throws ZipException {
		return ZipFile.createZipFile(filePath, zipOptions, Boolean.FALSE, Globals.DEFAULT_VALUE_LONG, addFiles);
	}

	/**
	 * Create a split archive zip file
	 *
	 * @param filePath     Zip file path
	 * @param zipOptions   Zip options
	 * @param splitArchive Status of split archive
	 * @param splitLength  Maximum size of the split file
	 * @param addFiles     List of files in the zip file
	 * @return ZipFile instance
	 * @throws ZipException If the target file was existed or add files is null or empty
	 * @see ZipOptions
	 */
	public static ZipFile createZipFile(String filePath, ZipOptions zipOptions,
	                                    boolean splitArchive, long splitLength, String... addFiles) throws ZipException {
		ZipFile.checkFilePath(filePath);
		if (addFiles == null || addFiles.length == 0) {
			throw new ZipException(0x0000001B001BL, "Null_Path_Zip_Error");
		}

		ZipFile zipFile = ZipFile.createZipFile(filePath, zipOptions.getCharsetEncoding(), splitArchive, splitLength);
		zipFile.addFiles(Arrays.asList(addFiles), zipOptions);

		return zipFile;
	}

	private static void checkFilePath(String filePath) throws ZipException {
		if (StringUtils.isEmpty(filePath)) {
			throw new ZipException(0x0000001B001BL, "Null_Path_Zip_Error");
		}
		if (FileUtils.isExists(filePath)) {
			throw new ZipException(0x0000001B001CL, "Exists_Path_Zip_Error");
		}
	}

	/**
	 * Create the zip file and add folder to the zip file
	 *
	 * @param filePath   Zip file path
	 * @param zipOptions Zip options
	 * @param folderPath Folder will add to the zip file
	 * @return ZipFile instance
	 * @throws ZipException If the target file was existed or the folder is empty
	 * @see ZipOptions
	 */
	public static ZipFile createZipFileFromFolder(final String filePath, final ZipOptions zipOptions,
	                                              final String folderPath) throws ZipException {
		return ZipFile.createZipFileFromFolder(filePath, zipOptions,
				Boolean.FALSE, Globals.DEFAULT_VALUE_LONG, folderPath);
	}

	/**
	 * Create the zip file and add folder to the zip file
	 *
	 * @param filePath     Zip file path
	 * @param zipOptions   Zip options
	 * @param splitArchive Status of split archive
	 * @param splitLength  Maximum size of the split file
	 * @param folderPath   Folder will add to the zip file
	 * @return ZipFile instance
	 * @throws ZipException If the target file was existed or the folder is empty
	 * @see ZipOptions
	 */
	public static ZipFile createZipFileFromFolder(String filePath, ZipOptions zipOptions,
	                                              boolean splitArchive, long splitLength, String folderPath) throws ZipException {
		ZipFile.checkFilePath(filePath);

		if (StringUtils.isEmpty(folderPath)) {
			throw new ZipException(0x0000001B001BL, "Null_Path_Zip_Error");
		}

		ZipFile zipFile = ZipFile.createZipFile(filePath, zipOptions.getCharsetEncoding(), splitArchive, splitLength);
		zipFile.addFolder(folderPath, zipOptions, Boolean.FALSE);
		if (zipOptions.getPassword() != null) {
			zipFile.setPassword(zipOptions.getPassword());
		}
		return zipFile;
	}

	/**
	 * Generate the entity path
	 *
	 * @param file            Which file path will add to the zip file.
	 * @param rootFolderInZip prefix path of the zip file
	 * @param rootFolderPath  root path of folder
	 * @return Generated entry path
	 * @throws ZipException given file is null
	 */
	public static String getRelativeFileName(String file, String rootFolderInZip, String rootFolderPath) throws ZipException {
		if (StringUtils.isEmpty(file)) {
			throw new ZipException(0x0000001B001EL, "Null_Input_Path_Zip_Error");
		}

		String fileName;

		if (StringUtils.notBlank(rootFolderPath)) {
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
						Globals.DEFAULT_ZIP_PAGE_SEPARATOR);
				if (!tmpFileName.endsWith(Globals.DEFAULT_ZIP_PAGE_SEPARATOR)) {
					tmpFileName += Globals.DEFAULT_ZIP_PAGE_SEPARATOR;
				}
			} else {
				String bkFileName = tmpFileName.substring(0, tmpFileName.lastIndexOf(tmpFile.getName()));
				bkFileName = StringUtils.replace(bkFileName, Globals.DEFAULT_PAGE_SEPARATOR,
						Globals.DEFAULT_ZIP_PAGE_SEPARATOR);
				tmpFileName = bkFileName + tmpFile.getName();
			}

			fileName = tmpFileName;
		} else {
			File relFile = new File(file);
			if (relFile.isDirectory()) {
				fileName = relFile.getName() + Globals.DEFAULT_ZIP_PAGE_SEPARATOR;
			} else {
				fileName = getFileNameFromFilePath(relFile);
			}
		}

		if (StringUtils.isEmpty(rootFolderInZip)) {
			fileName = rootFolderInZip + fileName;
		}

		if (StringUtils.isEmpty(fileName)) {
			throw new ZipException(0x0000001B0020L, "Determining_File_Name_Zip_Error");
		}

		return fileName;
	}

	/**
	 * Get the entry path list
	 *
	 * @return entry path list
	 */
	public List<String> entryList() {
		return this.entryList(Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * Get the entry path list
	 *
	 * @param regex the regex
	 * @return entry path list
	 */
	public List<String> entryList(String regex) {
		List<String> entryList = new ArrayList<>();
		if (StringUtils.isEmpty(regex)) {
			this.centralDirectory.getFileHeaders()
					.forEach(generalFileHeader -> entryList.add(generalFileHeader.getEntryPath()));
		} else {
			this.centralDirectory.getFileHeaders()
					.stream()
					.filter(generalFileHeader -> StringUtils.matches(generalFileHeader.getEntryPath(), regex))
					.forEach(generalFileHeader -> entryList.add(generalFileHeader.getEntryPath()));
		}
		return entryList;
	}

	/**
	 * Check the given entry path is existed
	 *
	 * @param entryPath entry path
	 * @return check result
	 */
	public boolean isEntryExists(String entryPath) {
		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			if (generalFileHeader.getEntryPath().equals(entryPath)) {
				return true;
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Read entry length
	 *
	 * @param entryPath Check the entry path
	 * @return Entry length
	 * @throws ZipException file list is empty or zipOptions is null
	 */
	public int readEntryLength(String entryPath) throws ZipException {
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
		}
		return this.readEntryLength(this.retrieveGeneralFileHeader(entryPath));
	}

	/**
	 * Read entry data bytes
	 *
	 * @param entryPath Check the entry path
	 * @return entry data bytes
	 * @throws ZipException file list is empty or zipOptions is null
	 */
	public byte[] readEntry(String entryPath) throws ZipException {
		return this.readEntry(entryPath, Globals.DEFAULT_VALUE_LONG, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * Read entry data bytes
	 *
	 * @param entryPath  Check the entry path
	 * @param position   the position
	 * @param readLength the read length
	 * @return entry data bytes
	 * @throws ZipException file list is empty or zipOptions is null
	 */
	public byte[] readEntry(String entryPath, long position, int readLength) throws ZipException {
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
		}

		return this.readEntry(this.retrieveGeneralFileHeader(entryPath), position, readLength);
	}

	/**
	 * Open input stream by given entry path
	 *
	 * @param entryPath The zip entry path
	 * @return Opened input stream
	 * @throws ZipException File is split archive
	 */
	public InputStream entryInputStream(String entryPath) throws ZipException {
		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
		}

		return this.openInputStream(this.retrieveGeneralFileHeader(entryPath));
	}

	/**
	 * Add file to zip file
	 *
	 * @param file Target file will add to zip file
	 * @throws ZipException file list is empty or zipOptions is null
	 */
	public void addFile(File file) throws ZipException {
		this.addFile(file, ZipOptions.newOptions());
	}

	/**
	 * Add file to zip file with zip options
	 *
	 * @param file       Target file will add to zip file
	 * @param zipOptions Zip options
	 * @throws ZipException file list is empty or zipOptions is null
	 * @see ZipOptions
	 */
	public void addFile(File file, ZipOptions zipOptions) throws ZipException {
		this.addFiles(Collections.singletonList(file.getAbsolutePath()), zipOptions);
	}

	/**
	 * Add files to zip file
	 *
	 * @param fileList the file list
	 * @throws ZipException file list is empty or zipOptions is null
	 */
	public void addFiles(List<String> fileList) throws ZipException {
		this.addFiles(fileList, ZipOptions.newOptions());
	}

	/**
	 * Add files to zip file with zip options
	 *
	 * @param fileList   the file list
	 * @param zipOptions Zip options
	 * @throws ZipException file list is empty or zipOptions is null
	 * @see ZipOptions
	 */
	public void addFiles(List<String> fileList, ZipOptions zipOptions) throws ZipException {
		this.appendCheck(zipOptions);
		this.addFilesToZip(fileList, zipOptions);
	}

	private void appendCheck(ZipOptions zipOptions) throws ZipException {
		if (zipOptions == null) {
			throw new ZipException(0x0000001B0021L, "Null_Options_Zip_Error");
		}

		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
		}
	}

	/**
	 * Add InputStream to zip file
	 *
	 * @param inputStream Entity input stream
	 * @throws ZipException Input stream is null
	 */
	public void addStream(InputStream inputStream) throws ZipException {
		this.addStream(inputStream, ZipOptions.newOptions());
	}

	/**
	 * Add InputStream to zip file with zip options
	 *
	 * @param inputStream Entity input stream
	 * @param zipOptions  Zip options
	 * @throws ZipException input stream is null or zipOptions is null
	 * @see ZipOptions
	 */
	public void addStream(InputStream inputStream, ZipOptions zipOptions) throws ZipException {
		if (inputStream == null) {
			throw new ZipException(0x0000001B0022L, "Null_Input_Stream_Zip_Error");
		}

		this.appendCheck(zipOptions);
		this.addStreamToZip(inputStream, zipOptions);
	}

	/**
	 * Add folder to zip file
	 *
	 * @param folderPath Target folder path will add to zip file
	 * @throws ZipException folder path is null or folder was not existed
	 */
	public void addFolder(String folderPath) throws ZipException {
		this.addFolder(folderPath, ZipOptions.newOptions(), true);
	}

	/**
	 * Add folder to zip file with zip options
	 *
	 * @param folderPath Target folder path will add to zip file
	 * @param zipOptions Zip options
	 * @throws ZipException folder path is null or folder was not existed, or zipOptions is null
	 * @see ZipOptions
	 */
	public void addFolder(String folderPath, ZipOptions zipOptions) throws ZipException {
		this.addFolder(folderPath, zipOptions, true);
	}

	/**
	 * Extract all entries in zip file to the target extract file path
	 *
	 * @param destPath Target extract file path
	 * @throws ZipException Target path is null or file exists
	 */
	public void extractAll(String destPath) throws ZipException {
		this.extractAll(destPath, Boolean.FALSE);
	}

	/**
	 * Extract all entries in zip file to the target extract file path
	 *
	 * @param destPath       Target extract file path
	 * @param ignoreFileAttr Status of process file attribute
	 * @throws ZipException Target path is null or zip file invalid
	 */
	public void extractAll(String destPath, boolean ignoreFileAttr) throws ZipException {
		if (StringUtils.isEmpty(destPath)) {
			throw new ZipException("Destination path is null!");
		}

		if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null) {
			throw new ZipException("Invalid central directory in zip entity");
		}

		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			this.extractFile(generalFileHeader, destPath, ignoreFileAttr);
		}
	}

	/**
	 * Extract entry path file to the target extra file path
	 *
	 * @param entryPath Which entry path will extract
	 * @param destPath  Target extract file path
	 * @throws ZipException Target path is null or entry path is null/not exists or zip file invalid
	 */
	public void extractFile(String entryPath, String destPath) throws ZipException {
		this.extractFile(entryPath, destPath, Boolean.FALSE);
	}

	/**
	 * Extract entry path file to the target extra file path
	 *
	 * @param entryPath      Which entry path will extract
	 * @param destPath       Target extract file path
	 * @param ignoreFileAttr Status of process file attribute
	 * @throws ZipException Target path is null or entry path is null/not exists or zip file invalid
	 */
	public void extractFile(String entryPath, String destPath, boolean ignoreFileAttr) throws ZipException {
		if (StringUtils.isEmpty(entryPath)) {
			throw new ZipException("extract file name is null!");
		}

		if (StringUtils.isEmpty(destPath)) {
			throw new ZipException("Destination path is null!");
		}

		this.extractFile(this.retrieveGeneralFileHeader(entryPath), destPath, ignoreFileAttr);
	}

	/**
	 * Remove entry folder from zip file
	 *
	 * @param folderPath Which entry folder will be removed
	 * @throws ZipException Given the path was not a directory
	 */
	public void removeFolder(String folderPath) throws ZipException {
		if (this.isDirectory(folderPath)) {
			this.removeFilesIfExists(this.listFolderGeneralFileHeaders(folderPath));
			return;
		}
		throw new ZipException("Entry path: " + folderPath + " is not directory entry!");
	}

	/**
	 * Remove the entry path from zip file
	 *
	 * @param entryPath Which entry path will be removed
	 * @throws ZipException the given entry path is null or zip file was not existed
	 */
	public void removeExistsEntry(String entryPath) throws ZipException {
		this.removeExistsEntries(entryPath);
	}

	/**
	 * Remove entry paths from zip file
	 *
	 * @param existsEntries Which entry paths will be removed
	 * @throws ZipException the given entry path is null or zip file was not existed
	 */
	public void removeExistsEntries(String... existsEntries) throws ZipException {
		if (existsEntries == null) {
			throw new ZipException("Input entry path is null!");
		}

		if (FileUtils.isExists(this.filePath) && this.splitArchive) {
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
		}

		this.removeFilesIfExists(Arrays.asList(existsEntries));

		if (this.isNoEntry()) {
			FileUtils.removeFile(this.filePath);
		}
	}

	/**
	 * Setting password
	 *
	 * @param password password
	 * @throws ZipException given password is null
	 */
	public void setPassword(String password) throws ZipException {
		if (StringUtils.isEmpty(password)) {
			throw new ZipException(0x0000001B0006L, "Invalid_Password_Zip_Error");
		}
		this.setPassword(password.toCharArray());
	}

	/**
	 * Setting password
	 *
	 * @param password password char arrays
	 * @throws ZipException given password is null
	 */
	public void setPassword(char[] password) throws ZipException {
		if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null) {
			throw new ZipException("Invalid zip file");
		}

		for (int i = 0; i < this.centralDirectory.getFileHeaders().size(); i++) {
			if (this.centralDirectory.getFileHeaders().get(i) != null
					&& this.centralDirectory.getFileHeaders().get(i).isEncrypted()) {
				this.centralDirectory.getFileHeaders().get(i).setPassword(password);
			}
		}
	}

	/**
	 * Setting comment
	 *
	 * @param comment comment information
	 * @throws ZipException comment is null or zip file was not existed
	 */
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

		byte[] commentBytes;
		int commentLength;

		try {
			commentBytes = comment.getBytes(this.charsetEncoding);
		} catch (UnsupportedEncodingException e) {
			throw new ZipException("Charset encoding not supported! ", e);
		}

		commentLength = commentBytes.length;

		if (commentLength > Globals.MAX_ALLOWED_ZIP_COMMENT_LENGTH) {
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
		} catch (IOException e) {
			throw new ZipException("Write comment information error! ", e);
		} finally {
			IOUtils.closeStream(outputStream);
		}
	}

	/**
	 * Read comment
	 *
	 * @return Read comment content
	 * @throws ZipException zip file was not existed
	 */
	public String getComment() throws ZipException {
		return this.getComment(this.charsetEncoding);
	}

	/**
	 * Read comment by given charset encoding
	 *
	 * @param charset charset encoding
	 * @return Read comment content
	 * @throws ZipException zip file was not exists, zip file does not include comment content or charset encoding was not supported
	 */
	public String getComment(String charset) throws ZipException {
		if (StringUtils.isEmpty(charset)) {
			charset = Globals.DEFAULT_SYSTEM_CHARSET;
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
			throw new ZipException("Charset encoding not supported! ", e);
		}
	}

	/**
	 * Merge split files and write merge file to the target output path
	 *
	 * @param outputPath Merge file output path
	 * @throws ZipException Zip file was not a split file or zip file invalid
	 */
	public void mergeSplitFile(String outputPath) throws ZipException {
		if (!this.splitArchive) {
			throw new ZipException("archive not a split zip file");
		}

		if (this.endCentralDirectoryRecord.getIndexOfThisDisk() <= 0) {
			throw new ZipException("corrupt zip entity, archive not a split zip file");
		}

		OutputStream outputStream = null;
		StandardFile input = null;
		List<Long> sizeList = new ArrayList<>();
		long totalWriteBytes = 0L;
		boolean removeSplitSig = Boolean.FALSE;

		try {
			outputStream = this.openMergeOutputStream(outputPath);

			for (int i = 0; i <= this.endCentralDirectoryRecord.getIndexOfThisDisk(); i++) {
				IOUtils.closeStream(input);
				input = this.openSplitFile(i);
				int start = 0;

				if (i == 0) {
					if (this.centralDirectory != null
							&& this.centralDirectory.getFileHeaders() != null
							&& !this.centralDirectory.getFileHeaders().isEmpty()) {
						byte[] buffer = new byte[4];

						input.seek(0L);
						if (input.read(buffer) > 0
								&& RawUtils.readInt(buffer, 0, ByteOrder.LITTLE_ENDIAN) == Globals.EXTSIG) {
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

			ZipFile newFile = (ZipFile) this.clone();
			newFile.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(totalWriteBytes);

			newFile.updateSplitZipEntity(sizeList, removeSplitSig);
			newFile.finalizeZipFileWithoutValidations(outputStream);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Merge split zip file error! ", e);
			}
		} finally {
			IOUtils.closeStream(input);
			IOUtils.closeStream(outputStream);
		}
	}

	/**
	 * Finalize zip file
	 *
	 * @param outputStream Output stream
	 * @throws ZipException Write data bytes to output stream error
	 */
	public void finalizeZipFile(final OutputStream outputStream) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("input parameters is null, cannot finalize zip file");
		}

		this.processHeaderData(outputStream);

		long offsetCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();

		List<String> headerBytesList = new ArrayList<>();

		int sizeOfCentralDirectory = this.writeCentralDirectory(outputStream, headerBytesList);

		if (this.zip64Format) {
			this.checkZip64Format();
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

		this.writeEndOfCentralDirectoryRecord(sizeOfCentralDirectory, offsetCentralDirectory, headerBytesList);
		this.writeZipHeaderBytes(outputStream, HeaderOperator.convertByteArrayListToByteArray(headerBytesList));
	}

	/**
	 * Gets central directory.
	 *
	 * @return the centralDirectory
	 */
	public CentralDirectory getCentralDirectory() {
		return centralDirectory;
	}

	/**
	 * Sets central directory.
	 *
	 * @param centralDirectory the centralDirectory to set
	 */
	public void setCentralDirectory(CentralDirectory centralDirectory) {
		this.centralDirectory = centralDirectory;
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
	 * Gets the local file header list.
	 *
	 * @return the localFileHeaderList
	 */
	public List<LocalFileHeader> getLocalFileHeaderList() {
		return localFileHeaderList;
	}

	/**
	 * Sets the local file header list.
	 *
	 * @param localFileHeaderList the localFileHeaderList to set
	 */
	public void setLocalFileHeaderList(List<LocalFileHeader> localFileHeaderList) {
		this.localFileHeaderList = localFileHeaderList;
	}

	/**
	 * Gets archive extra data record.
	 *
	 * @return the archiveExtraDataRecord
	 */
	public ArchiveExtraDataRecord getArchiveExtraDataRecord() {
		return archiveExtraDataRecord;
	}

	/**
	 * Sets archive extra data record.
	 *
	 * @param archiveExtraDataRecord the archiveExtraDataRecord to set
	 */
	public void setArchiveExtraDataRecord(ArchiveExtraDataRecord archiveExtraDataRecord) {
		this.archiveExtraDataRecord = archiveExtraDataRecord;
	}

	/**
	 * Gets end central directory record.
	 *
	 * @return the endCentralDirectoryRecord
	 */
	public EndCentralDirectoryRecord getEndCentralDirectoryRecord() {
		return endCentralDirectoryRecord;
	}

	/**
	 * Sets end central directory record.
	 *
	 * @param endCentralDirectoryRecord the endCentralDirectoryRecord to set
	 */
	public void setEndCentralDirectoryRecord(EndCentralDirectoryRecord endCentralDirectoryRecord) {
		this.endCentralDirectoryRecord = endCentralDirectoryRecord;
	}

	/**
	 * Is split archive boolean.
	 *
	 * @return the boolean
	 */
	public boolean isSplitArchive() {
		return this.splitArchive;
	}

	/**
	 * Sets split archive.
	 *
	 * @param splitArchive the splitArchive to set
	 */
	public void setSplitArchive(boolean splitArchive) {
		this.splitArchive = splitArchive;
	}

	/**
	 * Sets split length.
	 *
	 * @param splitLength the splitLength to set
	 */
	public void setSplitLength(long splitLength) {
		this.splitLength = splitLength;
	}

	private static ZipFile createZipFile(String filePath, String fileNameCharset,
	                                     boolean splitArchive, long splitLength) throws ZipException {
		ZipFile.checkFilePath(filePath);
		return new ZipFile(filePath, fileNameCharset, splitArchive, splitLength);
	}

	private void addFolder(String folderPath, ZipOptions zipOptions, boolean checkSplitArchive) throws ZipException {
		if (folderPath == null) {
			throw new ZipException(0x0000001B001EL, "Null_Input_Path_Zip_Error");
		}

		if (zipOptions == null) {
			throw new ZipException(0x0000001B0021L, "Null_Options_Zip_Error");
		}

		if (checkSplitArchive && this.splitArchive) {
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
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
		return this.centralDirectory.getFileHeaders().isEmpty();
	}

	private boolean isDirectory(String entryPath) throws ZipException {
		GeneralFileHeader generalFileHeader = this.retrieveGeneralFileHeader(entryPath);
		if (generalFileHeader != null) {
			return generalFileHeader.isDirectory();
		}
		return Boolean.FALSE;
	}

	private List<String> listFolderGeneralFileHeaders(String folderPath) throws ZipException {
		if (StringUtils.notBlank(folderPath)) {
			if (this.centralDirectory == null) {
				throw new ZipException("central directory is null, cannot determine file header with exact match for entry path: " + folderPath);
			}
			return this.centralDirectory.listFolderGeneralFileHeaders(folderPath);
		}
		throw new ZipException("file name is null, cannot determine file header for entry path: " + folderPath);
	}

	private GeneralFileHeader retrieveGeneralFileHeader(String entryPath) throws ZipException {
		if (StringUtils.notBlank(entryPath)) {
			if (this.centralDirectory == null) {
				throw new ZipException("central directory is null, cannot determine file header with exact match for entry path: " + entryPath);
			}
			return this.centralDirectory.retrieveGeneralFileHeader(entryPath);
		}
		throw new ZipException("file name is null, cannot determine file header for entry path: " + entryPath);
	}

	private void removeFilesIfExists(List<String> entryList) throws ZipException {
		if (this.centralDirectory != null
				&& this.centralDirectory.getFileHeaders() != null
				&& !this.centralDirectory.getFileHeaders().isEmpty()) {
			for (String entryPath : entryList) {
				GeneralFileHeader generalFileHeader = this.retrieveGeneralFileHeader(entryPath);
				if (generalFileHeader != null) {
					this.removeExistsFile(generalFileHeader);
				}
			}
		}
	}

	private ZipOutputStream openOutputStream() throws IOException, ZipException {
		SplitOutputStream splitOutputStream = new SplitOutputStream(this.filePath, this.splitLength);
		ZipOutputStream zipOutputStream = new ZipOutputStream(splitOutputStream, this);
		if (FileUtils.isExists(this.filePath)) {
			if (this.endCentralDirectoryRecord == null) {
				throw new ZipException("invalid end of central directory record");
			}
			splitOutputStream.seek(this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory());
		}
		return zipOutputStream;
	}

	private void addStreamToZip(InputStream inputStream, ZipOptions zipOptions) throws ZipException {
		if (zipOptions == null) {
			throw new ZipException(0x0000001B0021L, "Null_Options_Zip_Error");
		}

		if (inputStream == null) {
			throw new ZipException("No data to added");
		}

		try (ZipOutputStream outputStream = this.openOutputStream()) {
			this.checkOptions(zipOptions);

			byte[] readBuffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
			int readLength;

			outputStream.putNextEntry(null, zipOptions);

			if (!zipOptions.getFileNameInZip().endsWith(Globals.DEFAULT_ZIP_PAGE_SEPARATOR)
					&& !zipOptions.getFileNameInZip().endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				while ((readLength = inputStream.read(readBuffer)) != Globals.DEFAULT_VALUE_INT) {
					outputStream.write(readBuffer, 0, readLength);
				}
			}

			outputStream.closeEntry();
			outputStream.finish();
		} catch (Exception e) {
			throw new ZipException("Add stream to zip error! ", e);
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
			throw new ZipException(0x0000001B001AL, "Read_Access_Failed_Zip_Error");
		}

		if (zipOptions == null) {
			throw new ZipException(0x0000001B0021L, "Null_Options_Zip_Error");
		}

		String rootFolderPath;

		if (zipOptions.isIncludeRootFolder()) {
			try {
				File file = FileUtils.getFile(folderPath);
				rootFolderPath = file.getAbsoluteFile().getParentFile() != null
						? file.getAbsoluteFile().getParentFile().getAbsolutePath() : Globals.DEFAULT_VALUE_STRING;
			} catch (FileNotFoundException e) {
				throw new ZipException("Cannot read folder: " + folderPath);
			}
		} else {
			rootFolderPath = folderPath;
		}

		zipOptions.setDefaultFolderPath(rootFolderPath);

		List<String> fileList = new ArrayList<>();
		try {
			File folder = FileUtils.getFile(folderPath);
			if (zipOptions.isIncludeRootFolder()) {
				fileList.add(folderPath);
			}
			fileList.addAll(FileUtils.listFiles(folder, zipOptions.isReadHiddenFiles(), zipOptions.isIncludeRootFolder()));
		} catch (Exception e) {
			throw new ZipException("Add folder to zip error! ", e);
		}

		this.addFiles(fileList, zipOptions);
	}

	private void checkZip64Format() {
		if (this.zip64EndCentralDirectoryRecord == null) {
			this.zip64EndCentralDirectoryRecord = new Zip64EndCentralDirectoryRecord();
		}

		if (this.zip64EndCentralDirectoryLocator == null) {
			this.zip64EndCentralDirectoryLocator = new Zip64EndCentralDirectoryLocator();
		}
	}

	private void finalizeZipFileWithoutValidations(OutputStream outputStream)
			throws ZipException {
		if (outputStream == null) {
			throw new ZipException("Output stream parameter is null, cannot finalize zip file");
		}

		try {
			List<String> headerBytesList = new ArrayList<>();

			long offsetCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();

			int sizeOfCentralDirectory = this.writeCentralDirectory(outputStream, headerBytesList);

			if (this.zip64Format) {
				this.checkZip64Format();
				this.zip64EndCentralDirectoryLocator
						.setOffsetZip64EndOfCentralDirectoryRecord(offsetCentralDirectory + sizeOfCentralDirectory);
				this.writeZip64EndOfCentralDirectoryRecord(outputStream, sizeOfCentralDirectory,
						offsetCentralDirectory, headerBytesList);
				this.writeZip64EndOfCentralDirectoryLocator(outputStream, headerBytesList);
			}

			this.writeEndOfCentralDirectoryRecord(sizeOfCentralDirectory, offsetCentralDirectory,
					headerBytesList);
			this.writeZipHeaderBytes(outputStream, HeaderOperator.convertByteArrayListToByteArray(headerBytesList));
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Process finalize zip file error! ", e);
			}
		}
	}

	private void extractFile(GeneralFileHeader generalFileHeader, String destPath, boolean ignoreFileAttr)
			throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException(0x0000001B000FL, "Null_General_File_Header_Zip_Error");
		}

		try {
			if (!destPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				destPath += Globals.DEFAULT_PAGE_SEPARATOR;
			}

			if (generalFileHeader.isDirectory()) {
				String targetPath = destPath + generalFileHeader.getEntryPath();
				targetPath = StringUtils.replace(targetPath, Globals.DEFAULT_ZIP_PAGE_SEPARATOR, Globals.DEFAULT_PAGE_SEPARATOR);
				if (!FileUtils.makeDir(targetPath)) {
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
				throw (ZipException) e;
			} else {
				throw new ZipException("Extract zip file error! ", e);
			}
		}
	}

	private void addFilesToZip(List<String> fileList, ZipOptions zipOptions) throws ZipException {
		if (CollectionUtils.isEmpty(fileList)) {
			throw new ZipException("No file to added");
		}

		if (this.endCentralDirectoryRecord == null) {
			this.endCentralDirectoryRecord = new EndCentralDirectoryRecord();
			this.endCentralDirectoryRecord.setSignature(Globals.ENDSIG);
			this.endCentralDirectoryRecord.setIndexOfThisDisk(0);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectory(0);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectoryOnThisDisk(0);
			this.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(0);
		}

		ZipOutputStream outputStream = null;
		InputStream inputStream = null;

		try {
			this.checkOptions(zipOptions);
			List<String> entryList = new ArrayList<>();
			for (String filePath : fileList) {
				entryList.add(ZipFile.getRelativeFileName(filePath,
						zipOptions.getRootFolderInZip(), zipOptions.getDefaultFolderPath()));
			}
			this.removeFilesIfExists(entryList);

			byte[] readBuffer = new byte[Globals.BUFFER_SIZE];
			int readLength;

			outputStream = this.openOutputStream();

			for (String filePath : fileList) {
				ZipOptions fileOptions = (ZipOptions) zipOptions.clone();

				if (!FileUtils.isDirectory(filePath)) {
					if (fileOptions.isEncryptFiles()
							&& fileOptions.getEncryptionMethod() == Globals.ENC_METHOD_STANDARD) {
						fileOptions.setSourceFileCRC(FileUtils.calcFileCRC(filePath));
					}

					if (FileUtils.fileSize(filePath) == 0L) {
						fileOptions.setCompressionMethod(Globals.COMP_STORE);
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
			}

			outputStream.finish();
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Add files to zip error! ", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
			IOUtils.closeStream(outputStream);
		}
	}

	private void checkOptions(ZipOptions zipOptions) throws ZipException {
		if (zipOptions == null) {
			throw new ZipException(0x0000001B0021L, "Null_Options_Zip_Error");
		}

		if (zipOptions.getCompressionMethod() != Globals.COMP_STORE
				&& zipOptions.getCompressionMethod() != Globals.COMP_DEFLATE) {
			throw new ZipException("Unsupported compression type!");
		}

		if (zipOptions.getCompressionMethod() == Globals.COMP_DEFLATE
				&& (zipOptions.getCompressionLevel() < 0 || zipOptions.getCompressionLevel() > 9)) {
			throw new ZipException("invalid compression level. compression level dor deflate should be in the range of 0-9");
		}

		if (zipOptions.isEncryptFiles()) {
			if (zipOptions.getEncryptionMethod() != Globals.ENC_METHOD_STANDARD
					&& zipOptions.getEncryptionMethod() != Globals.ENC_METHOD_STRONG
					&& zipOptions.getEncryptionMethod() != Globals.ENC_METHOD_AES) {
				throw new ZipException(0x0000001B0001L, "Not_Supported_Encryption_Mode_Zip_Error");
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
			throw new ZipException(0x0000001B0018L, "Not_Allow_Update_Files_Zip_Error");
		}

		SplitOutputStream outputStream = null;
		StandardFile input = null;
		boolean success = Boolean.FALSE;
		String tempFileName = this.filePath + System.currentTimeMillis() % 1000L;

		try {
			int indexOfHeader = this.retrieveIndexOfGeneralFileHeader(generalFileHeader);
			if (indexOfHeader < 0) {
				return;
			}

			while (FileUtils.isExists(tempFileName)) {
				tempFileName = this.filePath + System.currentTimeMillis() % 1000L;
			}

			try {
				outputStream = new SplitOutputStream(tempFileName);
			} catch (FileNotFoundException e) {
				throw new ZipException("Not found split file! ", e);
			}

			input = this.createFileHandler(generalFileHeader);

			if (!this.readLocalFileHeader(input, generalFileHeader).verifyPassword(input)) {
				throw new ZipException(0x0000001B000DL, "Wrong_Password_Zip_Error");
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

			for (int i = indexOfHeader; i < this.centralDirectory.getFileHeaders().size(); i++) {
				long offsetLocalHeader = this.centralDirectory.getFileHeaders().get(i).getOffsetLocalHeader();
				if (this.centralDirectory.getFileHeaders().get(i).getZip64ExtendInfo() != null
						&& this.centralDirectory.getFileHeaders().get(i).getZip64ExtendInfo().getOffsetLocalHeader() != Globals.DEFAULT_VALUE_LONG) {
					offsetLocalHeader = this.centralDirectory.getFileHeaders().get(i).getZip64ExtendInfo().getOffsetLocalHeader();
				}

				this.centralDirectory.getFileHeaders().get(i).setOffsetLocalHeader(offsetLocalHeader - (offsetEndOfCompressedFile - offsetLocalFileHeader) - 1);
			}

			this.finalizeZipFile(outputStream);
			success = true;
		} catch (IOException e) {
			throw new ZipException("Remove exists entry from zip file error! ", e);
		} finally {
			IOUtils.closeStream(input);
			IOUtils.closeStream(outputStream);

			if (success) {
				FileUtils.copy(tempFileName, this.filePath);
			}

			if (FileUtils.isExists(tempFileName)) {
				FileUtils.removeFile(tempFileName);
			}
		}
	}

	private int retrieveIndexOfGeneralFileHeader(GeneralFileHeader generalFileHeader) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException(0x0000001B000FL, "Null_General_File_Header_Zip_Error");
		}
		if (this.centralDirectory == null) {
			throw new ZipException("central directory is null, cannot determine index of file header");
		}
		return this.centralDirectory.retrieveIndexOfGeneralFileHeader(generalFileHeader);
	}

	private StandardFile createFileHandler(final GeneralFileHeader generalFileHeader)
			throws FileNotFoundException, ZipException {
		if (StringUtils.notBlank(this.filePath)) {
			if (this.splitArchive) {
				String splitPath = this.filePath.substring(0, this.filePath.lastIndexOf("."));
				if (this.numberFormattedName) {
					int diskNumberStart = Long.valueOf(generalFileHeader.getOffsetLocalHeader() / this.splitLength).intValue();
					if (diskNumberStart < 9) {
						splitPath += (".00" + (diskNumberStart + 1));
					} else if (diskNumberStart < 99) {
						splitPath += (".0" + (diskNumberStart + 1));
					} else {
						splitPath += ("." + (diskNumberStart + 1));
					}
				} else {
					int diskNumberStart = generalFileHeader.getDiskNumberStart();

					if (this.endCentralDirectoryRecord.getIndexOfThisDiskStartOfCentralDirectory() == diskNumberStart) {
						splitPath = this.filePath;
					} else {
						if (diskNumberStart < 9) {
							splitPath += (".zip.0" + (diskNumberStart + 1));
						} else {
							splitPath += (".zip." + (diskNumberStart + 1));
						}
					}
				}
				return new StandardFile(splitPath);
			}
			return new StandardFile(this.filePath);
		}

		throw new ZipException("cannot create file handler to remove file");
	}

	private void copyFile(StandardFile input,
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
				bufferSize = (int) (end - start);
			}

			int readLength;
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
					readBuffer = new byte[(int) (limitRead - totalRead)];
				}
			} while (readLength != Globals.DEFAULT_VALUE_INT);
		} catch (Exception e) {
			throw new ZipException("Copy data error! ", e);
		}
	}

	private void extractFileToPath(GeneralFileHeader generalFileHeader, String destPath, boolean ignoreFileAttr)
			throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException(0x0000001B000FL, "Null_General_File_Header_Zip_Error");
		}

		ZipInputStream inputStream = null;
		OutputStream outputStream = null;

		try {
			inputStream = this.openInputStream(generalFileHeader);
			outputStream = this.openOutputStream(destPath, generalFileHeader.getEntryPath());

			byte[] buffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
			int readLength;

			while ((readLength = inputStream.read(buffer)) != Globals.DEFAULT_VALUE_INT) {
				outputStream.write(buffer, 0, readLength);
			}

			if (generalFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
				this.checkMac();
			} else {
				long calculatedCRC = inputStream.crcValue() & 0xFFFFFFFFL;
				if (calculatedCRC != generalFileHeader.getCrc32()) {
					throw new ZipException(0x0000001B0019L, "CRC_Failed_Zip_Error");
				}
			}
		} catch (IOException e) {
			throw new ZipException("Zip file process crc check error! ", e);
		} finally {
			IOUtils.closeStream(inputStream);
			IOUtils.closeStream(outputStream);
		}

		try {
			String filePath = destPath + generalFileHeader.getEntryPath();
			if (generalFileHeader.getExternalFileAttr() != null && !ignoreFileAttr) {
				if (generalFileHeader.getExternalFileAttr()[0] == Globals.FILE_MODE_READ_ONLY) {
					setFileReadOnly(FileUtils.getFile(filePath));
				}

				setFileLastModify(FileUtils.getFile(filePath),
						DateTimeUtils.dosToJavaTime(generalFileHeader.getLastModFileTime()));
			}
		} catch (FileNotFoundException e) {
			throw new ZipException("Extract zip file error! ", e);
		}
	}

	private void checkMac() throws ZipException {
		if (this.decryptor instanceof AESDecryptor) {
			byte[] tempMacBytes;
			try {
				tempMacBytes = ((AESDecryptor) this.decryptor).calculateAuthenticationBytes();
			} catch (CryptoException e) {
				throw new ZipException(0x0000001B0019L, "CRC_Failed_Zip_Error");
			}
			byte[] storedMac = ((AESDecryptor) this.decryptor).getStoredMac();
			byte[] calculateMac = new byte[Globals.AES_AUTH_LENGTH];

			if (storedMac == null) {
				throw new ZipException(0x0000001B0019L, "CRC_Failed_Zip_Error");
			}

			System.arraycopy(tempMacBytes, 0, calculateMac, 0, Globals.AES_AUTH_LENGTH);

			if (!Arrays.equals(calculateMac, storedMac)) {
				throw new ZipException(0x0000001B0019L, "CRC_Failed_Zip_Error");
			}
		}
	}

	private int readEntryLength(GeneralFileHeader generalFileHeader) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException(0x0000001B000FL, "Null_General_File_Header_Zip_Error");
		}

		ZipInputStream inputStream = null;
		try {
			inputStream = this.openInputStream(generalFileHeader);
			return inputStream.available();
		} catch (IOException e) {
			throw new ZipException("Read entry length error! ", e);
		} finally {
			IOUtils.closeStream(inputStream);
		}
	}

	private byte[] readEntry(GeneralFileHeader generalFileHeader, long position, int dataLength) throws ZipException {
		if (generalFileHeader == null) {
			throw new ZipException(0x0000001B000FL, "Null_General_File_Header_Zip_Error");
		}

		ZipInputStream inputStream = null;
		ByteArrayOutputStream outputStream = null;

		try {
			int totalLength = 0, readLength;

			inputStream = this.openInputStream(generalFileHeader);
			outputStream = new ByteArrayOutputStream((int) generalFileHeader.getOriginalSize());

			if (position > 0L) {
				long skipLength = inputStream.skip(position);
				if (skipLength != position) {
					return new byte[0];
				}
			}

			if (dataLength > 0) {
				byte[] readBuffer;
				while (true) {
					int bufferLength = Integer.min(dataLength - totalLength, Globals.DEFAULT_BUFFER_SIZE);
					readBuffer = new byte[bufferLength];

					if ((readLength = inputStream.read(readBuffer)) == Globals.DEFAULT_VALUE_INT) {
						break;
					}
					outputStream.write(readBuffer, 0, readLength);
					totalLength += readLength;

					if (totalLength == dataLength) {
						break;
					}
				}
			} else {
				byte[] readBuffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
				while ((readLength = inputStream.read(readBuffer)) != Globals.DEFAULT_VALUE_INT) {
					outputStream.write(readBuffer, 0, readLength);
					totalLength += readLength;
				}
			}

			if (generalFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
				this.checkMac();
			} else {
				long calculatedCRC = inputStream.crcValue();
				if (calculatedCRC != generalFileHeader.getCrc32()) {
					throw new ZipException(0x0000001B0019L, "CRC_Failed_Zip_Error");
				}
			}

			return outputStream.toByteArray();
		} catch (IOException e) {
			throw new ZipException("Read entry data bytes error! ", e);
		} finally {
			IOUtils.closeStream(inputStream);
			IOUtils.closeStream(outputStream);
		}
	}

	private ZipInputStream openInputStream(GeneralFileHeader generalFileHeader) throws ZipException {
		StandardFile input = null;
		try {
			input = this.createFileHandler(generalFileHeader);

			LocalFileHeader localFileHeader = this.readLocalFileHeader(input, generalFileHeader);

			if (localFileHeader.getCompressionMethod() != generalFileHeader.getCompressionMethod()) {
				throw new ZipException("local header does not matched with general header");
			}

			if (localFileHeader.isEncrypted()) {
				if (localFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
					byte[] salt = null;
					if (localFileHeader.getAesExtraDataRecord() != null) {
						salt = new byte[HeaderOperator.saltLength(localFileHeader.getAesExtraDataRecord().getAesStrength())];
						input.seek(localFileHeader.getOffsetStartOfData());
						if (input.read(salt) == Globals.DEFAULT_VALUE_INT) {
							salt = null;
						}
					}

					byte[] passwordBytes = new byte[2];

					if (input.read(passwordBytes) > 0) {
						this.decryptor = new AESDecryptor(localFileHeader, salt, passwordBytes);
					}
				} else if (localFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_STANDARD) {
					byte[] decryptorHeader = new byte[Globals.STD_DEC_HDR_SIZE];
					input.seek(localFileHeader.getOffsetStartOfData());

					if (input.read(decryptorHeader) > 0) {
						this.decryptor = new StandardDecryptor(localFileHeader, decryptorHeader);
					}
				} else {
					throw new ZipException(0x0000001B0001L, "Not_Supported_Encryption_Mode_Zip_Error");
				}
			}

			long compressedSize = localFileHeader.getCompressedSize();
			long offsetStartOfData = localFileHeader.getOffsetStartOfData();

			if (localFileHeader.isEncrypted()) {
				if (localFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
					if (this.decryptor instanceof AESDecryptor) {
						compressedSize -= (((AESDecryptor) this.decryptor).getSaltLength() +
								Globals.PASSWORD_VERIFIER_LENGTH + 10);
						offsetStartOfData += (((AESDecryptor) this.decryptor).getSaltLength() +
								Globals.PASSWORD_VERIFIER_LENGTH);
					} else {
						throw new ZipException("invalid decryptor when trying to calculate " +
								"compressed size for AES encrypted file: " + localFileHeader.getEntryPath());
					}
				} else if (localFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_STANDARD) {
					compressedSize -= Globals.STD_DEC_HDR_SIZE;
					offsetStartOfData += Globals.STD_DEC_HDR_SIZE;
				}
			}

			int compressionMethod = localFileHeader.getCompressionMethod();
			if (generalFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES) {
				if (generalFileHeader.getAesExtraDataRecord() == null) {
					throw new ZipException("AES extra data record does not exists!");
				}
				compressionMethod = generalFileHeader.getAesExtraDataRecord().getCompressionMethod();
			}
			input.seek(offsetStartOfData);

			boolean isAESEncryptedFile = generalFileHeader.isEncrypted()
					&& generalFileHeader.getEncryptionMethod() == Globals.ENC_METHOD_AES;

			int currentIndex;
			if (this.numberFormattedName) {
				currentIndex = Long.valueOf(generalFileHeader.getOffsetLocalHeader() / this.splitLength).intValue();
			} else {
				currentIndex = generalFileHeader.getDiskNumberStart();
			}
			switch (compressionMethod) {
				case Globals.COMP_STORE:
					return new ZipInputStream(new PartInputStream(this, currentIndex,
							offsetStartOfData, compressedSize, this.decryptor, isAESEncryptedFile));
				case Globals.COMP_DEFLATE:
					return new ZipInputStream(new InflaterInputStream(this, currentIndex,
							offsetStartOfData, compressedSize, generalFileHeader.getOriginalSize(), this.decryptor,
							isAESEncryptedFile));
				default:
					throw new ZipException("Compression type not supported");
			}
		} catch (ZipException | IOException e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Open entry input stream error! ", e);
			}
		} finally {
			IOUtils.closeStream(input);
		}
	}

	private FileOutputStream openOutputStream(String folderPath, String fileName) throws ZipException {
		if (StringUtils.isEmpty(folderPath)) {
			throw new ZipException("Output path is null");
		}

		if (StringUtils.isEmpty(fileName)) {
			throw new ZipException("Output file name is null");
		}

		if (!FileUtils.makeDir(folderPath)) {
			throw new ZipException("Create output folder error");
		}

		try {
			if (!folderPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
				folderPath += Globals.DEFAULT_PAGE_SEPARATOR;
			}

			String fullPath = folderPath + fileName;
			fullPath = StringUtils.replace(fullPath, Globals.DEFAULT_ZIP_PAGE_SEPARATOR, Globals.DEFAULT_PAGE_SEPARATOR);
			FileUtils.makeDir(fullPath.substring(0, fullPath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR)));
			return new FileOutputStream(FileUtils.getFile(fullPath));
		} catch (FileNotFoundException e) {
			throw new ZipException("Extract path not found! ", e);
		}
	}

	private OutputStream openMergeOutputStream(String outputPath) throws ZipException {
		if (outputPath == null) {
			throw new ZipException("Output path is null, cannot create output stream");
		}

		try {
			return new FileOutputStream(FileUtils.getFile(outputPath));
		} catch (FileNotFoundException e) {
			throw new ZipException("Output path not found! ", e);
		}
	}

	/**
	 * Open split file nervousync random access file.
	 *
	 * @param index the index
	 * @return the nervousync random access file
	 * @throws ZipException the zip exception
	 */
	public StandardFile openSplitFile(int index) throws ZipException {
		try {
			if (this.splitArchive) {
				if (index < 0) {
					throw new ZipException("invalid index, cannot create split file handler");
				}

				String currentSplitFile = this.currentSplitFileName(index);

				if (!FileUtils.isExists(currentSplitFile)) {
					throw new ZipException("Split file not found!");
				}

				return new StandardFile(currentSplitFile);
			}
			return new StandardFile(this.filePath);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Open split file error! ", e);
			}
		}
	}

	private String currentSplitFileName(int index) {
		String currentSplitFile;
		if (index == this.endCentralDirectoryRecord.getIndexOfThisDisk()) {
			currentSplitFile = this.filePath;
		} else {
			currentSplitFile = this.filePath.substring(0, this.filePath.lastIndexOf('.'));
			if (this.numberFormattedName) {
				if (index < 9) {
					currentSplitFile += (".00" + (index + 1));
				} else if (index < 99) {
					currentSplitFile += (".0" + (index + 1));
				} else {
					currentSplitFile += ("." + (index + 1));
				}
			} else {
				if (index < 9) {
					currentSplitFile += (".zip.0" + (index + 1));
				} else {
					currentSplitFile += (".zip." + (index + 1));
				}
			}
		}
		return currentSplitFile;
	}

	private void updateSplitZipEntity(List<Long> sizeList,
	                                  boolean removeSplitSig) throws ZipException {
		this.splitArchive = Boolean.FALSE;
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

		List<GeneralFileHeader> newFileHeaders = new ArrayList<>();

		for (GeneralFileHeader generalFileHeader : this.centralDirectory.getFileHeaders()) {
			long offsetHeaderToAdd = 0L;

			for (int i = 0; i < generalFileHeader.getDiskNumberStart(); i++) {
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

	private void updateSplitZip64EndCentralDirectoryLocator(List<Long> sizeList) {
		if (this.zip64EndCentralDirectoryLocator == null) {
			return;
		}
		this.zip64EndCentralDirectoryLocator.setIndexOfZip64EndOfCentralDirectoryRecord(0);
		long offsetZip64EndCentralDirRec = 0;

		for (Long recordSize : sizeList) {
			offsetZip64EndCentralDirRec += recordSize;
		}
		this.zip64EndCentralDirectoryLocator.setOffsetZip64EndOfCentralDirectoryRecord(
				this.zip64EndCentralDirectoryLocator.getOffsetZip64EndOfCentralDirectoryRecord() +
						offsetZip64EndCentralDirRec);
		this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(1);
	}

	private void updateSplitZip64EndCentralDirectoryRecord(List<Long> sizeList) {
		if (this.zip64EndCentralDirectoryRecord == null) {
			return;
		}
		this.zip64EndCentralDirectoryRecord.setIndex(0);
		this.zip64EndCentralDirectoryRecord.setStartOfCentralDirectory(0);
		this.zip64EndCentralDirectoryRecord.setTotalEntriesInCentralDirectoryOnThisDisk(
				this.endCentralDirectoryRecord.getTotalOfEntriesInCentralDirectory());

		long offsetStartCenDirWRTStartDiskNo = 0;

		for (Long recordSize : sizeList) {
			offsetStartCenDirWRTStartDiskNo += recordSize;
		}

		this.zip64EndCentralDirectoryRecord.setOffsetStartCenDirWRTStartDiskNo(
				this.zip64EndCentralDirectoryRecord.getOffsetStartCenDirWRTStartDiskNo() +
						offsetStartCenDirWRTStartDiskNo);
	}

	private void readHeaders() throws ZipException {
		try (StandardFile input = retrieveHeaderFile()) {
			this.readEndOfCentralDirectoryRecord(input);

			// Check and set the zip64 format
			this.readZip64EndCentralDirectoryLocator(input);

			if (this.zip64Format) {
				this.readZip64EndCentralDirectoryRecord(input);
			}

			this.readCentralDirectory(input);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Read entry headers data error! ", e);
			}
		}
	}

	private StandardFile retrieveHeaderFile() throws FileNotFoundException {
		if (this.filePath.endsWith(".001")) {
			String folderPath = this.filePath.substring(0, this.filePath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR));
			final String fileName = Optional.ofNullable(StringUtils.getFilename(this.filePath))
					.map(name -> name.substring(0, name.length() - 4))
					.orElse(Globals.DEFAULT_VALUE_STRING);
			List<String> fileList = FileUtils.listFiles(folderPath, (dir, name) -> name.startsWith(fileName));
			fileList.sort(Comparator.reverseOrder());
			if (fileList.size() > 1) {
				this.splitArchive = Boolean.TRUE;
				this.numberFormattedName = Boolean.TRUE;
				this.splitCount = fileList.size();
				this.splitLength = FileUtils.fileSize(fileList.get(1));
				return new StandardFile(fileList.get(0));
			}
		}
		return new StandardFile(this.filePath);
	}

	private long headerOffset(final GeneralFileHeader generalFileHeader) throws ZipException {
		long localHeaderOffset = generalFileHeader.getOffsetLocalHeader();

		if (generalFileHeader.getZip64ExtendInfo() != null
				&& generalFileHeader.getZip64ExtendInfo().getOffsetLocalHeader() > 0L) {
			localHeaderOffset = generalFileHeader.getZip64ExtendInfo().getOffsetLocalHeader();
		}

		if (localHeaderOffset < 0) {
			throw new ZipException(0x0000001B001DL, "Invalid_Offset_Local_Header_Zip_Error");
		}

		if (this.numberFormattedName) {
			while (localHeaderOffset > this.splitLength) {
				localHeaderOffset -= this.splitLength;
			}
		}
		return localHeaderOffset;
	}

	private LocalFileHeader readLocalFileHeader(StandardFile input,
	                                            GeneralFileHeader generalFileHeader) throws ZipException {
		if (generalFileHeader == null || input == null) {
			throw new ZipException("invalid read parameters for local header");
		}
		try {
			long localHeaderOffset = this.headerOffset(generalFileHeader);
			input.seek(localHeaderOffset + 26);

			byte[] tempBuffer = new byte[4];
			if (input.read(tempBuffer) == Globals.DEFAULT_VALUE_INT) {
				throw new ZipException(0x0000001B001DL, "Invalid_Offset_Local_Header_Zip_Error");
			}

			byte[] shortBuffer = new byte[2];
			System.arraycopy(tempBuffer, 0, shortBuffer, 0, 2);
			int fileNameLength = RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN);
			System.arraycopy(tempBuffer, 2, shortBuffer, 0, 2);
			int extraFieldLength = RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN);

			input.seek(localHeaderOffset);

			int length = 0;
			LocalFileHeader localFileHeader = new LocalFileHeader();

			byte[] readBuffer = new byte[30 + fileNameLength + extraFieldLength];

			if (input.read(readBuffer) == Globals.DEFAULT_VALUE_INT) {
				throw new ZipException(0x0000001B001DL, "Invalid_Offset_Local_Header_Zip_Error");
			}

			byte[] intBuffer = new byte[4];

			// Signature
			System.arraycopy(readBuffer, 0, intBuffer, 0, 4);
			int signature = RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN);
			if (signature != Globals.LOCSIG) {
				throw new ZipException("invalid local header signature for file: " + generalFileHeader.getEntryPath());
			}
			localFileHeader.setSignature(signature);
			length += 4;

			// Extract needed
			System.arraycopy(readBuffer, 4, shortBuffer, 0, 2);
			localFileHeader.setExtractNeeded(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));
			length += 2;

			// General purpose bit flag
			System.arraycopy(readBuffer, 6, shortBuffer, 0, 2);
			localFileHeader.setFileNameUTF8Encoded(
					(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN) & Globals.UFT8_NAMES_FLAG) != 0);
			localFileHeader.setGeneralPurposeFlag(shortBuffer.clone());
			length += 2;

			int firstByte = shortBuffer[0];

			// Check if data descriptor exists for local file header
			String binaryData = Integer.toBinaryString(firstByte);
			if (binaryData.length() >= 4) {
				localFileHeader.setDataDescriptorExists(binaryData.charAt(3) == '1');
			}

			// Compression method
			System.arraycopy(readBuffer, 8, shortBuffer, 0, 2);
			localFileHeader.setCompressionMethod(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));
			length += 2;

			// Lase modify time
			System.arraycopy(readBuffer, 10, intBuffer, 0, 4);
			localFileHeader.setLastModFileTime(RawUtils.readShort(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));
			length += 4;

			// CRC
			System.arraycopy(readBuffer, 14, intBuffer, 0, 4);
			localFileHeader.setCrc32(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));
			localFileHeader.setCrcBuffer(intBuffer.clone());
			length += 4;

			// Compressed size
			System.arraycopy(readBuffer, 18, intBuffer, 0, 4);
			localFileHeader.setCompressedSize(RawUtils.readLong(readLongByteFromIntByte(intBuffer), 0, ByteOrder.LITTLE_ENDIAN));
			length += 4;

			// Original size
			System.arraycopy(readBuffer, 22, intBuffer, 0, 4);
			localFileHeader.setOriginalSize(RawUtils.readLong(readLongByteFromIntByte(intBuffer), 0, ByteOrder.LITTLE_ENDIAN));
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

				String entryPath = new String(fileNameBuffer, this.charsetEncoding);

				if (entryPath.contains(Globals.DEFAULT_ZIP_ENTRY_SEPARATOR)) {
					entryPath = entryPath.substring(entryPath.indexOf(Globals.DEFAULT_ZIP_ENTRY_SEPARATOR)
							+ Globals.DEFAULT_ZIP_ENTRY_SEPARATOR.length());
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

			if (localFileHeader.isEncrypted() && localFileHeader.getEncryptionMethod() != Globals.ENC_METHOD_AES) {
				if ((firstByte & 64) == 64) {
					localFileHeader.setEncryptionMethod(Globals.ENC_METHOD_STRONG);
				} else {
					localFileHeader.setEncryptionMethod(Globals.ENC_METHOD_STANDARD);
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
		} catch (IOException | DataInvalidException e) {
			throw new ZipException("Read local file header error! ", e);
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
				this.checkZip64Format();

				this.zip64EndCentralDirectoryLocator
						.setIndexOfZip64EndOfCentralDirectoryRecord(currentSplitFileCount);
				this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(currentSplitFileCount + 1);
			}

			this.endCentralDirectoryRecord.setIndexOfThisDisk(currentSplitFileCount);
			this.endCentralDirectoryRecord.setIndexOfThisDiskStartOfCentralDirectory(currentSplitFileCount);
		} catch (IOException e) {
			throw new ZipException("Process header data error! ", e);
		}
	}

	private int writeCentralDirectory(final OutputStream outputStream, final List<String> headerBytesList)
			throws ZipException {
		if (outputStream == null) {
			throw new ZipException("output parameters is null, cannot write central directory");
		}

		if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null
				|| this.centralDirectory.getFileHeaders().isEmpty()) {
			return Globals.INITIALIZE_INT_VALUE;
		}

		int sizeOfCentralDirectory = Globals.INITIALIZE_INT_VALUE;

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

			boolean writeZip64FileSize = false;
			boolean writeZip64OffsetLocalHeader = false;

			HeaderOperator.appendIntToArrayList(generalFileHeader.getSignature(), headerBytesList);
			sizeOfFileHeader += 4;

			HeaderOperator.appendShortToArrayList((short) generalFileHeader.getMadeVersion(), headerBytesList);
			sizeOfFileHeader += 2;

			HeaderOperator.appendShortToArrayList((short) generalFileHeader.getExtractNeeded(), headerBytesList);
			sizeOfFileHeader += 2;

			HeaderOperator.copyByteArrayToList(generalFileHeader.getGeneralPurposeFlag(), headerBytesList);
			sizeOfFileHeader += 2;

			HeaderOperator.appendShortToArrayList((short) generalFileHeader.getCompressionMethod(), headerBytesList);
			sizeOfFileHeader += 2;

			HeaderOperator.appendIntToArrayList(generalFileHeader.getLastModFileTime(), headerBytesList);
			sizeOfFileHeader += 4;

			HeaderOperator.appendIntToArrayList((int) (generalFileHeader.getCrc32()), headerBytesList);
			sizeOfFileHeader += 4;

			if (generalFileHeader.getOriginalSize() + Globals.ZIP64_EXTRA_BUFFER_SIZE >= Globals.ZIP_64_LIMIT
					|| generalFileHeader.getCompressedSize() >= Globals.ZIP_64_LIMIT) {
				RawUtils.writeLong(longBuffer, 0, Globals.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);

				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;

				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;

				writeZip64FileSize = true;
			} else {
				RawUtils.writeLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN, generalFileHeader.getCompressedSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;

				RawUtils.writeLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN, generalFileHeader.getOriginalSize());
				System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
				HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
				sizeOfFileHeader += 4;
			}

			RawUtils.writeShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN, (short) generalFileHeader.getFileNameLength());
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);
			sizeOfFileHeader += 2;

			// Compute offset bytes before extra field is written for Zip64
			// compatibility
			// NOTE: this data is not written now, but written at a later point
			byte[] offsetLocalHeaderBytes = new byte[4];
			if (generalFileHeader.getOffsetLocalHeader() > Globals.ZIP_64_LIMIT) {
				RawUtils.writeLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN, Globals.ZIP_64_LIMIT);
				System.arraycopy(longBuffer, 0, offsetLocalHeaderBytes, 0, 4);
				writeZip64OffsetLocalHeader = true;
			} else {
				RawUtils.writeLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN, generalFileHeader.getOffsetLocalHeader());
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
			HeaderOperator.appendShortToArrayList((short) extraFieldLength, headerBytesList);
			sizeOfFileHeader += 2;

			// Skip file comment length for now
			HeaderOperator.copyByteArrayToList(EMPTY_SHORT_BUFFER, headerBytesList);
			sizeOfFileHeader += 2;

			// Skip disk number start for now
			HeaderOperator.appendShortToArrayList((short) generalFileHeader.getDiskNumberStart(), headerBytesList);
			sizeOfFileHeader += 2;

			// Skip internal file attributes for now
			HeaderOperator.copyByteArrayToList(EMPTY_SHORT_BUFFER, headerBytesList);
			sizeOfFileHeader += 2;

			// External file attributes
			if (generalFileHeader.getExternalFileAttr() != null) {
				HeaderOperator.copyByteArrayToList(generalFileHeader.getExternalFileAttr(), headerBytesList);
			} else {
				HeaderOperator.copyByteArrayToList(EMPTY_INT_BUFFER, headerBytesList);
			}
			sizeOfFileHeader += 4;

			// offset local header
			// this data is computed above
			HeaderOperator.copyByteArrayToList(offsetLocalHeaderBytes, headerBytesList);
			sizeOfFileHeader += 4;

			byte[] fileNameBytes = generalFileHeader.getEntryPath().getBytes(this.charsetEncoding);
			HeaderOperator.copyByteArrayToList(fileNameBytes, headerBytesList);
			sizeOfFileHeader += fileNameBytes.length;

			if (writeZip64FileSize || writeZip64OffsetLocalHeader) {
				this.zip64Format = true;

				// Zip64 header
				HeaderOperator.appendShortToArrayList((short) Globals.EXTRAFIELDZIP64LENGTH, headerBytesList);
				sizeOfFileHeader += 2;

				// Zip64 extra data record size
				int dataSize = 0;

				if (writeZip64FileSize) {
					dataSize += 16;
				}
				if (writeZip64OffsetLocalHeader) {
					dataSize += 8;
				}

				HeaderOperator.appendShortToArrayList((short) dataSize, headerBytesList);
				sizeOfFileHeader += 2;

				if (writeZip64FileSize) {
					HeaderOperator.appendLongToArrayList(generalFileHeader.getOriginalSize(), headerBytesList);
					sizeOfFileHeader += 8;

					HeaderOperator.appendLongToArrayList(generalFileHeader.getCompressedSize(), headerBytesList);
					sizeOfFileHeader += 8;
				}

				if (writeZip64OffsetLocalHeader) {
					HeaderOperator.appendLongToArrayList(generalFileHeader.getOffsetLocalHeader(), headerBytesList);
					sizeOfFileHeader += 8;
				}
			}

			if (generalFileHeader.getAesExtraDataRecord() != null) {
				AESEngine.processHeader(generalFileHeader.getAesExtraDataRecord(), headerBytesList);
				sizeOfFileHeader += 11;
			}

			return sizeOfFileHeader;
		} catch (Exception e) {
			throw new ZipException("Write file header error! ", e);
		}
	}

	private void writeZip64EndOfCentralDirectoryRecord(OutputStream outputStream,
	                                                   int sizeOfCentralDirectory, long offsetCentralDirectory, List<String> headerBytesList) throws ZipException {
		if (outputStream == null) {
			throw new ZipException("Output stream is null, cannot write zip64 end of central directory record");
		}

		try {
//			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
//			byte[] longBuffer = new byte[8];

			final byte[] EMPTY_SHORT_BUFFER = {0, 0};

			// zip64 end of central dir signature
			HeaderOperator.appendIntToArrayList((int) Globals.ZIP64ENDCENDIRREC, headerBytesList);

			// size zip64 end of central directory record
			HeaderOperator.appendLongToArrayList(44L, headerBytesList);

			// version made by
			// version needed to extract
			if (this.centralDirectory != null && this.centralDirectory.getFileHeaders() != null
					&& !this.centralDirectory.getFileHeaders().isEmpty()) {
				HeaderOperator.appendShortToArrayList((short) this.centralDirectory.getFileHeaders().get(0).getMadeVersion(), headerBytesList);
				HeaderOperator.appendShortToArrayList((short) this.centralDirectory.getFileHeaders().get(0).getExtractNeeded(), headerBytesList);
			} else {
				HeaderOperator.copyByteArrayToList(EMPTY_SHORT_BUFFER, headerBytesList);
				HeaderOperator.copyByteArrayToList(EMPTY_SHORT_BUFFER, headerBytesList);
			}

			// number of these disks
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					this.endCentralDirectoryRecord.getIndexOfThisDisk());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// number of the disks with start of central directory
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					this.endCentralDirectoryRecord.getIndexOfThisDiskStartOfCentralDirectory());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// total number of entries in the central directory on this disk
			int numEntries;
			int numEntriesOnThisDisk = 0;
			if (this.centralDirectory == null || this.centralDirectory.getFileHeaders() == null) {
				throw new ZipException("invalid central directory/file headers, cannot write end of central directory record");
			} else {
				numEntries = this.centralDirectory.getFileHeaders().size();
				if (this.splitArchive) {
					countNumberOfFileHeaderEntriesOnDisk(this.centralDirectory.getFileHeaders(),
							this.endCentralDirectoryRecord.getIndexOfThisDisk());
				} else {
					numEntriesOnThisDisk = numEntries;
				}
			}

			HeaderOperator.appendLongToArrayList(numEntriesOnThisDisk, headerBytesList);

			// Total number of entries in central directory
			HeaderOperator.appendLongToArrayList(numEntries, headerBytesList);

			// Size of central directory
			HeaderOperator.appendLongToArrayList(sizeOfCentralDirectory, headerBytesList);

			// offset start of central directory with respect to the starting disk number
			HeaderOperator.appendLongToArrayList(offsetCentralDirectory, headerBytesList);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Write zip64 header data error! ", e);
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
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN, (int) Globals.ZIP64ENDCENDIRLOC);
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// number of the disks with the zip64 end of central directory
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					this.zip64EndCentralDirectoryLocator.getIndexOfZip64EndOfCentralDirectoryRecord());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// relative offset of the zip64 end of central directory record
			RawUtils.writeLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					this.zip64EndCentralDirectoryLocator.getOffsetZip64EndOfCentralDirectoryRecord());
			HeaderOperator.copyByteArrayToList(longBuffer, headerBytesList);

			// total number of disks
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					this.zip64EndCentralDirectoryLocator.getTotalNumberOfDiscs());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("Write zip64 End Of Central Directory Locator error! ", e);
			}
		}
	}

	private void writeEndOfCentralDirectoryRecord(final int sizeOfCentralDirectory, final long offsetCentralDirectory,
	                                              final List<String> headerBytesList) throws ZipException {

		try {
			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			// End of central directory signature
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN, (int) this.endCentralDirectoryRecord.getSignature());
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// number of these disks
			RawUtils.writeShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					(short) (this.endCentralDirectoryRecord.getIndexOfThisDisk()));
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			// number of the disks with start of central directory
			RawUtils.writeShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN,
					(short) (this.endCentralDirectoryRecord.getIndexOfThisDiskStartOfCentralDirectory()));
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			// Total number of entries in the central directory on this disk
			int numEntries;
			int numEntriesOnThisDisk;
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
			RawUtils.writeShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN, (short) numEntriesOnThisDisk);
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			// Total number of entries in central directory
			RawUtils.writeShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN, (short) numEntries);
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			// Size of central directory
			RawUtils.writeInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN, sizeOfCentralDirectory);
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// Offset central directory
			RawUtils.writeLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN, Math.min(offsetCentralDirectory, Globals.ZIP_64_LIMIT));
			System.arraycopy(longBuffer, 0, intBuffer, 0, 4);
			HeaderOperator.copyByteArrayToList(intBuffer, headerBytesList);

			// Zip File comment length
			int commentLength = 0;
			if (this.endCentralDirectoryRecord.getCommentBytes() != null) {
				commentLength = this.endCentralDirectoryRecord.getCommentLength();
			}
			RawUtils.writeShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN, (short) commentLength);
			HeaderOperator.copyByteArrayToList(shortBuffer, headerBytesList);

			// Comment
			if (commentLength > 0) {
				HeaderOperator.copyByteArrayToList(this.endCentralDirectoryRecord.getCommentBytes(), headerBytesList);
			}
		} catch (Exception e) {
			if (e instanceof ZipException) {
				throw (ZipException) e;
			} else {
				throw new ZipException("write End Of Central Directory Record error", e);
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
			throw new ZipException("write Zip Header Bytes error", e);
		}
	}

	private void readEndOfCentralDirectoryRecord(StandardFile input)
			throws ZipException {
		if (input == null) {
			throw new ZipException("Random access file is null!");
		}

		try {
			byte[] buffer = new byte[4];
			long position;
			try {
				position = input.length();
			} catch (IOException e) {
				position = Globals.DEFAULT_VALUE_LONG;
			}

			if (position == Globals.DEFAULT_VALUE_LONG) {
				throw new ZipException("Read end of central directory record error! ");
			}
			position -= Globals.ENDHDR;

			this.endCentralDirectoryRecord = new EndCentralDirectoryRecord();

			int count = 0;
			do {
				input.seek(position--);
				count++;
			} while ((readIntFromDataInput(input, buffer) != Globals.ENDSIG)
					&& count <= 3000);

			int endsig = RawUtils.readInt(buffer, 0, ByteOrder.LITTLE_ENDIAN);
			if (endsig != Globals.ENDSIG) {
				throw new ZipException("zip headers not found. probably not a zip file");
			}

			byte[] readBuffer = new byte[18];

			if (input.read(readBuffer) == Globals.DEFAULT_VALUE_INT) {
				return;
			}

			byte[] intBuffer = new byte[4];
			byte[] shortBuffer = new byte[2];

			this.endCentralDirectoryRecord.setSignature(Globals.ENDSIG);

			System.arraycopy(readBuffer, 0, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord.setIndexOfThisDisk(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 2, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord
					.setIndexOfThisDiskStartOfCentralDirectory(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 4, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord.setTotalOfEntriesInCentralDirectoryOnThisDisk(
					RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 6, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord
					.setTotalOfEntriesInCentralDirectory(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 8, intBuffer, 0, 4);
			this.endCentralDirectoryRecord.setSizeOfCentralDirectory(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 12, intBuffer, 0, 4);
			this.endCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(
					RawUtils.readLong(readLongByteFromIntByte(intBuffer), 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 16, shortBuffer, 0, 2);
			this.endCentralDirectoryRecord.setCommentLength(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			if (this.endCentralDirectoryRecord.getCommentLength() > 0) {
				byte[] commentBuffer = new byte[this.endCentralDirectoryRecord.getCommentLength()];
				input.read(commentBuffer);
				this.endCentralDirectoryRecord.setCommentBytes(commentBuffer);
			}

			this.splitArchive |= (this.endCentralDirectoryRecord.getIndexOfThisDisk() > 0);
		} catch (IOException | DataInvalidException e) {
			throw new ZipException("read End Of Central Directory Record error! ", e);
		}
	}

	private void readZip64EndCentralDirectoryLocator(StandardFile input)
			throws ZipException {
		try {
			this.zip64EndCentralDirectoryLocator = new Zip64EndCentralDirectoryLocator();
			byte[] buffer = new byte[4];
			long position;
			try {
				position = input.length();
			} catch (Exception e) {
				position = Globals.DEFAULT_VALUE_LONG;
			}

			if (position == Globals.DEFAULT_VALUE_LONG) {
				throw new ZipException("Read end of central directory record error! ");
			}
			position -= Globals.ENDHDR;

			do {
				input.seek(position--);
			} while (readIntFromDataInput(input, buffer) != Globals.ENDSIG);

			// Now the file pointer is at the end of signature of Central Dir
			// Rec
			// Seek back with the following values
			// 4 -> total number of disks
			// 8 -> relative offset of the zip64 end of central directory record
			// 4 -> number of the disk with the start of the zip64 end of
			// central directory
			// 4 -> zip64 end of central dir locator signature
			// Refer to Appose for more information
			input.seek(position - 4 - 8 - 4 - 4);

			byte[] readBuffer = new byte[20];

			if (input.read(readBuffer) == Globals.DEFAULT_VALUE_INT) {
				return;
			}

			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			int signature = this.readSignature(readBuffer);
			if (signature == Globals.ZIP64ENDCENDIRLOC) {
				this.zip64Format = true;
				this.zip64EndCentralDirectoryLocator.setSignature(signature);
			} else {
				this.zip64Format = false;
				return;
			}

			System.arraycopy(readBuffer, 4, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryLocator
					.setIndexOfZip64EndOfCentralDirectoryRecord(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 8, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryLocator
					.setOffsetZip64EndOfCentralDirectoryRecord(RawUtils.readInt(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			System.arraycopy(readBuffer, 16, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryLocator.setTotalNumberOfDiscs(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));
		} catch (Exception e) {
			throw new ZipException("read Zip64 End Central Directory Locator error! ", e);
		}
	}

	private int readSignature(byte[] dataBytes) {
		byte[] intBuffer = new byte[4];
		System.arraycopy(dataBytes, 0, intBuffer, 0, 4);
		try {
			return RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN);
		} catch (DataInvalidException ignore) {
			return Globals.DEFAULT_VALUE_INT;
		}
	}

	private void readCentralDirectory(StandardFile input)
			throws ZipException {
		if (this.endCentralDirectoryRecord == null) {
			throw new ZipException("End Central Record is null!");
		}

		try {
			List<GeneralFileHeader> fileHeaderList = new ArrayList<>();

			long offsetOfStartOfCentralDirectory = this.endCentralDirectoryRecord.getOffsetOfStartOfCentralDirectory();
			int centralDirectoryEntryCount = this.endCentralDirectoryRecord.getTotalOfEntriesInCentralDirectory();

			if (this.zip64Format) {
				offsetOfStartOfCentralDirectory = this.zip64EndCentralDirectoryRecord.getOffsetStartCenDirWRTStartDiskNo();
				centralDirectoryEntryCount = (int) this.zip64EndCentralDirectoryRecord.getTotalEntriesInCentralDirectory();
			}

			if (this.splitArchive && this.numberFormattedName) {
				offsetOfStartOfCentralDirectory -= ((this.splitCount - 1) * this.splitLength);
			}

			input.seek(offsetOfStartOfCentralDirectory);

			long bufferSize = input.length() - offsetOfStartOfCentralDirectory;
			byte[] readBuffer = new byte[(int) bufferSize];
			if (input.read(readBuffer) == Globals.DEFAULT_VALUE_INT) {
				return;
			}

			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];

			int pos = 0;
			for (int i = 0; i < centralDirectoryEntryCount; i++) {
				GeneralFileHeader fileHeader = new GeneralFileHeader();

				System.arraycopy(readBuffer, pos, intBuffer, 0, 4);
				int signature = RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN);
				if (signature != Globals.CENSIG) {
					throw new ZipException("Expected central directory entry not found! Index: " + i);
				}

				fileHeader.setSignature(signature);

				// Made version
				System.arraycopy(readBuffer, pos + 4, shortBuffer, 0, 2);
				fileHeader.setMadeVersion(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Extract needed
				System.arraycopy(readBuffer, pos + 6, shortBuffer, 0, 2);
				fileHeader.setExtractNeeded(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Purpose bit flag
				System.arraycopy(readBuffer, pos + 8, shortBuffer, 0, 2);
				fileHeader.setFileNameUTF8Encoded(
						(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN) & Globals.UFT8_NAMES_FLAG) != 0);
				int firstByte = shortBuffer[0];
				fileHeader.setGeneralPurposeFlag(shortBuffer.clone());
				fileHeader.setDataDescriptorExists((firstByte >> 3) == 1);

				// Compression method
				System.arraycopy(readBuffer, pos + 10, shortBuffer, 0, 2);
				fileHeader.setCompressionMethod(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Last modify file time
				System.arraycopy(readBuffer, pos + 12, intBuffer, 0, 4);
				fileHeader.setLastModFileTime(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Crc32
				System.arraycopy(readBuffer, pos + 16, intBuffer, 0, 4);
				fileHeader.setCrc32(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));
				fileHeader.setCrcBuffer(intBuffer.clone());

				// Compressed size
				System.arraycopy(readBuffer, pos + 20, intBuffer, 0, 4);
				fileHeader.setCompressedSize(RawUtils.readLong(readLongByteFromIntByte(intBuffer), 0, ByteOrder.LITTLE_ENDIAN));

				// Original size
				System.arraycopy(readBuffer, pos + 24, intBuffer, 0, 4);
				fileHeader.setOriginalSize(RawUtils.readLong(readLongByteFromIntByte(intBuffer), 0, ByteOrder.LITTLE_ENDIAN));

				// File name length
				System.arraycopy(readBuffer, pos + 28, shortBuffer, 0, 2);
				fileHeader.setFileNameLength(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Extra field length
				System.arraycopy(readBuffer, pos + 30, shortBuffer, 0, 2);
				fileHeader.setExtraFieldLength(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Comment length
				System.arraycopy(readBuffer, pos + 32, shortBuffer, 0, 2);
				fileHeader.setFileCommentLength(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Disk number of start
				System.arraycopy(readBuffer, pos + 34, shortBuffer, 0, 2);
				fileHeader.setDiskNumberStart(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				// Internal file attributes
				System.arraycopy(readBuffer, pos + 36, shortBuffer, 0, 2);
				fileHeader.setInternalFileAttr(shortBuffer.clone());

				// External file attributes
				System.arraycopy(readBuffer, pos + 38, intBuffer, 0, 4);
				fileHeader.setExternalFileAttr(intBuffer.clone());

				// Relative offset of local header
				System.arraycopy(readBuffer, pos + 42, intBuffer, 0, 4);
				fileHeader.setOffsetLocalHeader(
						RawUtils.readLong(readLongByteFromIntByte(intBuffer), 0, ByteOrder.LITTLE_ENDIAN) & 0xFFFFFFFFL);

				if (fileHeader.getFileNameLength() > 0) {
					byte[] fileNameBuffer = new byte[fileHeader.getFileNameLength()];
					System.arraycopy(readBuffer, pos + 46, fileNameBuffer, 0, fileHeader.getFileNameLength());

					String entryPath = new String(fileNameBuffer, this.charsetEncoding);

					if (entryPath.contains(Globals.DEFAULT_ZIP_ENTRY_SEPARATOR)) {
						entryPath = entryPath.substring(entryPath.indexOf(Globals.DEFAULT_ZIP_ENTRY_SEPARATOR)
								+ Globals.DEFAULT_ZIP_ENTRY_SEPARATOR.length());
					}

					fileHeader.setEntryPath(entryPath);
					if (entryPath.endsWith(Globals.DEFAULT_ZIP_PAGE_SEPARATOR)
							|| entryPath.endsWith(Globals.DEFAULT_PAGE_SEPARATOR)) {
						fileHeader.setDirectory(true);
					} else {
						fileHeader.setDirectory(Boolean.FALSE);
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
					System.arraycopy(readBuffer,
							pos + 46 + fileHeader.getFileNameLength() + fileHeader.getExtraFieldLength(),
							commentBuffer, 0, fileHeader.getFileCommentLength());
					fileHeader.setFileComment(new String(commentBuffer, this.charsetEncoding));
				}
				fileHeaderList.add(fileHeader);
				pos += (46 + fileHeader.getFileNameLength() + fileHeader.getExtraFieldLength() + fileHeader.getFileCommentLength());
			}

			this.centralDirectory = new CentralDirectory();

			this.centralDirectory.setFileHeaders(fileHeaderList);

			System.arraycopy(readBuffer, pos, intBuffer, 0, 4);
			int signature = RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN);
			if (signature == Globals.DIGSIG) {
				DigitalSignature digitalSignature = new DigitalSignature();

				digitalSignature.setSignature(signature);

				System.arraycopy(readBuffer, pos + 4, shortBuffer, 0, 2);
				digitalSignature.setDataSize(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

				if (digitalSignature.getDataSize() > 0) {
					byte[] signatureDataBuffer = new byte[digitalSignature.getDataSize()];
					System.arraycopy(readBuffer, pos + 6, signatureDataBuffer,
							0, digitalSignature.getDataSize());
					digitalSignature.setSignatureData(new String(signatureDataBuffer, this.charsetEncoding));
				}

				this.centralDirectory.setDigitalSignature(digitalSignature);
			}
		} catch (IOException | DataInvalidException e) {
			throw new ZipException("read Central Directory error! ", e);
		}
	}

	private void readZip64EndCentralDirectoryRecord(StandardFile input)
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
			if (input.read(readBuffer) == Globals.DEFAULT_VALUE_INT) {
				return;
			}

			byte[] shortBuffer = new byte[2];
			byte[] intBuffer = new byte[4];
			byte[] longBuffer = new byte[8];

			int signature = this.readSignature(readBuffer);
			if (signature != Globals.ZIP64ENDCENDIRREC) {
				throw new ZipException("Invalid signature for zip64 end of central directory record");
			}
			this.zip64EndCentralDirectoryRecord.setSignature(signature);

			// Read the size of zip64 end of central directory record
			System.arraycopy(readBuffer, 4, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord.setRecordSize(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Made version
			System.arraycopy(readBuffer, 12, shortBuffer, 0, 2);
			this.zip64EndCentralDirectoryRecord.setMadeVersion(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Extract needed
			System.arraycopy(readBuffer, 14, shortBuffer, 0, 2);
			this.zip64EndCentralDirectoryRecord.setExtractNeeded(RawUtils.readShort(shortBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Number of these disks
			System.arraycopy(readBuffer, 16, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryRecord.setIndex(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Start of central directory
			System.arraycopy(readBuffer, 20, intBuffer, 0, 4);
			this.zip64EndCentralDirectoryRecord
					.setStartOfCentralDirectory(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Total of entries in the central directory on this disk
			System.arraycopy(readBuffer, 24, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setTotalEntriesInCentralDirectoryOnThisDisk(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Total of entries in the central directory
			System.arraycopy(readBuffer, 32, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setTotalEntriesInCentralDirectory(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Size of the central directory
			System.arraycopy(readBuffer, 40, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setSizeOfCentralDirectory(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Offset start of central directory with respect to the starting
			// disk number
			System.arraycopy(readBuffer, 48, longBuffer, 0, 8);
			this.zip64EndCentralDirectoryRecord
					.setOffsetStartCenDirWRTStartDiskNo(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));

			// Zip64 extensible data sector
			long extDataSize = zip64EndCentralDirectoryRecord.getRecordSize() - 44L;
			if (extDataSize > 0) {
				byte[] extensibleDataSector = new byte[(int) extDataSize];
				if (input.read(extensibleDataSector) > 0) {
					this.zip64EndCentralDirectoryRecord.setExtensibleDataSector(extensibleDataSector);
				}
			}

			this.splitArchive |= (this.zip64EndCentralDirectoryRecord.getIndex() > 0);
		} catch (IOException | DataInvalidException e) {
			throw new ZipException("read Zip64 End Central Directory Record error! ", e);
		}
	}

	private static void readAndSaveAESExtraDataRecord(FileHeader fileHeader) throws ZipException {
		if (fileHeader == null) {
			throw new ZipException("File header is null!");
		}

		if (fileHeader.getExtraDataRecords() != null && !fileHeader.getExtraDataRecords().isEmpty()) {
			for (ExtraDataRecord extraDataRecord : fileHeader.getExtraDataRecords()) {
				if (extraDataRecord != null) {
					if (extraDataRecord.getHeader() == ((short) Globals.AESSIG)) {
						if (extraDataRecord.getDataContent() == null) {
							throw new ZipException("Corrupt AES extra data records");
						}

						AESExtraDataRecord aesExtraDataRecord = new AESExtraDataRecord();

						aesExtraDataRecord.setSignature(Globals.AESSIG);
						aesExtraDataRecord.setDataSize(extraDataRecord.getDataSize());

						try {
							byte[] aesData = extraDataRecord.getDataContent();
							aesExtraDataRecord.setVersionNumber(RawUtils.readShort(aesData, 0, ByteOrder.LITTLE_ENDIAN));

							byte[] vendorIDBuffer = new byte[2];
							System.arraycopy(aesData, 2, vendorIDBuffer, 0, 2);
							aesExtraDataRecord.setVendorID(new String(vendorIDBuffer, StandardCharsets.UTF_8));
							aesExtraDataRecord.setAesStrength((aesData[4] & 0xFF));
							aesExtraDataRecord.setCompressionMethod(RawUtils.readShort(aesData, 5, ByteOrder.LITTLE_ENDIAN));
						} catch (DataInvalidException e) {
							throw new ZipException("read And Save AES Extra Data Record error", e);
						}
						fileHeader.setAesExtraDataRecord(aesExtraDataRecord);
						fileHeader.setEncryptionMethod(Globals.ENC_METHOD_AES);
						break;
					}
				}
			}
		}
	}

	private static Zip64ExtendInfo readZip64ExtendInfo(List<ExtraDataRecord> extraDataRecords, long originalSize,
	                                                   long compressedSize, long offsetLocalHeader, int diskNumberStart) throws ZipException {
		for (ExtraDataRecord extraDataRecord : extraDataRecords) {
			if (extraDataRecord.getHeader() == 0x0001) {
				if (extraDataRecord.getDataSize() <= 0) {
					break;
				}

				byte[] intBuffer = new byte[4];
				byte[] longBuffer = new byte[8];
				int count = 0;
				boolean addValue = Boolean.FALSE;

				Zip64ExtendInfo zip64ExtendInfo = new Zip64ExtendInfo();

				try {
					if ((originalSize & 0xFFFF) == 0xFFFF) {
						System.arraycopy(extraDataRecord.getDataContent(), count, longBuffer, 0, 8);
						zip64ExtendInfo.setOriginalSize(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));
						count += 8;
						addValue = Boolean.TRUE;
					}

					if (((compressedSize & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
						System.arraycopy(extraDataRecord.getDataContent(), count, longBuffer, 0, 8);
						zip64ExtendInfo.setCompressedSize(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));
						count += 8;
						addValue = Boolean.TRUE;
					}

					if (((offsetLocalHeader & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
						System.arraycopy(extraDataRecord.getDataContent(), count, longBuffer, 0, 8);
						zip64ExtendInfo.setOffsetLocalHeader(RawUtils.readLong(longBuffer, 0, ByteOrder.LITTLE_ENDIAN));
						count += 8;
						addValue = Boolean.TRUE;
					}

					if (((diskNumberStart & 0xFFFF) == 0xFFFF) && count < extraDataRecord.getDataSize()) {
						System.arraycopy(extraDataRecord.getDataContent(), count, intBuffer, 0, 4);
						zip64ExtendInfo.setDiskNumberStart(RawUtils.readInt(intBuffer, 0, ByteOrder.LITTLE_ENDIAN));
						addValue = Boolean.TRUE;
					}
				} catch (DataInvalidException e) {
					throw new ZipException("read Zip64 Extend Info error! ", e);
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

		Zip64ExtendInfo zip64ExtendInfo = null;
		if (fileHeader instanceof GeneralFileHeader) {
			if (fileHeader.getExtraDataRecords() != null && !fileHeader.getExtraDataRecords().isEmpty()) {
				zip64ExtendInfo = readZip64ExtendInfo(fileHeader.getExtraDataRecords(),
						fileHeader.getOriginalSize(), fileHeader.getCompressedSize(),
						((GeneralFileHeader) fileHeader).getOffsetLocalHeader(),
						((GeneralFileHeader) fileHeader).getDiskNumberStart());
				if (zip64ExtendInfo != null) {
					if (zip64ExtendInfo.getOffsetLocalHeader() != -1) {
						((GeneralFileHeader) fileHeader).setOffsetLocalHeader(zip64ExtendInfo.getOffsetLocalHeader());
					}

					if (zip64ExtendInfo.getDiskNumberStart() != -1) {
						((GeneralFileHeader) fileHeader).setDiskNumberStart(zip64ExtendInfo.getDiskNumberStart());
					}
				}
			}
		} else if (fileHeader instanceof LocalFileHeader) {
			if (fileHeader.getExtraDataRecords() == null || fileHeader.getExtraDataRecords().isEmpty()) {
				return;
			}

			zip64ExtendInfo = readZip64ExtendInfo(fileHeader.getExtraDataRecords(),
					fileHeader.getOriginalSize(), fileHeader.getCompressedSize(), Globals.DEFAULT_VALUE_LONG,
					Globals.DEFAULT_VALUE_INT);
		} else {
			throw new ZipException("Unknown file header");
		}

		if (zip64ExtendInfo != null) {
			fileHeader.setZip64ExtendInfo(zip64ExtendInfo);
			if (zip64ExtendInfo.getOriginalSize() != -1) {
				fileHeader.setOriginalSize(zip64ExtendInfo.getOriginalSize());
			}

			if (zip64ExtendInfo.getCompressedSize() != -1) {
				fileHeader.setCompressedSize(zip64ExtendInfo.getCompressedSize());
			}

		}
	}

	private static List<ExtraDataRecord> readExtraDataRecords(byte[] extraFieldBuffer, int extraFieldLength)
			throws ZipException {
		int count = 0;
		List<ExtraDataRecord> extraDataRecords = new ArrayList<>();

		while (count < extraFieldLength) {
			ExtraDataRecord extraDataRecord = new ExtraDataRecord();
			try {
				extraDataRecord.setHeader(RawUtils.readShort(extraFieldBuffer, count, ByteOrder.LITTLE_ENDIAN));

				count += 2;

				int dataSize = RawUtils.readShort(extraFieldBuffer, count, ByteOrder.LITTLE_ENDIAN);

				if ((dataSize + 2) > extraFieldLength) {
					dataSize = RawUtils.readShort(extraFieldBuffer, count, ByteOrder.BIG_ENDIAN);
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
			} catch (DataInvalidException e) {
				throw new ZipException("read Extra Data Records error! ", e);
			}
			extraDataRecords.add(extraDataRecord);
		}

		if (!extraDataRecords.isEmpty()) {
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

		return new byte[]{intByte[0], intByte[1], intByte[2], intByte[3], 0, 0, 0, 0};
	}

	private static int readIntFromDataInput(StandardFile input, byte[] bytes) throws ZipException {
		try {
			if (input.read(bytes, 0, 4) == 4) {
				return RawUtils.readInt(bytes, 0, ByteOrder.LITTLE_ENDIAN);
			}
		} catch (IOException | DataInvalidException e) {
			throw new ZipException("read Int From Data Input error! ", e);
		}
		throw new ZipException("Invalid binary data");
	}

	private static void setFileReadOnly(File file) throws ZipException {
		if (file == null) {
			throw new ZipException("input file is null. cannot set read only file attribute");
		}

		if (!file.exists() || !file.setReadOnly()) {
			throw new ZipException("Process file read only attribute error! ");
		}
	}

	private static void setFileLastModify(File file, long lastModify) throws ZipException {
		if (file == null) {
			throw new ZipException("input file is null. cannot set read only file attribute");
		}

		if (lastModify < 0L) {
			throw new ZipException("last modify time invalid");
		}

		if (!file.exists() || !file.setLastModified(lastModify)) {
			throw new ZipException("Process file last modify attribute error! ");
		}
	}
}
