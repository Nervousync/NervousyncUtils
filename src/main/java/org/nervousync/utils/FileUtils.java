/*
 * Licensed to the Nervousync Studio (NSYC) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
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
package org.nervousync.utils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.CRC32;

import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;
import jcifs.smb.SmbFileOutputStream;

import org.nervousync.beans.files.FileExtensionInfo;
import org.nervousync.beans.xml.files.SegmentationFile;
import org.nervousync.beans.xml.files.SegmentationItem;
import org.nervousync.commons.core.Globals;
import org.nervousync.commons.core.MIMETypes;
import org.nervousync.zip.ZipFile;

/**
 * File operate utils
 * support zip/unzip Files Folders
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@Hotmail.com">wmkm0113@Hotmail.com</a>
 * @version $Revision : 1.0 $ $Date: Jan 13, 2010 11:08:14 AM $
 */
public final class FileUtils {

	private transient static final Logger LOGGER = LoggerFactory.getLogger(FileUtils.class);

	/**
	 * URL prefixes for loading from the class path: "classpath:"
	 */
	public static final String CLASSPATH_URL_PREFIX = "classpath:";

	/**
	 * URL prefixes for loading from the file system: "file:"
	 */
	public static final String FILE_URL_PREFIX = "file:";

	/**
	 * URL prefixes for loading from the samba path: "smb:"
	 */
	public static final String SAMBA_URL_PREFIX = "smb:";

	/**
	 * URL protocol for a file in the file system: "file"
	 */
	public static final String URL_PROTOCOL_FILE = "file";

	/**
	 * URL protocol for an entry from a jar file: "jar"
	 */
	public static final String URL_PROTOCOL_JAR = "jar";

	/**
	 * URL protocol for an entry from a zip file: "zip"
	 */
	public static final String URL_PROTOCOL_ZIP = "zip";

	/**
	 * URL protocol for an entry from a WebSphere jar file: "wsjar"
	 */
	public static final String URL_PROTOCOL_WSJAR = "wsjar";

	/**
	 * URL protocol for an entry from an OC4J jar file: "code-source"
	 */
	public static final String URL_PROTOCOL_CODE_SOURCE = "code-source";

	/**
	 * Separator between JAR URL and file path within the JAR
	 */
	public static final String JAR_URL_SEPARATOR = "!/";

	/**
	 * Line break character
	 */
	public static final String NEWLINE_CHARACTER = "\n";

	/**
	 * Registered identified map
	 */
	private static final Hashtable<String, FileExtensionInfo> REGISTER_IDENTIFIED_MAP = new Hashtable<>();

	/**
	 * Define file type code for picture
	 */
	public static final int FILE_TYPE_PIC 				= 0;
	/**
	 * Define file type code for audio
	 */
	public static final int FILE_TYPE_AUDIO 			= 1;
	/**
	 * Define file type code for video
	 */
	public static final int FILE_TYPE_VIDEO 			= 2;
	/**
	 * Define file type code for jar
	 */
	public static final int FILE_TYPE_JAVA_PACKAGE 		= 3;
	/**
	 * Define file type code for java
	 */
	public static final int FILE_TYPE_JAVA_FILE 		= 4;
	/**
	 * Define file type code for java class
	 */
	public static final int FILE_TYPE_JAVA_CLASS 		= 5;
	/**
	 * Define file type code for properties
	 */
	public static final int FILE_TYPE_JAVA_RESOURCE 	= 6;
	/**
	 * Define file type code for compress
	 */
	public static final int FILE_TYPE_COMPRESS 			= 7;
	/**
	 * Define file type code for document
	 */
	public static final int FILE_TYPE_DOCUMENT 			= 8;
	/**
	 * Define file type code for xml
	 */
	public static final int FILE_TYPE_XML 				= 9;
	/**
	 * Define file type code for xml
	 */
	public static final int FILE_TYPE_JSON 				= 10;
	/**
	 * Define file type code for access database
	 */
	public static final int FILE_TYPE_DATABASE_FILE 	= 11;
	/**
	 * Define file type code for sql
	 */
	public static final int FILE_TYPE_DATABASE_SQL 		= 12;
	/**
	 * Define file type code for Outlook email configure
	 */
	public static final int FILE_TYPE_EMAIL_CONF 		= 13;
	/**
	 * Define file type code for eml
	 */
	public static final int FILE_TYPE_EMAIL_DOCUMENT 	= 14;
	/**
	 * Define file type code for html
	 */
	public static final int FILE_TYPE_WEB_HTML 			= 15;
	/**
	 * Define file type code for javascript
	 */
	public static final int FILE_TYPE_WEB_JS 			= 16;
	/**
	 * Define file type code for css
	 */
	public static final int FILE_TYPE_WEB_CSS 			= 17;
	/**
	 * Define file type code for unknown
	 */
	public static final int FILE_TYPE_UNKNOWN 			= 18;

	private FileUtils() {
	}

	static {
		FileUtils.registerFileType();
	}

	/**
	 * Register user define file type
	 *
	 * @param extensionName  file extension name
	 * @param identifiedCode file identified code
	 * @param fileType       file type code
	 * @param printing       file is ready for printing
	 */
	public static void registerFileType(String extensionName, String identifiedCode,
	                                    int fileType, boolean printing) {
		FileUtils.checkRegisterFileType(extensionName);
		extensionName = extensionName.toLowerCase();
		FileUtils.REGISTER_IDENTIFIED_MAP.put(extensionName,
				new FileExtensionInfo(extensionName, identifiedCode, null, fileType, printing));
	}

	/**
	 * Register user define file type
	 *
	 * @param extensionName  file extension name
	 * @param identifiedCode file identified code
	 * @param mimeType       file mime type
	 * @param fileType       file type code
	 * @param printing       file is ready for printing
	 */
	public static void registerFileType(String extensionName, String identifiedCode, String mimeType,
	                                    int fileType, boolean printing) {
		FileUtils.checkRegisterFileType(extensionName);
		extensionName = extensionName.toLowerCase();

		if (mimeType == null) {
			mimeType = MIMETypes.MIME_TYPE_BINARY;
		}

		FileUtils.REGISTER_IDENTIFIED_MAP.put(extensionName,
				new FileExtensionInfo(extensionName, identifiedCode, mimeType, fileType, printing));
	}

	/**
	 * Match folder path in entry path
	 *
	 * @param entryPath  entry path
	 * @param folderPath folder path
	 * @return Match result
	 */
	public static boolean matchFolder(String entryPath, String folderPath) {
		if (entryPath == null || folderPath == null) {
			return Boolean.FALSE;
		}

		String convertFolderPath = FileUtils.replacePageSeparator(folderPath) + "|";
		return FileUtils.replacePageSeparator(entryPath).startsWith(convertFolderPath);
	}

	/**
	 * Match two path was same
	 *
	 * @param origPath   orig path
	 * @param destPath   dest path
	 * @param ignoreCase ignore character case
	 * @return Match result
	 */
	public static boolean matchFilePath(String origPath, String destPath, boolean ignoreCase) {
		if (origPath == null || destPath == null) {
			return Boolean.FALSE;
		}

		String origConvert = FileUtils.replacePageSeparator(origPath);
		String destConvert = FileUtils.replacePageSeparator(destPath);

		if (ignoreCase) {
			return origConvert.equalsIgnoreCase(destConvert);
		} else {
			return origConvert.equals(destConvert);
		}
	}

	/**
	 * Check the resource location is compressed jar file
	 *
	 * @param resourceLocation resource location
	 * @return check status
	 * @throws FileNotFoundException resource location file was not exists
	 */
	public static boolean isJarFile(String resourceLocation) throws FileNotFoundException {
		if (resourceLocation == null) {
			throw new FileNotFoundException("The resource location is null!");
		}

		if (FileUtils.retrieveFileType(StringUtils.getFilenameExtension(resourceLocation))
				== FileUtils.FILE_TYPE_JAVA_PACKAGE) {
			return FileUtils.validateFileType(resourceLocation);
		}
		return Boolean.FALSE;
	}

	/**
	 * Retrieve exists file type code
	 *
	 * @param extensionName extension name
	 * @return found file type code or #FILE_TYPE_UNKNOWN for not found or file identify code check error
	 */
	public static int retrieveFileType(String extensionName) {
		if (extensionName != null) {
			extensionName = extensionName.toLowerCase();
			FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName);
			if (fileExtensionInfo != null) {
				return fileExtensionInfo.getFileType();
			}
		}

		return FileUtils.FILE_TYPE_UNKNOWN;
	}

	/**
	 * Retrieve MIMEType string
	 *
	 * @param extensionName extension name
	 * @return MIMEType string
	 */
	public static String retrieveMimeType(String extensionName) {
		if (extensionName != null) {
			extensionName = extensionName.toLowerCase();
			FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName);
			if (fileExtensionInfo != null) {
				return fileExtensionInfo.getMimeType();
			}
		}

		return MIMETypes.MIME_TYPE_BINARY;
	}

	/**
	 * Validate resource file with identify code
	 *
	 * @param resourceLocation resource location
	 * @return validate result
	 */
	public static boolean validateFileType(String resourceLocation) {
		if (resourceLocation == null) {
			return Boolean.FALSE;
		}

		String extensionName = StringUtils.getFilenameExtension(resourceLocation);
		extensionName = extensionName.toLowerCase();
		FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName.toLowerCase());
		if (fileExtensionInfo != null) {
			byte[] fileTypeByte = FileUtils.readFileBytes(resourceLocation, 0,
					fileExtensionInfo.getIdentifiedCode().length() / 2);
			String fileType = ConvertUtils.byteToHex(fileTypeByte);
			return fileType.equalsIgnoreCase(fileExtensionInfo.getIdentifiedCode());
		}
		return Boolean.FALSE;
	}

	/**
	 * Identified file type
	 *
	 * @param extensionName extension name
	 * @param fileContent   File data as byte arrays
	 * @return identified result
	 */
	public static boolean validateFileType(String extensionName, byte[] fileContent) {
		FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName.toLowerCase());
		if (fileExtensionInfo != null) {
			int identifiedLength = fileExtensionInfo.getIdentifiedCode().length() / 2;
			if (fileContent.length < identifiedLength) {
				return Boolean.FALSE;
			}
			byte[] fileTypeByte = new byte[identifiedLength];

			System.arraycopy(fileContent, 0, fileTypeByte, 0, identifiedLength);

			String fileType = ConvertUtils.byteToHex(fileTypeByte);
			return fileType.equalsIgnoreCase(fileExtensionInfo.getIdentifiedCode());
		}

		return Boolean.FALSE;
	}

	/**
	 * Retrieve file extension name with file identified code
	 *
	 * @param identifiedByteCode identified code
	 * @return matched file extension name
	 */
	public static String identifiedFileType(byte[] identifiedByteCode) {
		String identifiedCode = ConvertUtils.byteToHex(identifiedByteCode);
		for (FileExtensionInfo fileExtensionInfo : FileUtils.REGISTER_IDENTIFIED_MAP.values()) {
			if (identifiedCode.startsWith(fileExtensionInfo.getIdentifiedCode())) {
				return fileExtensionInfo.getExtensionName();
			}
		}
		return null;
	}

	/**
	 * Return whether the given resource location is a URL:
	 * either a special "classpath" pseudo URL or a standard URL.
	 *
	 * @param resourceLocation the location String to check
	 * @return true when location qualifies as a URL, Boolean.FALSE for others
	 * @see java.net.URL
	 */
	public static boolean isUrl(String resourceLocation) {
		if (!FileUtils.isExists(resourceLocation)) {
			return Boolean.FALSE;
		}

		try {
			new URL(resourceLocation);
			return true;
		} catch (MalformedURLException ex) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Resolve the given resource location to a <code>java.net.URL</code>.
	 * <p>Does not check whether the URL actually exists; simply returns
	 * the URL that the given location would correspond to.
	 *
	 * @param resourceLocation the resource location to resolve: either a "classpath:" pseudo URL, a "file:" URL, or a plain file path
	 * @return a corresponding URL object
	 * @throws FileNotFoundException if the resource cannot be resolved to a URL
	 */
	public static URL getURL(String resourceLocation) throws FileNotFoundException {
		if (resourceLocation == null) {
			throw new IllegalArgumentException("Resource location must not be null");
		}
		if (resourceLocation.startsWith(CLASSPATH_URL_PREFIX)) {
			String path = resourceLocation.substring(CLASSPATH_URL_PREFIX.length());
			URL url = ClassUtils.getDefaultClassLoader().getResource(path);
			if (url == null) {
				String description = "class path resource [" + path + "]";
				throw new FileNotFoundException(
						description + " cannot be resolved to URL because it does not exist");
			}
			return url;
		}
		try {
			// try URL
			return new URL(resourceLocation);
		} catch (MalformedURLException ex) {
			// no URL -> treat as file path
			try {
				return new File(resourceLocation).toURI().toURL();
			} catch (MalformedURLException ex2) {
				throw new FileNotFoundException("Resource location [" + resourceLocation +
						"] is neither a URL not a well-formed file path");
			}
		}
	}

	/**
	 * Read file last modified time
	 *
	 * @param resourceLocation resource location
	 * @return last modified time with long type if file exists
	 */
	public static long lastModify(String resourceLocation) {
		if (resourceLocation == null || resourceLocation.trim().length() == 0) {
			return Globals.DEFAULT_VALUE_LONG;
		}
		try {
			if (resourceLocation.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
				SmbFile smbFile = openSMBFile(resourceLocation);
				if (smbFile.exists()) {
					return smbFile.getLastModified();
				}
			} else {
				File file = FileUtils.getFile(resourceLocation);
				if (file.exists()) {
					return file.lastModified();
				}
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Read file last modify error! ", e);
			}
		}
		return Globals.DEFAULT_VALUE_LONG;
	}

	/**
	 * Read file last modified time
	 *
	 * @param resourceLocation resource location
	 * @return last modified time with <code>java.util.Date</code> type if file exists or null for others
	 */
	public static Date getLastModify(String resourceLocation) {
		long lastModify = FileUtils.lastModify(resourceLocation);
		if (lastModify != Globals.DEFAULT_VALUE_LONG) {
			return new Date(lastModify);
		} else {
			return null;
		}
	}

	/**
	 * Open Samba file input stream
	 *
	 * @param resourceLocation resource location
	 * @return input stream
	 * @throws IOException when opening input stream error
	 */
	public static InputStream loadSMBFile(String resourceLocation) throws IOException {
		if (resourceLocation == null || !resourceLocation.startsWith(SAMBA_URL_PREFIX)) {
			throw new IOException("SMB file path error! ");
		}
		return new SmbFileInputStream(resourceLocation, new BaseContext(new PropertyConfiguration(new Properties())));
	}

	/**
	 * Load resource and convert to java.io.InputStream used <code>Globals.DEFAULT_ENCODING</code>
	 *
	 * @param resourceLocation resource location
	 * @return <code>java.io.InputStream</code>
	 * @throws IOException when opening input stream error
	 */
	public static InputStream loadFile(String resourceLocation) throws IOException {
		//	Convert resource location to input stream
		InputStream inputStream = FileUtils.class.getResourceAsStream(resourceLocation);

		if (inputStream == null) {
			try {
				inputStream = FileUtils.getURL(resourceLocation).openStream();
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Open file input stream error! ", e);
				}
				throw new IOException(e);
			}
		}

		return inputStream;
	}

	/**
	 * Resolve the given resource location to a <code>java.io.File</code>,
	 * i.e. to a file in the file system.
	 * <p>Does not check whether the fil actually exists; simply returns
	 * the File that the given location would correspond to.
	 *
	 * @param resourceLocation the resource location to resolve: either a "classpath:" pseudo URL, a "file:" URL, or a plain file path
	 * @return a corresponding File object
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static File getFile(String resourceLocation) throws FileNotFoundException {
		if (resourceLocation == null) {
			throw new IllegalArgumentException("Resource location must not be null");
		}
		if (resourceLocation.startsWith(CLASSPATH_URL_PREFIX)) {
			String path = resourceLocation.substring(CLASSPATH_URL_PREFIX.length());
			String description = "class path resource [" + path + "]";
			URL url = ClassUtils.getDefaultClassLoader().getResource(path);
			if (url != null) {
				return getFile(url, description);
			}
		}

		try {
			// try URL
			return getFile(new URL(resourceLocation));
		} catch (MalformedURLException ex) {
			// no URL -> treat as file path
			return new File(resourceLocation);
		}
	}

	/**
	 * Resolve the given resource URL to a <code>java.io.File</code>,
	 * i.e. to a file in the file system.
	 *
	 * @param resourceUrl the resource URL to resolve
	 * @return a corresponding File object
	 * @throws FileNotFoundException if the URL cannot be resolved to a file in the file system
	 */
	public static File getFile(URL resourceUrl) throws FileNotFoundException {
		return getFile(resourceUrl, "URL");
	}

	/**
	 * Resolve the given resource URL to a <code>java.io.File</code>,
	 * i.e. to a file in the file system.
	 *
	 * @param resourceUrl the resource URL to resolve
	 * @param description a description of the original resource that the URL was created for (for example, a class path location)
	 * @return a corresponding File object
	 * @throws FileNotFoundException if the URL cannot be resolved to a file in the file system
	 */
	public static File getFile(URL resourceUrl, String description) throws FileNotFoundException {
		if (resourceUrl == null) {
			throw new IllegalArgumentException("Resource URL must not be null");
		}
		if (!URL_PROTOCOL_FILE.equals(resourceUrl.getProtocol())) {
			throw new FileNotFoundException(
					description + " cannot be resolved to absolute file path " +
							"because it does not reside in the file system: " + resourceUrl);
		}

		try {
			return new File(toURI(resourceUrl).getSchemeSpecificPart());
		} catch (URISyntaxException ex) {
			// Fallback for URLs that are not valid URIs (should hardly ever happen).
			return new File(resourceUrl.getFile());
		}
	}

	/**
	 * Resolve the given resource URI to a <code>java.io.File</code>,
	 * i.e. to a file in the file system.
	 *
	 * @param resourceUri the resource URI to resolve
	 * @return a corresponding File object
	 * @throws FileNotFoundException if the URL cannot be resolved to a file in the file system
	 */
	public static File getFile(URI resourceUri) throws FileNotFoundException {
		return getFile(resourceUri, "URI");
	}

	/**
	 * Resolve the given resource URI to a <code>java.io.File</code>,
	 * i.e. to a file in the file system.
	 *
	 * @param resourceUri the resource URI to resolve
	 * @param description a description of the original resource that the URI was created for (for example, a class path location)
	 * @return a corresponding File object
	 * @throws FileNotFoundException if the URL cannot be resolved to a file in the file system
	 */
	public static File getFile(URI resourceUri, String description) throws FileNotFoundException {
		if (resourceUri == null) {
			throw new IllegalArgumentException("Resource URI must not be null");
		}
		if (!URL_PROTOCOL_FILE.equals(resourceUri.getScheme())) {
			throw new FileNotFoundException(description + " cannot be resolved to absolute file path " +
					"because it does not reside in the file system: " + resourceUri);
		}
		return new File(resourceUri.getSchemeSpecificPart());
	}

	/**
	 * List jar entry list.
	 *
	 * @param filePath the file path
	 * @return the list
	 */
	public static List<String> listJarEntry(String filePath) {

		List<String> entryList = new ArrayList<>();
		try (JarFile jarFile = new JarFile(getFile(filePath))) {
			Enumeration<JarEntry> enumeration = jarFile.entries();
			while (enumeration.hasMoreElements()) {
				JarEntry jarEntry = enumeration.nextElement();
				if (!jarEntry.isDirectory()) {
					entryList.add(jarEntry.getName());
				}
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Load jar entry content error! ", e);
			}
		}

		return entryList;
	}

	/**
	 * Read jar entry info string.
	 *
	 * @param filePath  the file path
	 * @param entryPath the entry path
	 * @return the string
	 */
	public static String readJarEntryInfo(String filePath, String entryPath) {
		String entryContent = null;
		InputStream inputStream = null;
		InputStreamReader inputStreamReader = null;

		try {
			JarFile jarFile = new JarFile(getFile(filePath));

			JarEntry packageEntry = jarFile.getJarEntry(entryPath);

			if(packageEntry != null){
				inputStream = jarFile.getInputStream(packageEntry);
				inputStreamReader = new InputStreamReader(inputStream, Globals.DEFAULT_ENCODING);

				char [] readBuffer = new char[Globals.DEFAULT_BUFFER_SIZE];
				int readLength;
				StringBuilder returnValue = new StringBuilder();

				while (((readLength = inputStreamReader.read(readBuffer)) > -1)) {
					returnValue.append(readBuffer, 0, readLength);
				}

				entryContent = returnValue.toString();
			}

			jarFile.close();
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Load jar entry content error! ", e);
			}
		} finally {
			IOUtils.closeStream(inputStreamReader);
			IOUtils.closeStream(inputStream);
		}

		return entryContent;
	}

	/**
	 * Read entry content from jar file
	 *
	 * @param filePath  jar file location
	 * @param entryPath read entry path
	 * @return entry content or zero length array if not exists
	 */
	public static byte[] readJarEntryBytes(String filePath, String entryPath) {
		return FileUtils.readJarEntryBytes(filePath, entryPath, 0, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * Read entry content from jar file
	 *
	 * @param filePath  jar file location
	 * @param entryPath read entry path
	 * @param offset    read offset
	 * @param length    read length
	 * @return entry content or zero length array if not exists
	 */
	public static byte[] readJarEntryBytes(String filePath, String entryPath, int offset, int length) {
		JarFile jarFile = null;
		InputStream inputStream = null;
		ByteArrayOutputStream byteArrayOutputStream = null;

		try {
			jarFile = new JarFile(getFile(filePath));

			JarEntry packageEntry = jarFile.getJarEntry(entryPath);

			if (packageEntry != null) {
				inputStream = jarFile.getInputStream(packageEntry);
				byteArrayOutputStream = new ByteArrayOutputStream();

				byte [] buffer;
				int readLength = 0;
				int position = Math.max(offset, Globals.INITIALIZE_INT_VALUE);
				int limitLength = Math.min(length, inputStream.available());
				do {
					int itemLength = Math.min((limitLength - readLength), Globals.DEFAULT_BUFFER_SIZE);
					buffer = new byte[itemLength];
					int currentLength = inputStream.read(buffer, position + readLength, itemLength);
					if (currentLength == itemLength) {
						byteArrayOutputStream.write(buffer, 0, buffer.length);
					} else if (currentLength == Globals.DEFAULT_VALUE_INT) {
						break;
					}
					readLength += itemLength;
				} while (readLength != limitLength);

				return byteArrayOutputStream.toByteArray();
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Load jar entry content error! ", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
			IOUtils.closeStream(byteArrayOutputStream);
			IOUtils.closeStream(jarFile);
		}
		return new byte[0];
	}

	/**
	 * Read resource content
	 *
	 * @param file object
	 * @return File data by byte arrays
	 * @throws IOException if an I/O error occurs
	 */
	public static byte[] readFileBytes(File file) throws IOException {
		if (file == null || !file.exists()) {
			throw new IOException("File not found");
		}

		byte[] content;
		try {
			content = IOUtils.readBytes(new FileInputStream(file));
		} catch (FileNotFoundException e) {
			content = new byte[0];
		}

		return content;
	}

	/**
	 * Read resource content
	 *
	 * @param resourceLocation Resource location
	 * @return File data by byte arrays
	 * @throws IOException if an I/O error occurs
	 */
	public static byte[] readFileBytes(String resourceLocation) throws IOException {
		return FileUtils.readFileBytes(FileUtils.getFile(resourceLocation));
	}

	/**
	 * Read resource content info in define length
	 *
	 * @param resourceLocation resource location
	 * @param position         start point
	 * @param length           read length
	 * @return File data by byte arrays
	 */
	public static byte[] readFileBytes(String resourceLocation, long position, int length) {
		byte[] readByte = new byte[length];

		try (RandomAccessFile randomAccessFile = new RandomAccessFile(resourceLocation, "r")) {
			randomAccessFile.seek(position);
			randomAccessFile.read(readByte);
		} catch (Exception e) {
			readByte = new byte[0];
		}

		return readByte;
	}

	/**
	 * Retrieve SMB file size
	 *
	 * @param resourceLocation resource location
	 * @return File size
	 */
	public static long getSMBFileSize(String resourceLocation) {
		try {
			SmbFile smbFile = openSMBFile(resourceLocation);
			return smbFile.length();
		} catch (Exception e) {
			return 0L;
		}
	}

	/**
	 * Retrieve resource location size
	 *
	 * @param resourceLocation resource location
	 * @return File size
	 */
	public static long getFileSize(String resourceLocation) {
		try {
			return getFileSize(FileUtils.getFile(resourceLocation));
		} catch (FileNotFoundException e) {
			return 0L;
		}
	}

	/**
	 * Retrieve file size
	 *
	 * @param file File object
	 * @return File size
	 */
	public static long getFileSize(File file) {
		long fileSize = 0L;

		if (file != null) {
			if (file.exists()) {
				if (file.isDirectory()) {
					File[] childFiles = file.listFiles();
					if (childFiles != null) {
						for (File childFile : childFiles) {
							fileSize += getFileSize(childFile);
						}
					}
				} else if (file.isFile()) {
					fileSize += file.length();
				}
			}
		}

		return fileSize;
	}

	/**
	 * Determine whether the given URL points to a resource in a jar file,
	 * that is, has protocol "jar", "zip", "wsjar" or "code-source".
	 * <p>"zip" and "wsjar" are used by BEA WebLogic Server and IBM WebSphere, respectively,
	 * but can be treated like jar files. The same applies to "code-source" URLs on Oracle
	 * OC4J, provided that the path contains a jar separator.
	 *
	 * @param url the URL to check
	 * @return whether the URL has been identified as a JAR URL
	 */
	public static boolean isJarURL(URL url) {
		String protocol = url.getProtocol();
		return (URL_PROTOCOL_JAR.equals(protocol) ||
				URL_PROTOCOL_ZIP.equals(protocol) ||
				URL_PROTOCOL_WSJAR.equals(protocol) ||
				(URL_PROTOCOL_CODE_SOURCE.equals(protocol) && url.getPath().contains(JAR_URL_SEPARATOR)));
	}

	/**
	 * Extract the URL for the actual jar file from the given URL
	 * (which may point to a resource in a jar file or to a jar file itself).
	 *
	 * @param jarUrl the original URL
	 * @return the URL for the actual jar file
	 * @throws MalformedURLException if no valid jar file URL could be extracted
	 */
	public static URL extractJarFileURL(URL jarUrl) throws MalformedURLException {
		String urlFile = jarUrl.getFile();
		int separatorIndex = urlFile.indexOf(JAR_URL_SEPARATOR);
		if (separatorIndex != -1) {
			String jarFile = urlFile.substring(0, separatorIndex);
			try {
				return new URL(jarFile);
			} catch (MalformedURLException ex) {
				// Probably no protocol in original jar URL, like "jar:C:/path/jarFile.jar".
				// This usually indicates that the jar file resides in the file system.
				if (!jarFile.startsWith("/")) {
					jarFile = "/" + jarFile;
				}
				return new URL(FILE_URL_PREFIX + jarFile);
			}
		} else {
			return jarUrl;
		}
	}

	/**
	 * Create a URI instance for the given URL,
	 * replacing spaces with "%20" quotes first.
	 * <p>Furthermore, this method works on JDK 1.4 as well,
	 * in contrast to the <code>URL.toURI()</code> method.
	 *
	 * @param url the URL to convert into a URI instance
	 * @return the URI instance
	 * @throws URISyntaxException if the URL wasn't a valid URI
	 * @see java.net.URL#toURI() java.net.URL#toURI()java.net.URL#toURI()
	 */
	public static URI toURI(URL url) throws URISyntaxException {
		return FileUtils.toURI(url.toString());
	}

	/**
	 * Create a URI instance for the given location String,
	 * replacing spaces with "%20" quotes first.
	 *
	 * @param location the location String to convert into a URI instance
	 * @return the URI instance
	 * @throws URISyntaxException if the location wasn't a valid URI
	 */
	public static URI toURI(String location) throws URISyntaxException {
		return new URI(StringUtils.replace(location, " ", "%20"));
	}

	/**
	 * List jar entry
	 *
	 * @param uri Jar file URI
	 * @return List of entry names
	 */
	public static List<String> listJarEntry(URI uri) {
		List<String> returnList = new ArrayList<>();

		if (uri != null) {
			String fullPath = uri.getPath();
			String filePath;
			String entryPath = null;
			if (fullPath.indexOf(JAR_URL_SEPARATOR) > 0) {
				filePath = fullPath.substring(0, fullPath.indexOf(JAR_URL_SEPARATOR));
				entryPath = fullPath.substring(fullPath.indexOf(JAR_URL_SEPARATOR) + JAR_URL_SEPARATOR.length());
			} else {
				filePath = fullPath;
			}

			if (FileUtils.isExists(filePath)) {
				JarFile jarFile = null;
				try {
					File file = FileUtils.getFile(filePath);
					if (file.isDirectory()) {
						returnList = FileUtils.listFiles(file);
					} else if (file.isFile()) {
						jarFile = new JarFile(file);
						Enumeration<JarEntry> enumeration = jarFile.entries();

						while (enumeration.hasMoreElements()) {
							JarEntry jarEntry = enumeration.nextElement();
							if (jarEntry.isDirectory()) {
								continue;
							}
							String entryName = jarEntry.getName();
							if (entryPath == null || entryName.startsWith(entryPath)) {
								returnList.add(entryName);
							}
						}
					}
				} catch (Exception e) {
					returnList = new ArrayList<>();
				} finally {
					IOUtils.closeStream(jarFile);
				}
			}
		}
		return returnList;
	}

	/**
	 * List child files
	 *
	 * @param filePath parent file path
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath));
	}

	/**
	 * List child files
	 *
	 * @param filePath        parent file path
	 * @param readHiddenFiles List include hidden files
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath, boolean readHiddenFiles) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), readHiddenFiles);
	}

	/**
	 * List child files
	 *
	 * @param filePath           parent file path
	 * @param readHiddenFiles    List include hidden files
	 * @param iterateChildFolder to iterate child folder
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath, boolean readHiddenFiles,
	                                     boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), readHiddenFiles, iterateChildFolder);
	}

	/**
	 * List child files
	 *
	 * @param filePath           parent file path
	 * @param readHiddenFiles    List include hidden files
	 * @param includeRootFolder  List include directories
	 * @param iterateChildFolder to iterate child folder
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath, boolean readHiddenFiles, boolean includeRootFolder,
	                                     boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), readHiddenFiles, includeRootFolder, iterateChildFolder);
	}

	/**
	 * List child files
	 *
	 * @param file parent file object
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file) {
		return FileUtils.listFiles(file, null);
	}

	/**
	 * List child files
	 *
	 * @param file            parent file object
	 * @param readHiddenFiles List include hidden files
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, boolean readHiddenFiles) {
		return FileUtils.listFiles(file, null, readHiddenFiles);
	}

	/**
	 * List child files
	 *
	 * @param file               parent file object
	 * @param readHiddenFiles    List include hidden files
	 * @param iterateChildFolder to iterate child folder
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, boolean readHiddenFiles, boolean iterateChildFolder) {
		return FileUtils.listFiles(file, null, readHiddenFiles, iterateChildFolder);
	}

	/**
	 * List child files
	 *
	 * @param file               parent file object
	 * @param readHiddenFiles    List include hidden files
	 * @param includeRootFolder  List include directories
	 * @param iterateChildFolder to iterate child folder
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, boolean readHiddenFiles,
	                                     boolean includeRootFolder, boolean iterateChildFolder) {
		return FileUtils.listFiles(file, null, readHiddenFiles, includeRootFolder, iterateChildFolder);
	}

	/**
	 * List child files by file name filter
	 *
	 * @param filePath parent file path
	 * @param filter   file name filter
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath, FilenameFilter filter)
			throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), filter);
	}

	/**
	 * List child files by file name filter
	 *
	 * @param filePath        parent file path
	 * @param filter          file name filter
	 * @param readHiddenFiles List include hidden files
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath, FilenameFilter filter,
	                                     boolean readHiddenFiles) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), filter, readHiddenFiles);
	}

	/**
	 * List child files by file name filter
	 *
	 * @param filePath           parent file path
	 * @param filter             file name filter
	 * @param readHiddenFiles    List include hidden files
	 * @param iterateChildFolder to iterate child folder
	 * @return list of child file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFiles(String filePath, FilenameFilter filter, boolean readHiddenFiles,
	                                     boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), filter, readHiddenFiles, iterateChildFolder);
	}

	/**
	 * List child files by file name filter
	 *
	 * @param file   parent file object
	 * @param filter file name filter
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, FilenameFilter filter) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, true,
				Boolean.FALSE, true);
		return returnList;
	}

	/**
	 * List child files by file name filter
	 *
	 * @param file            parent file object
	 * @param filter          file name filter
	 * @param readHiddenFiles List include hidden files
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, FilenameFilter filter, boolean readHiddenFiles) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, readHiddenFiles,
				Boolean.FALSE, true);
		return returnList;
	}

	/**
	 * List child files by file name filter
	 *
	 * @param file              parent file object
	 * @param filter            file name filter
	 * @param readHiddenFiles   List include hidden files
	 * @param includeRootFolder List include directories
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, FilenameFilter filter,
	                                     boolean readHiddenFiles, boolean includeRootFolder) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, readHiddenFiles, includeRootFolder, true);
		return returnList;
	}

	/**
	 * List child files by file name filter
	 *
	 * @param file               parent file object
	 * @param filter             file name filter
	 * @param readHiddenFiles    List include hidden files
	 * @param includeRootFolder  List include directories
	 * @param iterateChildFolder to iterate child folder
	 * @return list of child file path
	 */
	public static List<String> listFiles(File file, FilenameFilter filter, boolean readHiddenFiles,
	                                     boolean includeRootFolder, boolean iterateChildFolder) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, readHiddenFiles, includeRootFolder, iterateChildFolder);
		return returnList;
	}

	/**
	 * List child files and append file path to current list
	 *
	 * @param filePath parent file path
	 * @param fileList current child file list
	 * @throws IOException the io exception
	 */
	public static void listFiles(String filePath, List<String> fileList) throws IOException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, true,
				Boolean.FALSE, true);
	}

	/**
	 * List child files and append file path to current list
	 *
	 * @param filePath        parent file path
	 * @param fileList        current child file list
	 * @param readHiddenFiles List include hidden files
	 * @throws IOException the io exception
	 */
	public static void listFiles(String filePath, List<String> fileList, boolean readHiddenFiles) throws IOException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, readHiddenFiles,
				Boolean.FALSE, true);
	}

	/**
	 * List child files and append file path to current list
	 *
	 * @param filePath           parent file path
	 * @param fileList           current child file list
	 * @param readHiddenFiles    List include hidden files
	 * @param iterateChildFolder to iterate child folder
	 * @throws IOException the io exception
	 */
	public static void listFiles(String filePath, List<String> fileList, boolean readHiddenFiles,
	                             boolean iterateChildFolder) throws IOException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, readHiddenFiles,
				Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * List child files and append file path to current list
	 *
	 * @param filePath           parent file path
	 * @param fileList           current child file list
	 * @param readHiddenFiles    List include hidden files
	 * @param includeRootFolder  List include directories
	 * @param iterateChildFolder to iterate child folder
	 * @throws IOException the io exception
	 */
	public static void listFiles(String filePath, List<String> fileList, boolean readHiddenFiles,
	                             boolean includeRootFolder, boolean iterateChildFolder) throws IOException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, readHiddenFiles,
				includeRootFolder, iterateChildFolder);
	}

	/**
	 * List child files by file name filter and append file path to current list
	 *
	 * @param filePath parent file path
	 * @param filter   file name filter
	 * @param fileList current child file list
	 * @throws IOException the io exception
	 */
	public static void listFiles(String filePath, FilenameFilter filter, List<String> fileList) throws IOException {
		FileUtils.listFiles(FileUtils.getFile(filePath), filter, fileList, true,
				Boolean.FALSE, true);
	}

	/**
	 * List child files by file name filter and append file path to current list
	 *
	 * @param filePath          parent file path
	 * @param filter            file name filter
	 * @param fileList          current child file list
	 * @param includeRootFolder include root folder
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static void listFiles(String filePath, FilenameFilter filter,
	                             List<String> fileList, boolean includeRootFolder) throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), filter, fileList, true,
				includeRootFolder, true);
	}

	/**
	 * List child files by file name filter and append file path to current list
	 *
	 * @param filePath           parent file path
	 * @param filter             file name filter
	 * @param fileList           current child file list
	 * @param includeRootFolder  include root folder
	 * @param iterateChildFolder to iterate child folder
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static void listFiles(String filePath, FilenameFilter filter, List<String> fileList,
	                             boolean includeRootFolder, boolean iterateChildFolder) throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), filter, fileList, true,
				includeRootFolder, iterateChildFolder);
	}

	/**
	 * List child files by file name filter and append file path to current list
	 *
	 * @param file               parent file object
	 * @param filter             file name filter
	 * @param fileList           current child file list
	 * @param readHiddenFiles    include hidden file
	 * @param includeRootFolder  include root folder
	 * @param iterateChildFolder to iterate child folder
	 */
	public static void listFiles(File file, FilenameFilter filter, List<String> fileList,
	                             boolean readHiddenFiles, boolean includeRootFolder, boolean iterateChildFolder) {
		if (fileList == null) {
			fileList = new ArrayList<>();
		}

		if (file.isDirectory()) {
			if (includeRootFolder) {
				fileList.add(file.getAbsolutePath());
			}
			File[] childFiles = file.listFiles();
			if (childFiles != null) {
				for (File childFile : childFiles) {
					if (childFile.isDirectory()) {
						if (iterateChildFolder) {
							FileUtils.listFiles(childFile, filter, fileList, readHiddenFiles,
									includeRootFolder, Boolean.TRUE);
						}
					} else {
						if (!readHiddenFiles && file.isHidden()) {
							continue;
						}

						boolean match = Boolean.FALSE;
						if (filter == null) {
							match = true;
						} else if (filter.accept(childFile.getParentFile(), childFile.getName())) {
							match = true;
						}

						if (match) {
							String filePath = childFile.getAbsolutePath();
							if (!fileList.contains(filePath)) {
								fileList.add(filePath);
							}
						}
					}
				}
			}
		}
	}

	/**
	 * List child directory
	 *
	 * @param filePath parent path
	 * @return list of child directory path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listDirectory(String filePath) throws FileNotFoundException {
		List<String> directoryList = new ArrayList<>();
		FileUtils.listDirectory(FileUtils.getFile(filePath), directoryList);
		return directoryList;
	}

	/**
	 * List child directory
	 *
	 * @param directory parent directory object
	 * @return list of child directory path
	 */
	public static List<String> listDirectory(File directory) {
		List<String> directoryList = new ArrayList<>();
		FileUtils.listDirectory(directory, directoryList);
		return directoryList;
	}

	/**
	 * List child directory and append to current directory list
	 *
	 * @param file          parent directory object
	 * @param directoryList current directory list
	 */
	public static void listDirectory(File file, List<String> directoryList) {
		if (file == null || !file.isDirectory() || directoryList == null) {
			return;
		}

		FileFilter fileFilter = new DirectoryFileFilter();

		File[] directories = file.listFiles(fileFilter);

		if (directories != null) {
			for (File directory : directories) {
				directoryList.add(directory.getAbsolutePath());
				FileUtils.listDirectory(directory, directoryList);
			}
		}
	}

	/**
	 * List child files and filter by extension name
	 *
	 * @param filePath    parent file path
	 * @param fileExtName extension name
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listExtNameFiles(String filePath, String fileExtName) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(fileExtName));
	}

	/**
	 * List child files and filter by extension name
	 *
	 * @param filePath           parent file path
	 * @param fileExtName        extension name
	 * @param iterateChildFolder to iterate child folder
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listExtNameFiles(String filePath, String fileExtName,
	                                            boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(fileExtName),
				Boolean.FALSE, Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * List child files and filter by extension name
	 *
	 * @param filePath           parent file path
	 * @param fileExtName        extension name
	 * @param readHiddenFile     the read hidden file
	 * @param iterateChildFolder to iterate child folder
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listExtNameFiles(String filePath, String fileExtName, boolean readHiddenFile,
	                                            boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(fileExtName),
				readHiddenFile, Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * List child files by filter extension name is .class
	 *
	 * @param filePath parent file path
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listClassesFiles(String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter("class"));
	}

	/**
	 * List child files by filter extension name is .class
	 *
	 * @param file parent file object
	 * @return list of file path
	 */
	public static List<String> listClassesFiles(File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter("class"));
	}

	/**
	 * List child files by filter extension name is .jar
	 *
	 * @param filePath parent file path
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listJarFiles(String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(URL_PROTOCOL_JAR));
	}

	/**
	 * List child files by filter extension name is .jar
	 *
	 * @param file parent file object
	 * @return list of file path
	 */
	public static List<String> listJarFiles(File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter(URL_PROTOCOL_JAR));
	}

	/**
	 * List child files by filter extension name is .zip
	 *
	 * @param filePath parent file path
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listZipFiles(String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(URL_PROTOCOL_ZIP));
	}

	/**
	 * List child files by filter extension name is .zip
	 *
	 * @param file parent file object
	 * @return list of file path
	 */
	public static List<String> listZipFiles(File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter(URL_PROTOCOL_ZIP));
	}

	/**
	 * List child files by filter extension name is .wsjar
	 *
	 * @param filePath parent file path
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listWebSphereJarFiles(String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(URL_PROTOCOL_WSJAR));
	}

	/**
	 * List child files by filter extension name is .wsjar
	 *
	 * @param file parent file object
	 * @return list of file path
	 */
	public static List<String> listWebSphereJarFiles(File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter(URL_PROTOCOL_WSJAR));
	}

	/**
	 * List files, filter by file name regex string
	 *
	 * @param filePath      folder path
	 * @param fileNameRegex file name regex
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFilesByRegex(String filePath, String fileNameRegex)
			throws FileNotFoundException {
		return FileUtils.listFilesByRegex(filePath, fileNameRegex, true,
				Boolean.FALSE, true);
	}

	/**
	 * List files, filter by file name regex string
	 *
	 * @param filePath           folder path
	 * @param fileNameRegex      file name regex
	 * @param iterateChildFolder to iterate child folder
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFilesByRegex(String filePath, String fileNameRegex,
	                                            boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFilesByRegex(filePath, fileNameRegex, true,
				Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * List files, filter by file name regex string
	 *
	 * @param filePath           folder path
	 * @param fileNameRegex      file name regex
	 * @param readHiddenFiles    include hidden file
	 * @param includeRootFolder  include root folder
	 * @param iterateChildFolder to iterate child folder
	 * @return list of file path
	 * @throws FileNotFoundException if the resource cannot be resolved to a file in the file system
	 */
	public static List<String> listFilesByRegex(String filePath, String fileNameRegex,
	                                            boolean readHiddenFiles, boolean includeRootFolder,
	                                            boolean iterateChildFolder) throws FileNotFoundException {
		List<String> fileList = new ArrayList<>();
		FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameRegexFilter(fileNameRegex),
				fileList, readHiddenFiles, includeRootFolder, iterateChildFolder);
		return fileList;
	}

	/**
	 * Write file content to local file path
	 *
	 * @param fileData file content
	 * @param filePath write path
	 * @return true for success and Boolean.FALSE for error
	 */
	public static boolean saveFile(byte[] fileData, String filePath) {
		FileOutputStream fileOutputStream = null;

		try {
			File destFile = FileUtils.getFile(filePath);
			FileUtils.makeHome(destFile.getParent());

			fileOutputStream = new FileOutputStream(destFile);
			fileOutputStream.write(fileData);
			fileOutputStream.flush();
			return true;
		} catch (IOException e) {
			LOGGER.error("Save file to storage error! ");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack trace message: ", e);
			}
			return Boolean.FALSE;
		} finally {
			IOUtils.closeStream(fileOutputStream);
		}
	}

	/**
	 * Write input stream content to file path
	 *
	 * @param inputStream file content by input stream
	 * @param filePath    write to file path
	 * @return true for success and Boolean.FALSE for error
	 * @throws IOException close stream error
	 */
	public static boolean saveFile(InputStream inputStream, String filePath) throws IOException {
		OutputStream outputStream = null;
		try {
			File file = FileUtils.getFile(filePath);
			FileUtils.makeHome(file.getParent());

			outputStream = new FileOutputStream(file);
			int bytesRead;
			byte[] buffer = new byte[8192];
			while ((bytesRead = inputStream.read(buffer, 0, 8192)) != -1) {
				outputStream.write(buffer, 0, bytesRead);
			}
			return true;
		} catch(Exception e) {
			return Boolean.FALSE;
		} finally {
			if (outputStream != null) {
				outputStream.flush();
				outputStream.close();
			}

			if (inputStream != null) {
				inputStream.close();
			}
		}
	}

	/**
	 * Save String to File use default charset: UTF-8
	 *
	 * @param filePath    write to file path
	 * @param content    File content
	 * @return Save result
	 */
	public static boolean saveFile(String filePath, String content) {
		return FileUtils.saveFile(filePath, content, Globals.DEFAULT_ENCODING);
	}

	/**
	 * Save String to File
	 *
	 * @param filePath    write to file path
	 * @param content    File content
	 * @param encoding   Charset encoding
	 * @return Save result
	 */
	public static boolean saveFile(String filePath, String content, String encoding) {
		PrintWriter printWriter = null;
		OutputStreamWriter outputStreamWriter = null;
		try {
			int index = filePath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR);
			String homePath = filePath.substring(0, index);
			FileUtils.makeHome(homePath);
			outputStreamWriter = new OutputStreamWriter(new FileOutputStream(filePath), encoding);
			printWriter = new PrintWriter(outputStreamWriter);

			printWriter.print(content);
			outputStreamWriter.flush();
			return true;
		} catch (Exception e) {
			return Boolean.FALSE;
		} finally {
			IOUtils.closeStream(printWriter);
			IOUtils.closeStream(outputStreamWriter);
		}
	}

	/**
	 * Read File to String use default charset: UTF-8
	 *
	 * @param filePath File path
	 * @return File content as string
	 */
	public static String readFile(String filePath) {
		return FileUtils.readFile(filePath, Globals.DEFAULT_ENCODING);
	}

	/**
	 * Read File to String
	 *
	 * @param filePath File path
	 * @param encoding Charset encoding
	 * @return File content as string
	 */
	public static String readFile(String filePath, String encoding) {
		try {
			return IOUtils.readContent(getURL(filePath).openStream(), encoding);
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * Remove File by current file path
	 *
	 * @param filePath File path
	 * @return Remove result
	 */
	public static boolean removeFile(String filePath) {
		try {
			if (filePath.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
				try {
					return FileUtils.removeSmbFile(openSMBFile(filePath));
				} catch (Exception e) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Remove samba file error");
					}
					return Boolean.FALSE;
				}
			} else {
				return FileUtils.removeFile(FileUtils.getFile(filePath));
			}
		} catch (FileNotFoundException e) {
			return true;
		}
	}

	/**
	 * Remove File by current file object
	 *
	 * @param file File instance
	 * @return Remove result
	 */
	public static boolean removeFile(File file) {
		if (file == null) {
			return true;
		}

		if (file.exists()) {
			if (file.isDirectory()) {
				return FileUtils.removeDir(file);
			} else {
				return file.delete();
			}
		}
		return true;
	}

	/**
	 * Remove File by current file object
	 *
	 * @param smbFile SMB file instance
	 * @return Remove result
	 */
	public static boolean removeSmbFile(SmbFile smbFile) {
		if (smbFile == null) {
			return true;
		}

		try {
			if (smbFile.exists()) {
				if (smbFile.isDirectory()) {
					FileUtils.removeSmbDir(smbFile);
				} else {
					smbFile.delete();
				}
			}
			return true;
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Remove smb file error! ", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * Rename smb file
	 *
	 * @param origFile Original file
	 * @param destFile Rename file
	 * @return Rename result
	 */
	public static boolean renameSmbFile(String origFile, String destFile) {
		if (origFile.startsWith(FileUtils.SAMBA_URL_PREFIX)
				&& destFile.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
			try {
				SmbFile origSmbFile = openSMBFile(origFile);
				SmbFile destSmbFile = openSMBFile(destFile);

				origSmbFile.renameTo(destSmbFile);
				return true;
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Rename smb file error! ", e);
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Move file from basePath to moveToPath
	 *
	 * @param basePath   Original path
	 * @param moveToPath Target path
	 * @return Move result
	 */
	public static boolean moveFile(String basePath, String moveToPath) {
		return FileUtils.moveFile(basePath, moveToPath, Boolean.FALSE);
	}

	/**
	 * Move file from basePath to moveToPath
	 *
	 * @param basePath   Original path
	 * @param moveToPath Target path
	 * @param override   Override target file if exists
	 * @return Operate result
	 */
	public static boolean moveFile(String basePath, String moveToPath, boolean override) {
		if (FileUtils.isExists(basePath) && FileUtils.canRead(basePath)) {
			if (override || !FileUtils.isExists(moveToPath)) {
				try {
					File destFile = FileUtils.getFile(moveToPath);
					if (destFile.exists()) {
						if (override && !FileUtils.removeFile(destFile)) {
							return Boolean.FALSE;
						}
					}

					if (FileUtils.copyFile(basePath, moveToPath) && FileUtils.removeFile(basePath)) {
						return true;
					}

					return Boolean.FALSE;
				} catch (Exception e) {
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Move file error! ", e);
					}
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Move directory from basePath to moveToPath and ignore exists file
	 *
	 * @param basePath   Original directory
	 * @param moveToPath Target directory
	 * @return Move result
	 */
	public static boolean moveDir(String basePath, String moveToPath) {
		return FileUtils.moveDir(basePath, moveToPath, Boolean.FALSE);
	}

	/**
	 * Move directory from basePath to moveToPath and override by user defined
	 *
	 * @param basePath   Original directory
	 * @param moveToPath Target directory
	 * @param override   Override target file if it's exists
	 * @return Move result
	 */
	public static boolean moveDir(String basePath, String moveToPath, boolean override) {
		try {
			return FileUtils.moveDir(FileUtils.getFile(basePath), moveToPath, override);
		} catch (FileNotFoundException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Move directory from baseFile object to moveToPath and ignore exists file
	 *
	 * @param baseFile   Original file instance
	 * @param moveToPath Target directory
	 * @return Move result
	 */
	public static boolean moveDir(File baseFile, String moveToPath) {
		return FileUtils.moveDir(baseFile, moveToPath, Boolean.FALSE);
	}

	/**
	 * Move dir from baseFile object to moveToPath and override by user defined
	 *
	 * @param baseFile   Original file path
	 * @param moveToPath Target path
	 * @param override   Override target file
	 * @return Move result
	 */
	public static boolean moveDir(File baseFile, String moveToPath, boolean override) {
		if (baseFile == null || !baseFile.exists()) {
			return Boolean.FALSE;
		}
		try {
			FileUtils.makeHome(moveToPath);

			boolean error = Boolean.FALSE;
			if (baseFile.isDirectory()) {
				File[] childFiles = baseFile.listFiles();
				if (childFiles != null) {
					for (File tempFile : childFiles) {
						String childPath = moveToPath + Globals.DEFAULT_PAGE_SEPARATOR + tempFile.getName();
						if (tempFile.isDirectory()) {
							error = FileUtils.moveDir(tempFile, childPath, override);
							removeFile(tempFile);
						} else if (tempFile.isFile()) {
							error = FileUtils.moveFile(tempFile.getAbsolutePath(), childPath, override);
						}

						if (!error) {
							return Boolean.FALSE;
						}
					}
				}
				return true;
			} else if (baseFile.isFile()) {
				return FileUtils.moveFile(baseFile.getAbsolutePath(),
						moveToPath + Globals.DEFAULT_PAGE_SEPARATOR + baseFile.getName(), override);
			} else {
				return Boolean.FALSE;
			}
		} catch (Exception e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Copy file from basePath to copyToPath
	 *
	 * @param basePath   Original path
	 * @param copyToPath Target path
	 * @return Copy result
	 */
	public static boolean copyFile(String basePath, String copyToPath) {
		InputStream inputStream = null;
		OutputStream outputStream = null;
		try {
			String folderPath;
			if (copyToPath.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
				folderPath = copyToPath.substring(0, copyToPath.lastIndexOf("/"));
			} else {
				folderPath = copyToPath.substring(0, copyToPath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR));
			}
			if (FileUtils.makeHome(folderPath)) {
				if (basePath.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
					inputStream = new SmbFileInputStream(basePath, new BaseContext(new PropertyConfiguration(new Properties())));
				} else {
					inputStream = new FileInputStream(basePath);
				}

				if (copyToPath.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
					outputStream = new SmbFileOutputStream(openSMBFile(copyToPath));
				} else {
					outputStream = new FileOutputStream(copyToPath);
				}

				int len;
				byte [] buffer = new byte[Globals.DEFAULT_BUFFER_SIZE];

				while ((len = inputStream.read(buffer)) > -1) {
					outputStream.write(buffer, 0, len);
				}
				return true;
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Copy file error! ", e);
			}
		} finally {
			try {
				if (inputStream != null) {
					inputStream.close();
				}

				if (outputStream != null) {
					outputStream.flush();
					outputStream.close();
				}
			} catch (IOException e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Close stream error! ", e);
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Make directory
	 *
	 * @param destPath Target directory path
	 * @return Operate result
	 */
	public static boolean makeDir(String destPath) {
		if (FileUtils.isExists(destPath)) {
			return true;
		}

		if (FileUtils.makeHome(destPath)) {
			try {
				File destFile = FileUtils.getFile(destPath);
				return destFile.exists() || destFile.mkdirs();
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Make directory error! ", e);
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Create file directory
	 *
	 * @param homePath Check and create parent directory if it's not exists
	 * @return Operate result
	 */
	public static boolean makeHome(String homePath) {
		if (homePath.startsWith(FileUtils.SAMBA_URL_PREFIX)) {
			try {
				SmbFile smbFile = openSMBFile(homePath);
				smbFile.mkdirs();
				return true;
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Make smb file directories error! ", e);
				}
				return Boolean.FALSE;
			}
		} else {
			try {
				File homeDir = FileUtils.getFile(homePath);
				String parentPath = homeDir.getParent();
				if (parentPath != null && !FileUtils.isExists(parentPath)) {
					if (!FileUtils.makeHome(parentPath)) {
						return Boolean.FALSE;
					}
				}

				if (homeDir.exists()) {
					return true;
				} else {
					try {
						return homeDir.mkdirs();
					} catch (Exception e) {
						return Boolean.FALSE;
					}
				}
			} catch (FileNotFoundException e) {
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * Makes a directory, including any necessary but nonexistent parent
	 * directories. If a file already exists with specified name, but it is
	 * not a directory then an IOException is thrown.
	 * If the directory cannot be created (or the file already exists but is not a directory)
	 * then an IOException is thrown.
	 *
	 * @param directory directory to create, must not be {@code null}
	 * @throws IOException          if the directory cannot be created or the file already exists but is not a directory
	 */
	public static void forceMakeDir(final File directory) throws IOException {
		if (directory == null) {
			return;
		}
		if (directory.exists()) {
			if (!directory.isDirectory()) {
				throw new IOException("File " + directory + " was exists and not a directory.");
			}
		} else {
			if (!directory.mkdirs() && !directory.isDirectory()) {
				throw new IOException("Unable to create directory" + directory);
			}
		}
	}

	/**
	 * Makes any necessary but nonexistent parent directories for a given File. If the parent directory cannot be
	 * created then an IOException is thrown.
	 *
	 * @param file              file with parent to create
	 * @throws IOException      if the parent directory cannot be created
	 */
	public static void forceMakeParent(final File file) throws IOException {
		if (file == null) {
			return;
		}
		FileUtils.forceMakeDir(file.getParentFile());
	}

	/**
	 * Check filePath is exists
	 *
	 * @param resourceLocation Resource location
	 * @return Check result
	 */
	public static boolean isDirectory(String resourceLocation) {
		if (resourceLocation == null) {
			return Boolean.FALSE;
		}

		try {
			File directory = FileUtils.getFile(resourceLocation);
			return (directory.exists() && directory.isDirectory());
		} catch (FileNotFoundException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Copy directory from baseDir to destDir
	 *
	 * @param baseDir Original directory
	 * @param destDir Target directory
	 * @return Operate result
	 */
	public static boolean copyDir(String baseDir, String destDir) {
		if (!FileUtils.isDirectory(baseDir)) {
			return Boolean.FALSE;
		}

		File baseFiles = new File(baseDir);
		File destFiles = new File(destDir);

		String [] fileList = baseFiles.list();

		if (fileList == null || !FileUtils.makeHome(destDir)) {
			return Boolean.FALSE;
		}

		boolean copyStatus = true;

		for (String aFileList : fileList) {
			String baseFile = baseFiles + Globals.DEFAULT_PAGE_SEPARATOR + aFileList;
			String destFile = destFiles + Globals.DEFAULT_PAGE_SEPARATOR + aFileList;

			File tempFile = new File(baseFile);
			if (tempFile.isFile()) {
				copyStatus = FileUtils.copyFile(baseDir + Globals.DEFAULT_PAGE_SEPARATOR + tempFile.getName(),
						destDir + Globals.DEFAULT_PAGE_SEPARATOR + tempFile.getName());
			} else if (tempFile.isDirectory()) {
				copyStatus = FileUtils.copyDir(baseFile, destFile);
			}
			if (!copyStatus) {
				break;
			}
		}
		return copyStatus;
	}

	/**
	 * Delete directory
	 *
	 * @param directory directory will be removed
	 * @return Operate result
	 */
	public static boolean removeDir(File directory) {
		if (!directory.exists()) {
			return true;
		}
		String [] fileList = directory.list();

		if (fileList != null) {
			boolean operateStatus;
			for (String fileName : fileList) {
				File tempFile = new File(directory.getAbsolutePath(), fileName);
				if (tempFile.isDirectory()) {
					operateStatus = FileUtils.removeDir(tempFile);
				} else {
					operateStatus = tempFile.delete();
				}

				if (!operateStatus) {
					return Boolean.FALSE;
				}
			}
		}

		return directory.delete();
	}

	/**
	 * Delete directory
	 *
	 * @param directory Which directory will be removed
	 * @return Operate result
	 */
	public static boolean removeSmbDir(SmbFile directory) {
		try {
			if (!directory.exists()) {
				return true;
			}
			String [] fileList = directory.list();

			if (fileList != null) {
				for (String filePath : fileList) {
					SmbFile childFile = openSMBFile(filePath);
					if (childFile.isDirectory()) {
						if (!FileUtils.removeSmbDir(childFile)) {
							return Boolean.FALSE;
						}
					} else {
						childFile.delete();
					}
				}
			}

			directory.delete();
			return true;
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Remove smb folder error! ", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * Calculate file CRC value
	 *
	 * @param filePath file path
	 * @return CRC value
	 */
	public static long calcFileCRC(String filePath) {
		InputStream inputStream = null;
		try {
			inputStream = FileUtils.loadFile(filePath);
			if (inputStream != null) {
				byte[] readBuffer = new byte[Globals.DEFAULT_BUFFER_SIZE];
				int readLength;
				CRC32 crc = new CRC32();

				while ((readLength = inputStream.read(readBuffer)) != Globals.DEFAULT_VALUE_INT) {
					crc.update(readBuffer, 0, readLength);
				}

				return crc.getValue();
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Calculate file crc error! ", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
		}

		return Globals.DEFAULT_VALUE_LONG;
	}

	/**
	 * Check current file type is compress file
	 *
	 * @param resourceLocation Resource location
	 * @return Check result
	 */
	public static boolean isCompressFile(String resourceLocation) {
		if (!FileUtils.validateFileType(resourceLocation)) {
			return Boolean.FALSE;
		}
		String extensionName = StringUtils.getFilenameExtension(resourceLocation).toLowerCase();

		FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName);
		if (fileExtensionInfo != null) {
			return fileExtensionInfo.isCompressFile();
		}

		return Boolean.FALSE;
	}

	/**
	 * Check current file type is ready for printing
	 *
	 * @param resourceLocation Resource location
	 * @return Check result
	 */
	public static boolean isPrintable(String resourceLocation) {
		if (!FileUtils.validateFileType(resourceLocation)) {
			return Boolean.FALSE;
		}
		String extensionName = StringUtils.getFilenameExtension(resourceLocation).toLowerCase();

		FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName);
		if (fileExtensionInfo != null) {
			return fileExtensionInfo.isPrintable();
		}

		return Boolean.FALSE;
	}

	/**
	 * Check current file type is a picture file
	 *
	 * @param resourceLocation Resource location
	 * @return Check result
	 */
	public static boolean isPicture(String resourceLocation) {
		if (!FileUtils.validateFileType(resourceLocation)) {
			return Boolean.FALSE;
		}
		String extensionName = StringUtils.getFilenameExtension(resourceLocation).toLowerCase();

		FileExtensionInfo fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName);
		if (fileExtensionInfo != null) {
			return fileExtensionInfo.isPicture();
		}

		return Boolean.FALSE;
	}

	public static Optional<FileExtensionInfo> retrieveExtensionInfo(String resourceLocation) {
		FileExtensionInfo fileExtensionInfo = null;
		if (FileUtils.validateFileType(resourceLocation)) {
			String extensionName = StringUtils.getFilenameExtension(resourceLocation).toLowerCase();
			fileExtensionInfo = FileUtils.REGISTER_IDENTIFIED_MAP.get(extensionName);
		}
		return Optional.ofNullable(fileExtensionInfo);
	}

	/**
	 * Check current file is exists
	 *
	 * @param filePath File path
	 * @return Check result
	 */
	public static boolean isExists(String filePath) {
		return isExists(filePath, null, null, null);
	}

	/**
	 * Check current file is exists
	 *
	 * @param filePath File path
	 * @param domain    SMB domain
	 * @param userName  SMB user name
	 * @param passWord  SMB password
	 * @return Check result
	 */
	public static boolean isExists(String filePath, String domain, String userName, String passWord) {
		if (filePath == null) {
			return Boolean.FALSE;
		}

		if (filePath.startsWith(SAMBA_URL_PREFIX)) {
			return FileUtils.isSMBFileExists(filePath, domain, userName, passWord);
		}

		try {
			File file = FileUtils.getFile(filePath);
			return file.exists();
		} catch (FileNotFoundException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Read entry length
	 *
	 * @param filePath  Zip/jar file path
	 * @param entryPath Check entry path
	 * @return Entry length
	 */
	public static int readEntryLength(String filePath, String entryPath) {
		InputStream inputStream = null;
		JarFile jarFile = null;
		try {
			if (filePath.endsWith(URL_PROTOCOL_JAR)) {
				jarFile = new JarFile(getFile(filePath));
				JarEntry packageEntry = jarFile.getJarEntry(entryPath);

				if(packageEntry != null){
					inputStream = jarFile.getInputStream(jarFile.getJarEntry(entryPath));
					return inputStream.available();
				}
			} else if (filePath.endsWith(URL_PROTOCOL_ZIP)) {
				ZipFile zipFile = ZipFile.openZipFile(filePath);
				return zipFile.readEntryLength(entryPath);
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Read entry length error! ", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
			IOUtils.closeStream(jarFile);
		}
		return Globals.DEFAULT_VALUE_INT;
	}

	/**
	 * Check given entry path is exists in zip/jar file
	 *
	 * @param filePath  Zip/jar file path
	 * @param entryPath Check entry path
	 * @return Check result
	 */
	public static boolean isEntryExists(String filePath, String entryPath) {
		if (StringUtils.isEmpty(filePath) || StringUtils.isEmpty(entryPath)) {
			return Boolean.FALSE;
		}

		if (filePath.toLowerCase().endsWith(URL_PROTOCOL_JAR)) {
			JarFile jarFile = null;
			try {
				jarFile = new JarFile(getFile(filePath));
				return jarFile.getJarEntry(entryPath) != null;
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Load jar entry content error! ", e);
				}
			} finally {
				if (jarFile != null) {
					try {
						jarFile.close();
					} catch (Exception e) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Close jar file error! ", e);
						}
					}
				}
			}
		} else if (filePath.toLowerCase().endsWith(URL_PROTOCOL_ZIP)) {
			ZipFile zipFile = ZipFile.openZipFile(filePath);
			return zipFile.isEntryExists(entryPath);
		}
		return Boolean.FALSE;
	}

	/**
	 * Entry input stream.
	 *
	 * @param fileObject the file object
	 * @param entryPath  the entry path
	 * @return input stream
	 * @throws IOException the io exception
	 */
	public static InputStream openInputStream(Object fileObject, String entryPath) throws IOException {
		if (fileObject == null || StringUtils.isEmpty(entryPath)) {
			return null;
		}

		if (fileObject instanceof JarFile) {
			JarEntry jarEntry = ((JarFile) fileObject).getJarEntry(entryPath);
			if(jarEntry != null){
				return ((JarFile) fileObject).getInputStream(jarEntry);
			}
			return null;
		}

		if (fileObject instanceof ZipFile) {
			return ((ZipFile) fileObject).entryInputStream(entryPath);
		}

		return null;
	}

	/**
	 * Check current file can read
	 *
	 * @param filePath File path
	 * @return Check result
	 */
	public static boolean canRead(String filePath) {
		return canRead(filePath, null, null, null);
	}

	/**
	 * Check current file can read
	 *
	 * @param filePath File path
	 * @param domain    SMB domain
	 * @param userName  SMB user name
	 * @param passWord  SMB password
	 * @return Check result
	 */
	public static boolean canRead(String filePath, String domain, String userName, String passWord) {
		if (filePath == null) {
			return Boolean.FALSE;
		}

		if (filePath.startsWith(SAMBA_URL_PREFIX)) {
			return FileUtils.isSMBFileCanRead(filePath, domain, userName, passWord);
		}

		try {
			File file = FileUtils.getFile(filePath);
			return file.canRead();
		} catch (FileNotFoundException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Check current file can write
	 *
	 * @param path File path
	 * @return Check result
	 */
	public static boolean canWrite(String path) {
		return canWrite(path, null, null, null);
	}

	/**
	 * Check current file can write
	 *
	 * @param path     File path
	 * @param domain   SMB domain
	 * @param userName SMB user name
	 * @param passWord SMB password
	 * @return Check result
	 */
	public static boolean canWrite(String path, String domain, String userName, String passWord) {
		if (path == null) {
			return Boolean.FALSE;
		}

		if (path.startsWith(SAMBA_URL_PREFIX)) {
			return FileUtils.isSMBFileCanWrite(path, domain, userName, passWord);
		}

		try {
			File file = FileUtils.getFile(path);
			return file.canWrite();
		} catch (FileNotFoundException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Check current file can execute
	 *
	 * @param filePath File path
	 * @return Check result
	 */
	public static boolean canExecute(String filePath) {
		try {
			File file = FileUtils.getFile(filePath);
			return file.canExecute();
		} catch (FileNotFoundException e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Merge file to save path
	 *
	 * @param savePath         Target save path
	 * @param segmentationFile Segmentation file object
	 * @return Operate result
	 */
	public static boolean mergeFile(String savePath, SegmentationFile segmentationFile) {
		try (RandomAccessFile randomAccessFile = new RandomAccessFile(savePath, "rw")) {
			String extName = StringUtils.getFilenameExtension(savePath);
			if (extName.length() == 0) {
				extName = Globals.DEFAULT_VALUE_STRING;
			}
			if (!segmentationFile.getExtName().equalsIgnoreCase(extName)) {
				LOGGER.warn("File extension name not match");
			}

			long totalSize = 0;
			randomAccessFile.setLength(segmentationFile.getTotalSize());

			for (SegmentationItem segmentationItem : segmentationFile.getSegmentationItemList()) {
				if (segmentationItem == null) {
					return Boolean.FALSE;
				}

				if (FileUtils.mergeFile(randomAccessFile, segmentationItem)) {
					totalSize += segmentationItem.getBlockSize();
				}
			}

			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Write file size: " + totalSize);
			}

			if (totalSize != segmentationFile.getTotalSize()) {
				FileUtils.removeFile(savePath);
				return Boolean.FALSE;
			}
		} catch (Exception e) {
			return Boolean.FALSE;
		}

		return FileUtils.validateFileType(savePath);
	}

	/**
	 * Segment file by current block size
	 *
	 * @param filePath  Which file will be split
	 * @param blockSize Block size
	 * @return List of split file
	 */
	public static SegmentationFile segmentFile(String filePath, int blockSize) {
		return segmentFile(filePath, blockSize, null, null, null);
	}

	/**
	 * Segment file by current block size
	 *
	 * @param filePath  Which file will be split
	 * @param blockSize Block size
	 * @param domain    SMB domain
	 * @param userName  SMB user name
	 * @param passWord  SMB password
	 * @return List of split file
	 */
	public static SegmentationFile segmentFile(String filePath, int blockSize, 
											   String domain, String userName, String passWord) {
		if (!FileUtils.isExists(filePath, domain, userName, passWord)) {
			return null;
		}

		if (!FileUtils.validateFileType(filePath)) {
			LOGGER.warn("Validate file type error! Maybe invalid");
		}

		List<SegmentationItem> segmentationItemList = new ArrayList<>();
		InputStream fileInputStream = null;
		ByteArrayOutputStream byteArrayOutputStream;

		try {
			String extName = StringUtils.getFilenameExtension(filePath);
			if (extName.length() == 0) {
				extName = Globals.DEFAULT_VALUE_STRING;
			} else {
				extName = extName.toLowerCase();
			}
			File file = getFile(filePath);
			long fileSize = getFileSize(file);

			fileInputStream = new FileInputStream(file);

			byte[] readBuffer = new byte[blockSize];
			int index = 0;
			int readLength;
			while ((readLength = fileInputStream.read(readBuffer)) != -1) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Read index: " + index + ", read length: " + readLength);
				}
				byteArrayOutputStream = new ByteArrayOutputStream(blockSize);
				byteArrayOutputStream.write(readBuffer, 0, readLength);
				SegmentationItem segmentationItem =
						new SegmentationItem((long) index * blockSize, byteArrayOutputStream.toByteArray());
				segmentationItemList.add(segmentationItem);
				index++;
			}

			return new SegmentationFile(extName, fileSize, blockSize, ConvertUtils.byteToHex(SecurityUtils.MD5(file)),
					ConvertUtils.byteToHex(SecurityUtils.SHA256(file)), segmentationItemList);
		} catch (FileNotFoundException e) {
			LOGGER.error("Target file not exists! ");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack message: ", e);
			}
		} catch (IOException e) {
			LOGGER.error("Read file data error! ");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack message: ", e);
			}
		} finally {
			IOUtils.closeStream(fileInputStream);
		}

		return null;
	}

	/**
	 * Open SMB file
	 *
	 * @param smbPath SMB file path
	 * @return SmbFile object
	 * @throws FileNotFoundException if open file error
	 */
	public static SmbFile openSMBFile(String smbPath) throws FileNotFoundException {
		return openSMBFile(smbPath, null, null, null);
	}

	/**
	 * Open SMB file
	 *
	 * @param smbPath  SMB file path
	 * @param domain   SMB domain
	 * @param userName SMB user name
	 * @param passWord SMB password
	 * @return SmbFile object
	 * @throws FileNotFoundException if open file error
	 */
	public static SmbFile openSMBFile(String smbPath, String domain,
	                                  String userName, String passWord) throws FileNotFoundException {
		Properties properties = new Properties();
		if (domain != null) {
			properties.setProperty("jcifs.smb.client.domain", domain);
		}
		if (userName != null) {
			properties.setProperty("jcifs.smb.client.username", userName);
		}
		if (passWord != null) {
			properties.setProperty("jcifs.smb.client.password", passWord);
		}
		try {
			return new SmbFile(smbPath, new BaseContext(new PropertyConfiguration(properties)));
		} catch (Exception e) {
			throw new FileNotFoundException("Open file error! File location: " + smbPath);
		}
	}

	private static void checkRegisterFileType(String extensionName) {
		if (extensionName == null) {
			return;
		}
		extensionName = extensionName.toLowerCase();
		if (FileUtils.REGISTER_IDENTIFIED_MAP.containsKey(extensionName.toLowerCase())) {
			LOGGER.warn("Override file type define! Ext name: " + extensionName);
		}
	}

	/**
	 * Replace page separator to "|"
	 * @param path      file path
	 * @return          replaced file path
	 */
	private static String replacePageSeparator(String path) {
		String replacePath = StringUtils.replace(path, Globals.DEFAULT_PAGE_SEPARATOR, "|");
		replacePath = StringUtils.replace(replacePath, "/", "|");
		replacePath = StringUtils.replace(replacePath, "\\", "|");
		replacePath = StringUtils.replace(replacePath, "\\\\", "|");
		if (replacePath.endsWith("|")) {
			replacePath = replacePath.substring(0, replacePath.length() - 1);
		}
		return replacePath;
	}

	private static boolean mergeFile(RandomAccessFile randomAccessFile,
	                                 SegmentationItem segmentationItem) throws IOException {
		if (segmentationItem == null) {
			return Boolean.FALSE;
		}

		if (segmentationItem.securityCheck()) {
			randomAccessFile.seek(segmentationItem.getPosition());
			randomAccessFile.write(StringUtils.base64Decode(segmentationItem.getDataInfo()));
			return true;
		} else {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Segmentation file part is invalid");
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * Check SMB file exists
	 * @param filePath      file path
	 * @param domain        smb domain
	 * @param userName      smb user name
	 * @param passWord      smb password
	 * @return              check result
	 */
	private static boolean isSMBFileExists(String filePath, String domain, String userName, String passWord) {
		if (filePath == null) {
			return Boolean.FALSE;
		}

		if (!filePath.startsWith(SAMBA_URL_PREFIX)) {
			return FileUtils.isExists(filePath, domain, userName, passWord);
		}

		try {
			SmbFile smbFile = openSMBFile(filePath, domain, userName, passWord);
			return smbFile.exists();
		} catch (Exception e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Check SMB file read access
	 * @param filePath      file path
	 * @param domain        smb domain
	 * @param userName      smb user name
	 * @param passWord      smb password
	 * @return              check result
	 */
	private static boolean isSMBFileCanRead(String filePath, String domain, String userName, String passWord) {
		if (filePath == null) {
			return Boolean.FALSE;
		}

		if (!filePath.startsWith(SAMBA_URL_PREFIX)) {
			return FileUtils.canRead(filePath, domain, userName, passWord);
		}

		try {
			SmbFile smbFile = openSMBFile(filePath, domain, userName, passWord);
			return smbFile.canRead();
		} catch (Exception e) {
			return Boolean.FALSE;
		}
	}

	/**
	 * Check SMB file write access
	 * @param filePath      file path
	 * @param domain        smb domain
	 * @param userName      smb user name
	 * @param passWord      smb password
	 * @return              check result
	 */
	private static boolean isSMBFileCanWrite(String filePath, String domain, String userName, String passWord) {
		if (filePath == null) {
			return Boolean.FALSE;
		}

		if (!filePath.startsWith(SAMBA_URL_PREFIX)) {
			return FileUtils.canWrite(filePath, domain, userName, passWord);
		}

		try {
			SmbFile smbFile = openSMBFile(filePath, domain, userName, passWord);
			return !smbFile.exists() || smbFile.canWrite();
		} catch (Exception e) {
			return Boolean.FALSE;
		}
	}

	private static void generateFileData(String folderPath, String targetPath) throws IOException {
		List<String> fileList = FileUtils.listFiles(folderPath);
		byte[] intBuffer = new byte[4];
		RawUtils.writeInt(intBuffer, RawUtils.Endian.LITTLE, fileList.size());
		RandomAccessFile randomAccessFile = new RandomAccessFile(targetPath, Globals.WRITE_MODE);
		randomAccessFile.write(intBuffer);
		fileList.forEach(filePath -> {
			FileExtensionInfo fileExtensionInfo =
					BeanUtils.parseXml(FileUtils.readFile(filePath), FileExtensionInfo.class);
			if (fileExtensionInfo != null) {
				try {
					randomAccessFile.write(fileExtensionInfo.convertToByteArray());
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Register default file type value
	 */
	private static void registerFileType() {
		InputStream inputStream;

		inputStream = FileUtils.class.getClassLoader().getResourceAsStream("org/nervousync/datas/File.dat");
		byte[] bytes = IOUtils.readBytes(inputStream);
		IOUtils.closeStream(inputStream);

		if (bytes == null || bytes.length == 0) {
			return;
		}

		List<FileExtensionInfo> extensionInfoList = new ArrayList<>();
		byte[] readBuffer;
		byte[] intBuffer = new byte[4];
		System.arraycopy(bytes, 0, intBuffer, 0, 4);
		int dataCount = RawUtils.readInt(intBuffer, RawUtils.Endian.LITTLE);
		int srcPos = 4;
		LOGGER.info("File identified information count: {}", dataCount);
		for (int i = 0 ; i < dataCount ; i++) {
			byte[] indexData = new byte[6];
			System.arraycopy(bytes, srcPos, indexData, 0, indexData.length);
			srcPos += 6;

			int fileType = indexData[0];
			boolean printing = ((int)indexData[1]) == 1;
			int dataLength = RawUtils.readInt(indexData, 2, RawUtils.Endian.LITTLE);

			readBuffer = new byte[dataLength];
			System.arraycopy(bytes, srcPos, readBuffer, 0, dataLength);
			srcPos += dataLength;
			try {
				String contentInfo = new String(readBuffer, Globals.DEFAULT_ENCODING);
				extensionInfoList.add(new FileExtensionInfo(fileType, printing, contentInfo));
			} catch (UnsupportedEncodingException e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Charset does not supported! ", e);
				}
			}
		}

		for (FileExtensionInfo fileExtensionInfo : extensionInfoList) {
			if (REGISTER_IDENTIFIED_MAP.containsKey(fileExtensionInfo.getExtensionName())) {
				LOGGER.warn("Override file extension info, extension name: " + fileExtensionInfo.getExtensionName());
			}
			REGISTER_IDENTIFIED_MAP.put(fileExtensionInfo.getExtensionName(), fileExtensionInfo);
		}
	}

	/**
	 * File name filter by regex
	 */
	private static final class FilenameRegexFilter implements FilenameFilter {
		private final String fileNameRegex;

		/**
		 * Instantiates a new Filename regex filter.
		 *
		 * @param fileNameRegex the file name regex
		 */
		public FilenameRegexFilter(String fileNameRegex) {
			this.fileNameRegex = fileNameRegex;
		}

		public boolean accept(File dir, String name) {
			if (this.fileNameRegex != null && dir != null && dir.isDirectory()
					&& dir.exists() && name != null) {
				String fileName = StringUtils.getFilename(name);
				return StringUtils.matches(fileName, this.fileNameRegex);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * file extension name filter
	 */
	private static final class FilenameExtensionFilter implements FilenameFilter {
		private final String fileExtName;

		/**
		 * Instantiates a new Filename extension filter.
		 *
		 * @param fileExtName the file ext name
		 */
		public FilenameExtensionFilter(String fileExtName) {
			this.fileExtName = fileExtName;
		}

		public boolean accept(File dir, String name) {
			if (this.fileExtName != null && dir != null && dir.isDirectory()
					&& dir.exists() && name != null) {
				String fileExtName = StringUtils.getFilenameExtension(name);
				return fileExtName.equalsIgnoreCase(this.fileExtName);
			}
			return Boolean.FALSE;
		}
	}

	private static final class DirectoryFileFilter implements FileFilter {
		public boolean accept(File pathname) {
			return pathname.isDirectory();
		}
	}
}
