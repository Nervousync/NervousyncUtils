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
package org.nervousync.utils;

import jcifs.CIFSContext;
import jcifs.CIFSException;
import jcifs.Config;
import jcifs.config.PropertyConfiguration;
import jcifs.context.BaseContext;
import jcifs.smb.NtlmPasswordAuthenticator;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;
import jcifs.smb.SmbFileOutputStream;
import org.nervousync.beans.path.TargetPath;
import org.nervousync.beans.xml.files.SegmentationBlock;
import org.nervousync.beans.xml.files.SegmentationInfo;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.zip.ZipException;
import org.nervousync.zip.ZipFile;

import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.CRC32;

/**
 * <h2 class="en-US">File operate utilities</h2>
 * <h2 class="zh-CN">文件操作工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 13, 2010 11:08:14 $
 */
public final class FileUtils {
	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(FileUtils.class);

	/**
	 * <span class="en-US">URL prefixes for loading from the class path: "classpath:"</span>
	 * <span class="zh-CN">用于从类路径加载的 URL 前缀：“classpath:”</span>
	 */
	public static final String CLASSPATH_URL_PREFIX = "classpath:";

	/**
	 * <span class="en-US">URL prefixes for loading from the file system: "file:"</span>
	 * <span class="zh-CN">用于从文件系统加载的 URL 前缀：“file:”</span>
	 */
	public static final String FILE_URL_PREFIX = "file:";

	/**
	 * <span class="en-US">URL protocol for a file in the file system: "file"</span>
	 * <span class="zh-CN">文件系统中文件的 URL 协议：“file”</span>
	 */
	public static final String URL_PROTOCOL_FILE = "file";

	/**
	 * <span class="en-US">URL protocol for an entry from a jar file: "jar"</span>
	 * <span class="zh-CN">jar 文件中条目的 URL 协议：“jar”</span>
	 */
	public static final String URL_PROTOCOL_JAR = "jar";

	/**
	 * <span class="en-US">URL protocol for an entry from a zip file: "zip"</span>
	 * <span class="zh-CN">zip 文件中条目的 URL 协议：“zip”</span>
	 */
	public static final String URL_PROTOCOL_ZIP = "zip";

	/**
	 * <span class="en-US">URL protocol for an entry from a WebSphere jar file: "wsjar"</span>
	 * <span class="zh-CN">WebSphere jar 文件中条目的 URL 协议：“wsjar”</span>
	 */
	public static final String URL_PROTOCOL_WSJAR = "wsjar";

	/**
	 * <span class="en-US">URL protocol for an entry from an OC4J jar file: "code-source"</span>
	 * <span class="zh-CN">OC4J jar 文件中条目的 URL 协议：“code-source”</span>
	 */
	public static final String URL_PROTOCOL_CODE_SOURCE = "code-source";

	/**
	 * <span class="en-US">Separator between JAR URL and the path within the JAR</span>
	 * <span class="zh-CN">JAR URL 和 JAR 内路径之间的分隔符</span>
	 */
	public static final String JAR_URL_SEPARATOR = "!/";

	/**
	 * <span class="en-US">Carriage Return character</span>
	 * <span class="zh-CN">回车符</span>
	 */
	public static final char CR = '\r';

	/**
	 * <span class="en-US">Line Feed character</span>
	 * <span class="zh-CN">换行符</span>
	 */
	public static final char LF = '\n';

	/**
	 * <span class="en-US">Carriage Return Line Feed character</span>
	 * <span class="zh-CN">回车换行符</span>
	 */
	public static final String CRLF = "\r\n";
	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_TEXT.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_TEXT。</span>
	 */
	public static final String MIME_TYPE_TEXT = "text/plain";
	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_TEXT_XML.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_TEXT_XML.</span>
	 */
	public static final String MIME_TYPE_TEXT_XML = "text/xml";
	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_TEXT_YAML.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_TEXT_YAML.</span>
	 */
	public static final String MIME_TYPE_TEXT_YAML = "text/yaml";
	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_BINARY.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_BINARY.</span>
	 */
	public static final String MIME_TYPE_BINARY = "application/octet-stream";
	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_XML.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_XML.</span>
	 */
	public static final String MIME_TYPE_XML = "application/xml";
	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_JSON.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_JSON.</span>
	 */
	public static final String MIME_TYPE_JSON = "application/json";

	/**
	 * <span class="en-US">The constant value of mime type: MIME_TYPE_YAML.</span>
	 * <span class="zh-CN">mime类型常量值：MIME_TYPE_YAML.</span>
	 */
	public static final String MIME_TYPE_YAML = "application/x-yaml";

	/**
	 * <h3 class="en-US">Private constructor for BeanUtils</h3>
	 * <h3 class="zh-CN">JavaBean工具集的私有构造函数</h3>
	 */
	private FileUtils() {
	}

	static {
		//  Register SMB protocol handler for using java.net.URL class with "smb://"
		Config.registerSmbURLHandler();
	}

	/**
	 * <h3 class="en-US">Match the folder path in the entry path</h3>
	 * <h3 class="zh-CN">匹配入口路径中的文件夹路径</h3>
	 *
	 * @param entryPath  <span class="en-US">entry path</span>
	 *                   <span class="zh-CN">入口路径</span>
	 * @param folderPath <span class="en-US">folder path</span>
	 *                   <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">Match result</span>
	 * <span class="zh-CN">匹配结果</span>
	 */
	public static boolean matchFolder(final String entryPath, final String folderPath) {
		if (StringUtils.isEmpty(entryPath) || StringUtils.isEmpty(folderPath)) {
			return Boolean.FALSE;
		}
		String convertFolderPath = FileUtils.replacePageSeparator(folderPath) + "|";
		return FileUtils.replacePageSeparator(entryPath).startsWith(convertFolderPath);
	}

	/**
	 * <h3 class="en-US">Match the original path is the same as the destination path</h3>
	 * <h3 class="zh-CN">比较原始路径是否与目标路径一致</h3>
	 *
	 * @param origPath   <span class="en-US">original path</span>
	 *                   <span class="zh-CN">原始路径</span>
	 * @param destPath   <span class="en-US">destination path</span>
	 *                   <span class="zh-CN">目标路径</span>
	 * @param ignoreCase <span class="en-US">ignore the character case</span>
	 *                   <span class="zh-CN">忽略大小写</span>
	 * @return <span class="en-US">Match result</span>
	 * <span class="zh-CN">匹配结果</span>
	 */
	public static boolean matchFilePath(final String origPath, final String destPath, final boolean ignoreCase) {
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
	 * <h3 class="en-US">Retrieve MIMEType string</h3>
	 * <h3 class="zh-CN">检索 MIME 类型字符串</h3>
	 *
	 * @param extensionName <span class="en-US">File extension name</span>
	 *                      <span class="zh-CN">文件扩展名</span>
	 * @return <span class="en-US">MIMEType string</span>
	 * <span class="zh-CN">MIME类型字符串</span>
	 */
	public static String mimeType(final String extensionName) {
		if (StringUtils.notBlank(extensionName)) {
			String extName = extensionName.startsWith(".") ? extensionName : "." + extensionName;
			return Optional.ofNullable(URLConnection.getFileNameMap().getContentTypeFor(extName))
					.orElse(MIME_TYPE_BINARY);
		}
		return MIME_TYPE_BINARY;
	}

	public static boolean imageFile(final String fileLocation) {
		return mimeType(StringUtils.getFilenameExtension(fileLocation)).contains("image");
	}

	/**
	 * <h3 class="en-US">Return whether the given resource location is a URL: either a special "classpath" pseudo URL or a standard URL.</h3>
	 * <h3 class="zh-CN">返回给定的资源位置是否是 URL：特殊的“类路径”伪 URL 或标准 URL。</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String to check</span>
	 *                         <span class="zh-CN">要检查的位置字符串</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> when location qualifies as a URL, <code>Boolean.FALSE</code> for others</span>
	 * <span class="zh-CN">当位置符合 URL 条件时 <code>Boolean.TRUE</code>，对于其他条件则 <code>Boolean.FALSE</code></span>
	 */
	public static boolean isUrl(final String resourceLocation) {
		if (!FileUtils.isExists(resourceLocation)) {
			return Boolean.FALSE;
		}
		try {
			new URL(resourceLocation);
			return Boolean.TRUE;
		} catch (MalformedURLException ex) {
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Resolve the given resource location to a <code>java.net.URL</code>.</h3>
	 * <span class="en-US">
	 * Does not check whether the URL actually exists; simply returns
	 * the URL that the given location would correspond to.
	 * </span>
	 * <h3 class="zh-CN">将给定资源位置解析为 <code>java.net.URL</code>。</h3>
	 * <span class="zh-CN">不检查URL是否真实存在；只是返回给定位置对应的 URL。</span>
	 *
	 * @param resourceLocation <span class="en-US">the resource location to resolve: either a "classpath:" pseudo URL, a "file:" URL, or a plain file path</span>
	 *                         <span class="zh-CN">要解析的资源位置：“classpath:”伪 URL、 “file:”URL 或纯文件路</span>
	 * @return <span class="en-US">a corresponding URL object</span>
	 * <span class="zh-CN">对应的URL对象</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a URL</span>
	 *                               <span class="zh-CN">如果资源无法解析为 URL</span>
	 */
	public static URL getURL(final String resourceLocation) throws FileNotFoundException {
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
			// no URL -> treat as the file path
			try {
				return new File(resourceLocation).toURI().toURL();
			} catch (MalformedURLException ex2) {
				throw new FileNotFoundException("Resource location [" + resourceLocation +
						"] is neither a URL not a well-formed file path");
			}
		}
	}

	/**
	 * <h3 class="en-US">Read the file last modified time</h3>
	 * <h3 class="zh-CN">读取文件最后修改时间</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @return <span class="en-US">last modified time with the long type if file exists</span>
	 * <span class="zh-CN">如果文件存在，则最后修改时间为 long 类型</span>
	 */
	public static long lastModify(final String resourceLocation) {
		return FileUtils.lastModify(resourceLocation, new Properties());
	}

	/**
	 * <h3 class="en-US">Read the file last modified time</h3>
	 * <h3 class="zh-CN">读取文件最后修改时间</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @param properties       <span class="en-US">the properties configure of samba</span>
	 *                         <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US">last modified time with the long type if file exists</span>
	 * <span class="zh-CN">如果文件存在，则最后修改时间为 long 类型</span>
	 */
	public static long lastModify(final String resourceLocation, final Properties properties) {
		if (resourceLocation == null || resourceLocation.trim().isEmpty()) {
			return Globals.DEFAULT_VALUE_LONG;
		}
		if (resourceLocation.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = new SmbFile(resourceLocation, new BaseContext(new PropertyConfiguration(properties)))) {
				if (smbFile.exists()) {
					return smbFile.getLastModified();
				}
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Last_Modify_Read_File_Error", e);
				}
			}
		} else {
			try {
				File file = FileUtils.getFile(resourceLocation);
				if (file.exists()) {
					return file.lastModified();
				}
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Last_Modify_Read_File_Error", e);
				}
			}
		}
		return Globals.DEFAULT_VALUE_LONG;
	}

	/**
	 * <h3 class="en-US">Read the file last modified time</h3>
	 * <h3 class="zh-CN">读取文件最后修改时间</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @param properties       <span class="en-US">the properties configure of samba</span>
	 *                         <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US">last modified time with the <code>java.util.Date</code> type if file exists or <code>null</code> for others</span>
	 * <span class="zh-CN">如果文件存在，则最后修改时间为<code>java.util.Date</code>类型，其他情况返回<code>null</code></span>
	 */
	public static Date modifyDate(final String resourceLocation, final Properties properties) {
		long lastModify = FileUtils.lastModify(resourceLocation, properties);
		if (lastModify != Globals.DEFAULT_VALUE_LONG) {
			return new Date(lastModify);
		} else {
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Load resource and convert to <code>java.io.InputStream</code> used <code>Globals.DEFAULT_ENCODING</code></h3>
	 * <h3 class="zh-CN">使用 Globals.DEFAULT_ENCODING 加载资源并转换为 <code>java.io.InputStream</code></h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @return <span class="en-US"><code>java.io.InputStream</code> instance</span>
	 * <span class="zh-CN"><code>java.io.InputStream</code>实例对象</span>
	 * @throws IOException <span class="en-US">when opening input stream error</span>
	 *                     <span class="zh-CN">打开输入流时出错</span>
	 */
	public static InputStream loadFile(final String resourceLocation) throws IOException {
		if (StringUtils.isEmpty(resourceLocation)) {
			throw new IOException("Resource location is null! ");
		}
		//	Convert resource location to input stream
		InputStream inputStream;

		if (resourceLocation.startsWith(Globals.SAMBA_PROTOCOL)) {
			inputStream = new SmbFileInputStream(resourceLocation,
					new BaseContext(new PropertyConfiguration(new Properties())));
		} else {
			TargetPath targetPath = TargetPath.parse(resourceLocation);
			if (targetPath == null) {
				inputStream = FileUtils.class.getResourceAsStream(resourceLocation);
				if (inputStream == null) {
					try {
						inputStream = FileUtils.getURL(resourceLocation).openStream();
					} catch (FileNotFoundException e) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Input_Stream_Open_Error", e);
						}
						throw new IOException(e);
					}
				}
			} else {
				try {
					switch (StringUtils.getFilenameExtension(targetPath.getFilePath())) {
						case URL_PROTOCOL_JAR:
							inputStream = openInputStream(new JarFile(getFile(targetPath.getFilePath())),
									targetPath.getEntryPath());
							break;
						case URL_PROTOCOL_ZIP:
							inputStream = openInputStream(ZipFile.openZipFile(targetPath.getFilePath()),
									targetPath.getEntryPath());
							break;
						default:
							inputStream = null;
							break;
					}
				} catch (ZipException e) {
					throw new IOException("", e);
				}
			}
		}
		return inputStream;
	}

	/**
	 * <h3 class="en-US">Load resource from samba server and convert to <code>java.io.InputStream</code></h3>
	 * <h3 class="zh-CN">从samba服务器加载资源并转换为 <code>java.io.InputStream</code></h3>
	 *
	 * @param smbLocation <span class="en-US">the samba file location</span>
	 *                    <span class="zh-CN">samba文件位置</span>
	 * @param properties  <span class="en-US">the properties configure of samba</span>
	 *                    <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US"><code>java.io.InputStream</code> instance</span>
	 * <span class="zh-CN"><code>java.io.InputStream</code>实例对象</span>
	 * @throws IOException <span class="en-US">when opening input stream error</span>
	 *                     <span class="zh-CN">打开输入流时出错</span>
	 */
	public static InputStream loadFile(final String smbLocation, final Properties properties) throws IOException {
		return loadFile(smbLocation, properties, null);
	}

	/**
	 * <h3 class="en-US">Load resource from samba server and convert to <code>java.io.InputStream</code></h3>
	 * <h3 class="zh-CN">从samba服务器加载资源并转换为 <code>java.io.InputStream</code></h3>
	 *
	 * @param smbLocation   <span class="en-US">the samba file location</span>
	 *                      <span class="zh-CN">samba文件位置</span>
	 * @param authenticator <span class="en-US">Authenticator instance</span>
	 *                      <span class="zh-CN">身份验证器实例</span>
	 * @return <span class="en-US"><code>java.io.InputStream</code> instance</span>
	 * <span class="zh-CN"><code>java.io.InputStream</code>实例对象</span>
	 * @throws IOException <span class="en-US">when opening input stream error</span>
	 *                     <span class="zh-CN">打开输入流时出错</span>
	 */
	public static InputStream loadFile(final String smbLocation, final NtlmPasswordAuthenticator authenticator)
			throws IOException {
		return loadFile(smbLocation, null, authenticator);
	}

	/**
	 * <h3 class="en-US">Load resource from samba server and convert to <code>java.io.InputStream</code></h3>
	 * <h3 class="zh-CN">从samba服务器加载资源并转换为 <code>java.io.InputStream</code></h3>
	 *
	 * @param smbLocation   <span class="en-US">the samba file location</span>
	 *                      <span class="zh-CN">samba文件位置</span>
	 * @param properties    <span class="en-US">the properties configure of samba</span>
	 *                      <span class="zh-CN">访问samba的配置信息</span>
	 * @param authenticator <span class="en-US">Authenticator instance</span>
	 *                      <span class="zh-CN">身份验证器实例</span>
	 * @return <span class="en-US"><code>java.io.InputStream</code> instance</span>
	 * <span class="zh-CN"><code>java.io.InputStream</code>实例对象</span>
	 * @throws IOException <span class="en-US">when opening input stream error</span>
	 *                     <span class="zh-CN">打开输入流时出错</span>
	 */
	public static InputStream loadFile(final String smbLocation, final Properties properties,
	                                   final NtlmPasswordAuthenticator authenticator)
			throws IOException {
		if (StringUtils.isEmpty(smbLocation) || !smbLocation.startsWith(Globals.SAMBA_PROTOCOL)) {
			throw new IOException("Location is not a valid smb location! ");
		}
		return new SmbFileInputStream(smbLocation, generateContext(properties, authenticator));
	}

	/**
	 * <h3 class="en-US">Resolve the given resource location to a <code>jcifs.smb.SmbFile</code></h3>
	 * <h3 class="zh-CN">将给定资源位置解析为 <code>jcifs.smb.SmbFile</code></h3>
	 *
	 * @param smbLocation <span class="en-US">the samba file location</span>
	 *                    <span class="zh-CN">samba文件位置</span>
	 * @param properties  <span class="en-US">the properties configure of samba</span>
	 *                    <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US">a corresponding <code>jcifs.smb.SmbFile</code> object or <code>null</code> if an error occurs</span>
	 * <span class="zh-CN">对应的<code>jcifs.smb.SmbFile</code>对象，如果出现异常则返回<code>null</code></span>
	 */
	public static SmbFile getFile(final String smbLocation, final Properties properties) {
		if (StringUtils.isEmpty(smbLocation)) {
			return null;
		}
		try {
			return new SmbFile(smbLocation, generateContext(properties, null));
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Resolve the given resource location to a <code>jcifs.smb.SmbFile</code></h3>
	 * <h3 class="zh-CN">将给定资源位置解析为 <code>jcifs.smb.SmbFile</code></h3>
	 *
	 * @param smbLocation   <span class="en-US">the samba file location</span>
	 *                      <span class="zh-CN">samba文件位置</span>
	 * @param authenticator <span class="en-US">Authenticator instance</span>
	 *                      <span class="zh-CN">身份验证器实例</span>
	 * @return <span class="en-US">a corresponding <code>jcifs.smb.SmbFile</code> object or <code>null</code> if an error occurs</span>
	 * <span class="zh-CN">对应的<code>jcifs.smb.SmbFile</code>对象，如果出现异常则返回<code>null</code></span>
	 */
	public static SmbFile getFile(final String smbLocation, final NtlmPasswordAuthenticator authenticator) {
		if (StringUtils.isEmpty(smbLocation)) {
			return null;
		}
		try {
			return new SmbFile(smbLocation, generateContext(null, authenticator));
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Resolve the given resource location to a <code>jcifs.smb.SmbFile</code></h3>
	 * <h3 class="zh-CN">将给定资源位置解析为 <code>jcifs.smb.SmbFile</code></h3>
	 *
	 * @param smbLocation   <span class="en-US">the samba file location</span>
	 *                      <span class="zh-CN">samba文件位置</span>
	 * @param properties    <span class="en-US">the properties configure of samba</span>
	 *                      <span class="zh-CN">访问samba的配置信息</span>
	 * @param authenticator <span class="en-US">Authenticator instance</span>
	 *                      <span class="zh-CN">身份验证器实例</span>
	 * @return <span class="en-US">a corresponding <code>jcifs.smb.SmbFile</code> object or <code>null</code> if an error occurs</span>
	 * <span class="zh-CN">对应的<code>jcifs.smb.SmbFile</code>对象，如果出现异常则返回<code>null</code></span>
	 */
	public static SmbFile getFile(final String smbLocation, final Properties properties,
	                              final NtlmPasswordAuthenticator authenticator) {
		if (StringUtils.isEmpty(smbLocation)) {
			return null;
		}
		try {
			return new SmbFile(smbLocation, generateContext(properties, authenticator));
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Resolve the given resource location to a <code>java.io.File</code></h3>
	 * <span class="en-US">
	 * For example, to a file in the file system.
	 * Does not check whether the fil actually exists;
	 * simply returns the File that the given location would correspond to.
	 * </span>
	 * <h3 class="zh-CN">将给定资源位置解析为 <code>java.io.File</code></h3>
	 * <span class="zh-CN">即文件系统中的文件。不检查fil是否确实存在；只是返回给定位置对应的文件。</span>
	 *
	 * @param resourceLocation <span class="en-US">the resource location to resolve: either a "classpath:" pseudo URL, a "file:" URL, or a plain file path</span>
	 *                         <span class="zh-CN">要解析的资源位置：“classpath:”伪 URL、 “file:”URL 或纯文件路</span>
	 * @return <span class="en-US">a corresponding <code>java.io.File</code> object</span>
	 * <span class="zh-CN">对应的<code>java.io.File</code>对象</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static File getFile(final String resourceLocation) throws FileNotFoundException {
		if (resourceLocation == null) {
			throw new IllegalArgumentException("Resource location must not be null");
		}
		if (resourceLocation.startsWith(CLASSPATH_URL_PREFIX)) {
			String path = resourceLocation.substring(CLASSPATH_URL_PREFIX.length());
			String description = "class path resource [" + path + "]";
			try {
				return getFile(FileUtils.getURL(resourceLocation), description);
			} catch (FileNotFoundException ignored) {
			}
		}
		try {
			// try URL
			return getFile(new URL(resourceLocation));
		} catch (MalformedURLException ex) {
			// no URL -> treat as the file path
			return new File(resourceLocation);
		}
	}

	/**
	 * <h3 class="en-US">Resolve the given resource URL to a <code>java.io.File</code>, i.e., to a file in the file system.</h3>
	 * <h3 class="zh-CN">将给定的资源 URL 解析为 java.io.File，即文件系统中的文件。</h3>
	 *
	 * @param resourceUrl <span class="en-US">the resource URL to resolve</span>
	 *                    <span class="zh-CN">要解析的资源 URL</span>
	 * @return <span class="en-US">a corresponding <code>java.io.File</code> object</span>
	 * <span class="zh-CN">对应的<code>java.io.File</code>对象</span>
	 * @throws FileNotFoundException <span class="en-US">if the URL cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果URL无法解析为文件系统中的文件</span>
	 */
	public static File getFile(final URL resourceUrl) throws FileNotFoundException {
		return getFile(resourceUrl, "URL");
	}

	/**
	 * <h3 class="en-US">Resolve the given resource URL to a <code>java.io.File</code>, i.e., to a file in the file system.</h3>
	 * <h3 class="zh-CN">将给定的资源 URL 解析为 java.io.File，即文件系统中的文件。</h3>
	 *
	 * @param resourceUrl <span class="en-US">the resource URL to resolve</span>
	 *                    <span class="zh-CN">要解析的资源 URL</span>
	 * @param description <span class="en-US">a description of the original resource that the URL was created for (for example, a class path location)</span>
	 *                    <span class="zh-CN">为其创建 URL 的原始资源的描述（例如，类路径位置）</span>
	 * @return <span class="en-US">a corresponding <code>java.io.File</code> object</span>
	 * <span class="zh-CN">对应的<code>java.io.File</code>对象</span>
	 * @throws FileNotFoundException <span class="en-US">if the URL cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果URL无法解析为文件系统中的文件</span>
	 */
	public static File getFile(final URL resourceUrl, final String description) throws FileNotFoundException {
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
	 * <h3 class="en-US">Resolve the given resource URI to a <code>java.io.File</code>, i.e., to a file in the file system.</h3>
	 * <h3 class="zh-CN">将给定的资源 URI 解析为 java.io.File，即文件系统中的文件。</h3>
	 *
	 * @param resourceUri <span class="en-US">the resource URI to resolve</span>
	 *                    <span class="zh-CN">要解析的资源 URI</span>
	 * @return <span class="en-US">a corresponding <code>java.io.File</code> object</span>
	 * <span class="zh-CN">对应的<code>java.io.File</code>对象</span>
	 * @throws FileNotFoundException <span class="en-US">if the URL cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果URL无法解析为文件系统中的文件</span>
	 */
	public static File getFile(final URI resourceUri) throws FileNotFoundException {
		return getFile(resourceUri, "URI");
	}

	/**
	 * <h3 class="en-US">Resolve the given resource URI to a <code>java.io.File</code>, i.e., to a file in the file system.</h3>
	 * <h3 class="zh-CN">将给定的资源 URI 解析为 java.io.File，即文件系统中的文件。</h3>
	 *
	 * @param resourceUri <span class="en-US">the resource URI to resolve</span>
	 *                    <span class="zh-CN">要解析的资源 URI</span>
	 * @param description <span class="en-US">a description of the original resource that the URL was created for (for example, a class path location)</span>
	 *                    <span class="zh-CN">为其创建 URL 的原始资源的描述（例如，类路径位置）</span>
	 * @return <span class="en-US">a corresponding <code>java.io.File</code> object</span>
	 * <span class="zh-CN">对应的<code>java.io.File</code>对象</span>
	 * @throws FileNotFoundException <span class="en-US">if the URL cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果URL无法解析为文件系统中的文件</span>
	 */
	public static File getFile(final URI resourceUri, final String description) throws FileNotFoundException {
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
	 * <h3 class="en-US">Retrieve the entry path list of the given file path</h3>
	 * <h3 class="zh-CN">检索给定文件路径的条目路径列表</h3>
	 *
	 * @param filePath <span class="en-US">the file path</span>
	 *                 <span class="zh-CN">给定文件路径</span>
	 * @return <span class="en-US">entry path list</span>
	 * <span class="zh-CN">条目路径列表</span>
	 */
	public static List<String> listJarEntry(final String filePath) {
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
				LOGGER.debug("Entry_Content_Load_Error", e);
			}
		}
		return entryList;
	}

	/**
	 * <h3 class="en-US">Read jar entry information content</h3>
	 * <h3 class="zh-CN">读取jar文件条目资源内容</h3>
	 *
	 * @param filePath  <span class="en-US">the file path</span>
	 *                  <span class="zh-CN">给定文件路径</span>
	 * @param entryPath <span class="en-US">the entry path</span>
	 *                  <span class="zh-CN">条目资源路径</span>
	 * @return <span class="en-US">entry information content</span>
	 * <span class="zh-CN">条目资源路径文件内容</span>
	 */
	public static String readJarEntryInfo(final String filePath, final String entryPath) {
		try (JarFile jarFile = new JarFile(getFile(filePath))) {
			JarEntry packageEntry = jarFile.getJarEntry(entryPath);
			if (packageEntry != null) {
				return IOUtils.readContent(jarFile.getInputStream(packageEntry));
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Entry_Content_Load_Error", e);
			}
		}
		return Globals.DEFAULT_VALUE_STRING;
	}

	/**
	 * <h3 class="en-US">Read jar entry content as byte arrays</h3>
	 * <h3 class="zh-CN">读取jar文件条目资源内容的字节数组</h3>
	 *
	 * @param filePath  <span class="en-US">the file path</span>
	 *                  <span class="zh-CN">给定文件路径</span>
	 * @param entryPath <span class="en-US">the entry path</span>
	 *                  <span class="zh-CN">条目资源路径</span>
	 * @return <span class="en-US">entry content or zero length array if not exists</span>
	 * <span class="zh-CN">条目内容或零长度数组（如果不存在）</span>
	 */
	public static byte[] readJarEntryBytes(final String filePath, final String entryPath) {
		return FileUtils.readJarEntryBytes(filePath, entryPath, 0, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Read jar entry content as byte arrays</h3>
	 * <h3 class="zh-CN">读取jar文件条目资源内容的字节数组</h3>
	 *
	 * @param filePath  <span class="en-US">the file path</span>
	 *                  <span class="zh-CN">给定文件路径</span>
	 * @param entryPath <span class="en-US">the entry path</span>
	 *                  <span class="zh-CN">条目资源路径</span>
	 * @param offset    <span class="en-US">read offset</span>
	 *                  <span class="zh-CN">读取起始偏移量</span>
	 * @param length    <span class="en-US">read length</span>
	 *                  <span class="zh-CN">读取数据长度</span>
	 * @return <span class="en-US">entry content or zero length array if not exists</span>
	 * <span class="zh-CN">条目内容或零长度数组（如果不存在）</span>
	 */
	public static byte[] readJarEntryBytes(final String filePath, final String entryPath,
	                                       final int offset, final int length) {
		try (JarFile jarFile = new JarFile(getFile(filePath))) {
			JarEntry packageEntry = jarFile.getJarEntry(entryPath);
			if (packageEntry != null) {
				return IOUtils.readBytes(jarFile.getInputStream(packageEntry), offset, length);
			}
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Entry_Content_Load_Error", e);
			}
		}
		return new byte[0];
	}

	/**
	 * <h3 class="en-US">Read file instance content as byte arrays</h3>
	 * <h3 class="zh-CN">读取文件实例对象内容的字节数组</h3>
	 *
	 * @param file <span class="en-US">the file instance</span>
	 *             <span class="zh-CN">文件实例对象</span>
	 * @return <span class="en-US">file content or zero length array if not exists</span>
	 * <span class="zh-CN">文件内容或零长度数组（如果不存在）</span>
	 * @throws FileNotFoundException <span class="en-US">if the URL cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果URL无法解析为文件系统中的文件</span>
	 */
	public static byte[] readFileBytes(final File file) throws FileNotFoundException {
		if (file == null || !file.exists()) {
			throw new FileNotFoundException("File not found");
		}
		return IOUtils.readBytes(new FileInputStream(file));
	}

	/**
	 * <h3 class="en-US">Read the content of given file path as byte arrays</h3>
	 * <h3 class="zh-CN">读取给定文件地址的文件内容为字节数组</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @return <span class="en-US">file content or zero length array if not exists</span>
	 * <span class="zh-CN">文件内容或零长度数组（如果不存在）</span>
	 * @throws FileNotFoundException <span class="en-US">if the URL cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果URL无法解析为文件系统中的文件</span>
	 */
	public static byte[] readFileBytes(final String resourceLocation) throws FileNotFoundException {
		TargetPath targetPath = TargetPath.parse(resourceLocation);
		if (targetPath == null) {
			return readFileBytes(FileUtils.getFile(resourceLocation));
		}
		if (targetPath.getFilePath().toLowerCase().endsWith(URL_PROTOCOL_JAR)) {
			return FileUtils.readJarEntryBytes(targetPath.getFilePath(), targetPath.getEntryPath());
		} else if (targetPath.getFilePath().toLowerCase().endsWith(URL_PROTOCOL_ZIP)) {
			try {
				return ZipFile.openZipFile(targetPath.getFilePath()).readEntry(targetPath.getEntryPath());
			} catch (ZipException ignored) {
				return new byte[0];
			}
		} else {
			return new byte[0];
		}
	}

	/**
	 * <h3 class="en-US">Read part content of the given file path as byte arrays</h3>
	 * <h3 class="zh-CN">读取给定文件地址的部分文件内容为字节数组</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @param offset           <span class="en-US">read offset</span>
	 *                         <span class="zh-CN">读取起始偏移量</span>
	 * @param length           <span class="en-US">read length</span>
	 *                         <span class="zh-CN">读取数据长度</span>
	 * @return <span class="en-US">file content or zero length array if not exists</span>
	 * <span class="zh-CN">文件内容或零长度数组（如果不存在）</span>
	 */
	public static byte[] readFileBytes(final String resourceLocation, final long offset, final int length) {
		byte[] readByte = new byte[length];

		try (RandomAccessFile randomAccessFile = new RandomAccessFile(resourceLocation, "r")) {
			randomAccessFile.seek(offset);
			randomAccessFile.read(readByte);
		} catch (Exception e) {
			readByte = new byte[0];
		}

		return readByte;
	}

	/**
	 * <h3 class="en-US">Retrieve content size of the given file path</h3>
	 * <h3 class="zh-CN">读取给定文件地址的文件大小</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @return <span class="en-US">File size</span>
	 * <span class="zh-CN">文件大小</span>
	 */
	public static long fileSize(final String resourceLocation) {
		return FileUtils.fileSize(resourceLocation, null);
	}

	/**
	 * <h3 class="en-US">Retrieve content size of the given file path</h3>
	 * <h3 class="zh-CN">读取给定文件地址的文件大小</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @param cifsContext      <span class="en-US">the cifs context</span>
	 *                         <span class="zh-CN">CIFS上下文配置信息</span>
	 * @return <span class="en-US">File size</span>
	 * <span class="zh-CN">文件大小</span>
	 */
	public static long fileSize(final String resourceLocation, final CIFSContext cifsContext) {
		if (resourceLocation == null) {
			return Globals.DEFAULT_VALUE_LONG;
		}

		if (resourceLocation.startsWith(Globals.SAMBA_PROTOCOL)) {
			return fileSize(FileUtils.getFile(resourceLocation, cifsContext));
		} else {
			try {
				return fileSize(FileUtils.getFile(resourceLocation));
			} catch (FileNotFoundException e) {
				return Globals.DEFAULT_VALUE_LONG;
			}
		}
	}

	/**
	 * <h3 class="en-US">Retrieve content size of given file instance</h3>
	 * <h3 class="zh-CN">读取给定文件实例对象的文件大小</h3>
	 *
	 * @param fileObject <span class="en-US">the file object</span>
	 *                   <span class="zh-CN">文件实例对象</span>
	 * @return <span class="en-US">File size</span>
	 * <span class="zh-CN">文件大小</span>
	 */
	public static long fileSize(final Object fileObject) {
		if (fileObject == null) {
			return Globals.DEFAULT_VALUE_LONG;
		}
		long fileSize = 0L;
		if (fileObject instanceof SmbFile) {
			try {
				if (((SmbFile) fileObject).exists()) {
					if (((SmbFile) fileObject).isDirectory()) {
						SmbFile[] childFiles = ((SmbFile) fileObject).listFiles();
						if (childFiles != null) {
							for (SmbFile childFile : childFiles) {
								fileSize += fileSize(childFile);
							}
						}
					} else if (((SmbFile) fileObject).isFile()) {
						fileSize += ((SmbFile) fileObject).length();
					}
				}
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Size_Read_File_Error", e);
				}
				return Globals.DEFAULT_VALUE_LONG;
			}
		} else {
			if (((File) fileObject).exists()) {
				if (((File) fileObject).isDirectory()) {
					File[] childFiles = ((File) fileObject).listFiles();
					if (childFiles != null) {
						for (File childFile : childFiles) {
							fileSize += fileSize(childFile);
						}
					}
				} else if (((File) fileObject).isFile()) {
					fileSize += ((File) fileObject).length();
				}
			}
		}
		return fileSize;
	}

	/**
	 * <h3 class="en-US">Determine whether the given URL points to a resource in a jar file, that is, has protocol "jar", "zip", "wsjar" or "code-source".</h3>
	 * <span class="en-US">
	 * ".zip" and ".wsjar" are used by BEA WebLogic Server and IBM WebSphere, respectively,
	 * but can be treated like jar files.
	 * The same applies to "code-source" URLs on Oracle OC4J, except that the path contains a jar separator.
	 * </span>
	 * <h3 class="zh-CN">确定给定的 URL 是否指向 jar 文件中的资源，即具有协议“jar”、“zip”、“wsjar”或“code-source”。</h3>
	 * <span class="zh-CN">
	 * “zip”和“wsjar”分别由 BEA WebLogic Server 和 IBM WebSphere 使用，
	 * 但可以像 jar 文件一样对待。这同样适用于 Oracle OC4J 上的“代码源”URL，只不过路径包含 jar 分隔符。
	 * </span>
	 *
	 * @param url <span class="en-US">the URL to check</span>
	 *            <span class="zh-CN">要检查的资源 URL</span>
	 * @return <span class="en-US">whether the URL has been identified as a JAR URL</span>
	 * <span class="zh-CN">URL是否已被识别为JAR URL</span>
	 */
	public static boolean isJarURL(final URL url) {
		String protocol = url.getProtocol();
		return (URL_PROTOCOL_JAR.equals(protocol) ||
				URL_PROTOCOL_ZIP.equals(protocol) ||
				URL_PROTOCOL_WSJAR.equals(protocol) ||
				(URL_PROTOCOL_CODE_SOURCE.equals(protocol) && url.getPath().contains(JAR_URL_SEPARATOR)));
	}

	/**
	 * <h3 class="en-US">Extract the URL for the actual jar file from the given URL (which may point to a resource in a jar file or to a jar file itself).</h3>
	 * <h3 class="zh-CN">从给定的 URL（可能指向 jar 文件中的资源或 jar 文件本身）中提取实际 jar 文件的 URL。</h3>
	 *
	 * @param jarUrl <span class="en-US">the original URL</span>
	 *               <span class="zh-CN">原始 URL</span>
	 * @return <span class="en-US">whether the URL has been identified as a JAR URL</span>
	 * <span class="zh-CN">实际 jar 文件的 URL</span>
	 * @throws MalformedURLException <span class="en-US">if no valid jar file URL could be extracted</span>
	 *                               <span class="zh-CN">如果无法提取有效的 jar 文件 URL</span>
	 */
	public static URL extractJarFileURL(final URL jarUrl) throws MalformedURLException {
		String urlFile = jarUrl.getFile();
		int separatorIndex = urlFile.indexOf(JAR_URL_SEPARATOR);
		if (separatorIndex != -1) {
			String jarFile = urlFile.substring(0, separatorIndex);
			try {
				return new URL(jarFile);
			} catch (MalformedURLException ex) {
				// Probably no protocol in the original jar URL, like "jar:C:/path/jarFile.jar".
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
	 * <h3 class="en-US">Create a URI instance for the given URL</h3>
	 * <span class="en-US">
	 * Replacing spaces with "%20" quotes first.
	 * Furthermore, this method works on JDK 1.4 as well,
	 * in contrast to the <code>URL.toURI()</code> method.
	 * </span>
	 * <h3 class="zh-CN">为给定 URL 创建 URI 实例</h3>
	 * <span class="zh-CN">首先用“%20”引号替换空格。此外，与 <code>URL.toURI()</code> 方法相比，此方法也适用于 JDK 1.4。</span>
	 *
	 * @param url <span class="en-US">the URL to convert into a URI instance</span>
	 *            <span class="zh-CN">要转换为 URI 实例的 URL</span>
	 * @return <span class="en-US">the URI instance</span>
	 * <span class="zh-CN">URI 实例</span>
	 * @throws URISyntaxException <span class="en-US">if the URL was not a valid URI</span>
	 *                            <span class="zh-CN">如果 URL 不是有效的 URI</span>
	 * @see java.net.URL#toURI() java.net.URL#toURI()
	 */
	public static URI toURI(final URL url) throws URISyntaxException {
		return FileUtils.toURI(url.toString());
	}

	/**
	 * <h3 class="en-US">Create a URI instance for the given location String</h3>
	 * <span class="en-US">replacing spaces with "%20" quotes first.</span>
	 * <h3 class="zh-CN">为给定位置字符串创建 URI 实例</h3>
	 * <span class="zh-CN">首先用“%20”引号替换空格。</span>
	 *
	 * @param location <span class="en-US">the location String to convert into a URI instance</span>
	 *                 <span class="zh-CN">要转换为 URI 实例的位置字符串</span>
	 * @return <span class="en-US">the URI instance</span>
	 * <span class="zh-CN">URI 实例</span>
	 * @throws URISyntaxException <span class="en-US">if the location wasn't a valid URI</span>
	 *                            <span class="zh-CN">如果该位置不是有效的 URI</span>
	 */
	public static URI toURI(final String location) throws URISyntaxException {
		return new URI(StringUtils.replace(location, " ", "%20"));
	}

	/**
	 * <h3 class="en-US">Retrieve the entry path list of given URI instance</h3>
	 * <h3 class="zh-CN">检索给定URI实例对象的条目路径列表</h3>
	 *
	 * @param uri <span class="en-US">Jar file URI instance</span>
	 *            <span class="zh-CN">Jar 文件 URI 实例</span>
	 * @return <span class="en-US">entry path list</span>
	 * <span class="zh-CN">条目路径列表</span>
	 */
	public static List<String> listJarEntry(final URI uri) {
		return Optional.ofNullable(uri)
				.map(URI::getPath)
				.map(fullPath -> {
					int index = fullPath.indexOf(JAR_URL_SEPARATOR);
					if (index > 0) {
						return TargetPath.newInstance(fullPath.substring(0, index),
								fullPath.substring(index + JAR_URL_SEPARATOR.length()));
					} else {
						return TargetPath.newInstance(fullPath, Globals.DEFAULT_VALUE_STRING);
					}
				})
				.filter(jarPath -> FileUtils.isExists(jarPath.getFilePath()))
				.map(jarPath -> {
					final List<String> returnList = new ArrayList<>();
					JarFile jarFile = null;
					try {
						File file = FileUtils.getFile(jarPath.getFilePath());
						BasicFileAttributes basicFileAttributes =
								Files.readAttributes(file.toPath(), BasicFileAttributes.class);
						if (basicFileAttributes.isDirectory()) {
							returnList.addAll(FileUtils.listFiles(file));
						} else if (basicFileAttributes.isRegularFile()) {
							jarFile = new JarFile(file);
							jarFile.entries().asIterator().forEachRemaining(jarEntry -> {
								if (!jarEntry.isDirectory()) {
									String entryName = jarEntry.getName();
									if (StringUtils.isEmpty(jarPath.getEntryPath())
											|| entryName.startsWith(jarPath.getEntryPath())) {
										returnList.add(entryName);
									}
								}
							});
						}
					} catch (Exception e) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Entry_List_Error", e);
						}
					} finally {
						IOUtils.closeStream(jarFile);
					}
					return returnList;
				})
				.orElse(Collections.emptyList());
	}

	/**
	 * <h3 class="en-US">List files of the given folder path</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath));
	}

	/**
	 * <h3 class="en-US">List files of the given folder path</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表</h3>
	 *
	 * @param filePath        <span class="en-US">the folder path</span>
	 *                        <span class="zh-CN">文件夹路径</span>
	 * @param readHiddenFiles <span class="en-US">List include hidden files</span>
	 *                        <span class="zh-CN">包含隐藏文件</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath, final boolean readHiddenFiles)
			throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), readHiddenFiles);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath, final boolean readHiddenFiles,
	                                     final boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), readHiddenFiles, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath, final boolean readHiddenFiles,
	                                     final boolean includeRootFolder, final boolean iterateChildFolder)
			throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), readHiddenFiles, includeRootFolder, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表</h3>
	 *
	 * @param file <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *             <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file) {
		return FileUtils.listFiles(file, null);
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表</h3>
	 *
	 * @param file            <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                        <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param readHiddenFiles <span class="en-US">List include hidden files</span>
	 *                        <span class="zh-CN">包含隐藏文件</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final boolean readHiddenFiles) {
		return FileUtils.listFiles(file, null, readHiddenFiles);
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表</h3>
	 *
	 * @param file               <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                           <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final boolean readHiddenFiles,
	                                     final boolean iterateChildFolder) {
		return FileUtils.listFiles(file, null, readHiddenFiles, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表</h3>
	 *
	 * @param file               <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                           <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final boolean readHiddenFiles,
	                                     final boolean includeRootFolder, final boolean iterateChildFolder) {
		return FileUtils.listFiles(file, null, readHiddenFiles, includeRootFolder, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @param filter   <span class="en-US">file name filter instance</span>
	 *                 <span class="zh-CN">文件名过滤器实例</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath, final FilenameFilter filter)
			throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), filter);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath        <span class="en-US">the folder path</span>
	 *                        <span class="zh-CN">文件夹路径</span>
	 * @param filter          <span class="en-US">file name filter instance</span>
	 *                        <span class="zh-CN">文件名过滤器实例</span>
	 * @param readHiddenFiles <span class="en-US">List include hidden files</span>
	 *                        <span class="zh-CN">包含隐藏文件</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath, final FilenameFilter filter,
	                                     final boolean readHiddenFiles) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), filter, readHiddenFiles);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param filter             <span class="en-US">file name filter instance</span>
	 *                           <span class="zh-CN">文件名过滤器实例</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFiles(final String filePath, final FilenameFilter filter, final boolean readHiddenFiles,
	                                     final boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), filter, readHiddenFiles, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param file   <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *               <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param filter <span class="en-US">file name filter instance</span>
	 *               <span class="zh-CN">文件名过滤器实例</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final FilenameFilter filter) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, Boolean.TRUE,
				Boolean.FALSE, Boolean.TRUE);
		return returnList;
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param file            <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                        <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param filter          <span class="en-US">file name filter instance</span>
	 *                        <span class="zh-CN">文件名过滤器实例</span>
	 * @param readHiddenFiles <span class="en-US">List include hidden files</span>
	 *                        <span class="zh-CN">包含隐藏文件</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final FilenameFilter filter, final boolean readHiddenFiles) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, readHiddenFiles,
				Boolean.FALSE, Boolean.TRUE);
		return returnList;
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param file              <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                          <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param filter            <span class="en-US">file name filter instance</span>
	 *                          <span class="zh-CN">文件名过滤器实例</span>
	 * @param readHiddenFiles   <span class="en-US">List include hidden files</span>
	 *                          <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder <span class="en-US">to include root folder</span>
	 *                          <span class="zh-CN">包含根文件夹路径</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final FilenameFilter filter,
	                                     final boolean readHiddenFiles, final boolean includeRootFolder) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, readHiddenFiles, includeRootFolder, Boolean.TRUE);
		return returnList;
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param file               <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                           <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param filter             <span class="en-US">file name filter instance</span>
	 *                           <span class="zh-CN">文件名过滤器实例</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listFiles(final File file, final FilenameFilter filter, final boolean readHiddenFiles,
	                                     final boolean includeRootFolder, final boolean iterateChildFolder) {
		List<String> returnList = new ArrayList<>();
		FileUtils.listFiles(file, filter, returnList, readHiddenFiles, includeRootFolder, iterateChildFolder);
		return returnList;
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @param fileList <span class="en-US">current child file list</span>
	 *                 <span class="zh-CN">名称列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final List<String> fileList) throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, Boolean.TRUE, Boolean.FALSE, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中</h3>
	 *
	 * @param filePath        <span class="en-US">the folder path</span>
	 *                        <span class="zh-CN">文件夹路径</span>
	 * @param fileList        <span class="en-US">current child file list</span>
	 *                        <span class="zh-CN">名称列表</span>
	 * @param readHiddenFiles <span class="en-US">List include hidden files</span>
	 *                        <span class="zh-CN">包含隐藏文件</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final List<String> fileList, final boolean readHiddenFiles)
			throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, readHiddenFiles,
				Boolean.FALSE, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param fileList           <span class="en-US">current child file list</span>
	 *                           <span class="zh-CN">名称列表</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final List<String> fileList, final boolean readHiddenFiles,
	                             final boolean iterateChildFolder) throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, readHiddenFiles,
				Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param fileList           <span class="en-US">current child file list</span>
	 *                           <span class="zh-CN">名称列表</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final List<String> fileList, final boolean readHiddenFiles,
	                             final boolean includeRootFolder, final boolean iterateChildFolder)
			throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), null, fileList, readHiddenFiles,
				includeRootFolder, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @param filter   <span class="en-US">file name filter instance</span>
	 *                 <span class="zh-CN">文件名过滤器实例</span>
	 * @param fileList <span class="en-US">current child file list</span>
	 *                 <span class="zh-CN">名称列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final FilenameFilter filter, final List<String> fileList)
			throws IOException {
		FileUtils.listFiles(FileUtils.getFile(filePath), filter, fileList, Boolean.TRUE,
				Boolean.FALSE, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath          <span class="en-US">the folder path</span>
	 *                          <span class="zh-CN">文件夹路径</span>
	 * @param filter            <span class="en-US">file name filter instance</span>
	 *                          <span class="zh-CN">文件名过滤器实例</span>
	 * @param fileList          <span class="en-US">current child file list</span>
	 *                          <span class="zh-CN">名称列表</span>
	 * @param includeRootFolder <span class="en-US">to include root folder</span>
	 *                          <span class="zh-CN">包含根文件夹路径</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final FilenameFilter filter, final List<String> fileList,
	                             final boolean includeRootFolder) throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), filter, fileList, Boolean.TRUE,
				includeRootFolder, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and add to the given name list by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表并添加到给定的名称列表中，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param filter             <span class="en-US">file name filter instance</span>
	 *                           <span class="zh-CN">文件名过滤器实例</span>
	 * @param fileList           <span class="en-US">current child file list</span>
	 *                           <span class="zh-CN">名称列表</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static void listFiles(final String filePath, final FilenameFilter filter, final List<String> fileList,
	                             final boolean includeRootFolder, final boolean iterateChildFolder)
			throws FileNotFoundException {
		FileUtils.listFiles(FileUtils.getFile(filePath), filter, fileList, Boolean.TRUE,
				includeRootFolder, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance and add to the given name list by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表并添加到给定的名称列表中，使用给定的文件名过滤器实例</h3>
	 *
	 * @param file               <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                           <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param filter             <span class="en-US">file name filter instance</span>
	 *                           <span class="zh-CN">文件名过滤器实例</span>
	 * @param fileList           <span class="en-US">current child file list</span>
	 *                           <span class="zh-CN">名称列表</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 */
	public static void listFiles(final File file, final FilenameFilter filter, List<String> fileList,
	                             final boolean readHiddenFiles, final boolean includeRootFolder,
	                             final boolean iterateChildFolder) {
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
						if (filter == null || filter.accept(childFile.getParentFile(), childFile.getName())) {
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
	 * <h3 class="en-US">List child folder of the given folder path and add to the given name list</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的子文件夹列表并添加到给定的名称列表中</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listDirectory(final String filePath) throws FileNotFoundException {
		List<String> directoryList = new ArrayList<>();
		FileUtils.listDirectory(FileUtils.getFile(filePath), directoryList);
		return directoryList;
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance by given file name filter instance</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param directory <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                  <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 */
	public static List<String> listDirectory(final File directory) {
		List<String> directoryList = new ArrayList<>();
		FileUtils.listDirectory(directory, directoryList);
		return directoryList;
	}

	/**
	 * <h3 class="en-US">List child folder of given folder <code>java.io.File</code> instance and add to the given name list</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象内的子文件夹列表并添加到给定的名称列表中</h3>
	 *
	 * @param file          <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *                      <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @param directoryList <span class="en-US">current child directory list</span>
	 *                      <span class="zh-CN">子文件夹列表</span>
	 */
	public static void listDirectory(final File file, final List<String> directoryList) {
		if (file == null || !file.isDirectory() || directoryList == null) {
			return;
		}
		Optional.ofNullable(file.listFiles(new DirectoryFileFilter()))
				.map(Arrays::asList)
				.ifPresent(directories -> directories.forEach(directory -> {
					directoryList.add(directory.getAbsolutePath());
					FileUtils.listDirectory(directory, directoryList);
				}));
	}

	/**
	 * <h3 class="en-US">List files of given folder path and filter file name by given file extension name</h3>
	 * <h3 class="zh-CN">读取给定文件夹中指定扩展名的文件列表</h3>
	 *
	 * @param filePath    <span class="en-US">the folder path</span>
	 *                    <span class="zh-CN">文件夹路径</span>
	 * @param fileExtName <span class="en-US">file extension name</span>
	 *                    <span class="zh-CN">文件扩展名</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listExtNameFiles(final String filePath, final String fileExtName)
			throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(fileExtName));
	}

	/**
	 * <h3 class="en-US">List files of given folder path and filter file name by given file extension name</h3>
	 * <h3 class="zh-CN">读取给定文件夹中指定扩展名的文件列表</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param fileExtName        <span class="en-US">file extension name</span>
	 *                           <span class="zh-CN">文件扩展名</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listExtNameFiles(final String filePath, final String fileExtName,
	                                            final boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(fileExtName),
				Boolean.FALSE, Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of given folder path and filter file name by given file extension name</h3>
	 * <h3 class="zh-CN">读取给定文件夹中指定扩展名的文件列表</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param fileExtName        <span class="en-US">file extension name</span>
	 *                           <span class="zh-CN">文件扩展名</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listExtNameFiles(final String filePath, final String fileExtName,
	                                            final boolean readHiddenFiles, final boolean iterateChildFolder)
			throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(fileExtName),
				readHiddenFiles, Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and filter file extension name is "class"</h3>
	 * <h3 class="zh-CN">读取给定文件夹中的".class"文件列表</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listClassesFiles(final String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter("class"));
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance and filter file extension name is "class"</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象中的".class"文件列表</h3>
	 *
	 * @param file <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *             <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 */
	public static List<String> listClassesFiles(final File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter("class"));
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and filter file extension name is "jar"</h3>
	 * <h3 class="zh-CN">读取给定文件夹中的".jar"文件列表</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listJarFiles(final String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(URL_PROTOCOL_JAR));
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance and filter file extension name is "jar"</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象中的".jar"文件列表</h3>
	 *
	 * @param file <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *             <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 */
	public static List<String> listJarFiles(final File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter(URL_PROTOCOL_JAR));
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and filter file extension name is "zip"</h3>
	 * <h3 class="zh-CN">读取给定文件夹中的".zip"文件列表</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listZipFiles(final String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(URL_PROTOCOL_ZIP));
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance and filter file extension name is "zip"</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象中的".zip"文件列表</h3>
	 *
	 * @param file <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *             <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 */
	public static List<String> listZipFiles(final File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter(URL_PROTOCOL_ZIP));
	}

	/**
	 * <h3 class="en-US">List files of the given folder path and filter file extension name is "wsjar"</h3>
	 * <h3 class="zh-CN">读取给定文件夹中的".wsjar"文件列表</h3>
	 *
	 * @param filePath <span class="en-US">the folder path</span>
	 *                 <span class="zh-CN">文件夹路径</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listWebSphereJarFiles(final String filePath) throws FileNotFoundException {
		return FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameExtensionFilter(URL_PROTOCOL_WSJAR));
	}

	/**
	 * <h3 class="en-US">List files of given folder <code>java.io.File</code> instance and filter file extension name is "wsjar"</h3>
	 * <h3 class="zh-CN">读取给定文件夹<code>java.io.File</code>实例对象中的".wsjar"文件列表</h3>
	 *
	 * @param file <span class="en-US">the folder <code>java.io.File</code> instance</span>
	 *             <span class="zh-CN">文件夹<code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US">list of the found file path</span>
	 * <span class="zh-CN">找到的文件路径列表</span>
	 */
	public static List<String> listWebSphereJarFiles(final File file) {
		return FileUtils.listFiles(file, new FilenameExtensionFilter(URL_PROTOCOL_WSJAR));
	}

	/**
	 * <h3 class="en-US">List files of the given folder path, file path filter by given regex string</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath      <span class="en-US">the folder path</span>
	 *                      <span class="zh-CN">文件夹路径</span>
	 * @param fileNameRegex <span class="en-US">file name filter regex string</span>
	 *                      <span class="zh-CN">文件名匹配的正则表达式字符串</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFilesByRegex(final String filePath, final String fileNameRegex)
			throws FileNotFoundException {
		return FileUtils.listFilesByRegex(filePath, fileNameRegex, Boolean.TRUE,
				Boolean.FALSE, Boolean.TRUE);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path, file path filter by given regex string</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param fileNameRegex      <span class="en-US">file name filter regex string</span>
	 *                           <span class="zh-CN">文件名匹配的正则表达式字符串</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFilesByRegex(final String filePath, final String fileNameRegex,
	                                            final boolean iterateChildFolder) throws FileNotFoundException {
		return FileUtils.listFilesByRegex(filePath, fileNameRegex, Boolean.TRUE,
				Boolean.FALSE, iterateChildFolder);
	}

	/**
	 * <h3 class="en-US">List files of the given folder path, file path filter by given regex string</h3>
	 * <h3 class="zh-CN">读取给定文件夹内的文件列表，使用给定的文件名过滤器实例</h3>
	 *
	 * @param filePath           <span class="en-US">the folder path</span>
	 *                           <span class="zh-CN">文件夹路径</span>
	 * @param fileNameRegex      <span class="en-US">file name filter regex string</span>
	 *                           <span class="zh-CN">文件名匹配的正则表达式字符串</span>
	 * @param readHiddenFiles    <span class="en-US">List include hidden files</span>
	 *                           <span class="zh-CN">包含隐藏文件</span>
	 * @param includeRootFolder  <span class="en-US">to include root folder</span>
	 *                           <span class="zh-CN">包含根文件夹路径</span>
	 * @param iterateChildFolder <span class="en-US">to iterate child folder</span>
	 *                           <span class="zh-CN">迭代子文件夹</span>
	 * @return <span class="en-US">list of the child file path</span>
	 * <span class="zh-CN">子文件路径列表</span>
	 * @throws FileNotFoundException <span class="en-US">if the resource cannot be resolved to a file in the file system</span>
	 *                               <span class="zh-CN">如果资源无法解析为文件系统中的文件</span>
	 */
	public static List<String> listFilesByRegex(final String filePath, final String fileNameRegex,
	                                            final boolean readHiddenFiles, final boolean includeRootFolder,
	                                            final boolean iterateChildFolder) throws FileNotFoundException {
		List<String> fileList = new ArrayList<>();
		FileUtils.listFiles(FileUtils.getFile(filePath), new FilenameRegexFilter(fileNameRegex),
				fileList, readHiddenFiles, includeRootFolder, iterateChildFolder);
		return fileList;
	}

	/**
	 * <h3 class="en-US">Write data bytes to the target file path</h3>
	 * <h3 class="zh-CN">写入字节数组到目标文件路径</h3>
	 *
	 * @param fileData <span class="en-US">file content data bytes</span>
	 *                 <span class="zh-CN">文件内容字节数组</span>
	 * @param filePath <span class="en-US">target file path</span>
	 *                 <span class="zh-CN">目标文件路径</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final byte[] fileData, final String filePath) {
		return FileUtils.saveFile(fileData, filePath, new Properties());
	}

	/**
	 * <h3 class="en-US">Write data bytes to the target file path</h3>
	 * <h3 class="zh-CN">写入字节数组到目标文件路径</h3>
	 *
	 * @param fileData   <span class="en-US">file content data bytes</span>
	 *                   <span class="zh-CN">文件内容字节数组</span>
	 * @param filePath   <span class="en-US">target file path</span>
	 *                   <span class="zh-CN">目标文件路径</span>
	 * @param properties <span class="en-US">the properties configure of samba</span>
	 *                   <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final byte[] fileData, final String filePath, final Properties properties) {
		if (StringUtils.isEmpty(filePath)) {
			return Boolean.FALSE;
		}

		if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = new SmbFile(filePath, new BaseContext(new PropertyConfiguration(properties)));
			     OutputStream outputStream = new SmbFileOutputStream(smbFile)) {
				smbFile.mkdirs();
				outputStream.write(fileData);
				outputStream.flush();
				return Boolean.TRUE;
			} catch (Exception e) {
				return Boolean.FALSE;
			}
		} else {
			FileOutputStream fileOutputStream = null;
			try {
				File destFile = FileUtils.getFile(filePath);
				File folder = destFile.getParentFile();
				if (folder.exists() || folder.mkdirs()) {
					fileOutputStream = new FileOutputStream(destFile);
					fileOutputStream.write(fileData);
					fileOutputStream.flush();
					return Boolean.TRUE;
				}
			} catch (IOException e) {
				LOGGER.error("Target_Save_File_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			} finally {
				IOUtils.closeStream(fileOutputStream);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Write data from input stream to the target file path</h3>
	 * <h3 class="zh-CN">从输入流中读取数据并写入到目标文件路径</h3>
	 *
	 * @param inputStream <span class="en-US">input stream instance</span>
	 *                    <span class="zh-CN">输入流实例对象</span>
	 * @param filePath    <span class="en-US">target file path</span>
	 *                    <span class="zh-CN">目标文件路径</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final InputStream inputStream, final String filePath) {
		return FileUtils.saveFile(inputStream, filePath, new Properties());
	}

	/**
	 * <h3 class="en-US">Write data from input stream to the target file path</h3>
	 * <h3 class="zh-CN">从输入流中读取数据并写入到目标文件路径</h3>
	 *
	 * @param inputStream <span class="en-US">input stream instance</span>
	 *                    <span class="zh-CN">输入流实例对象</span>
	 * @param filePath    <span class="en-US">target file path</span>
	 *                    <span class="zh-CN">目标文件路径</span>
	 * @param properties  <span class="en-US">the properties configure of samba</span>
	 *                    <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final InputStream inputStream, final String filePath, final Properties properties) {
		if (StringUtils.isEmpty(filePath)) {
			return Boolean.FALSE;
		}

		OutputStream outputStream = null;
		SmbFile smbFile = null;
		try {
			if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
				smbFile = new SmbFile(filePath, new BaseContext(new PropertyConfiguration(properties)));
				smbFile.mkdirs();
				outputStream = new SmbFileOutputStream(smbFile);
			} else {
				File destFile = FileUtils.getFile(filePath);
				File folder = destFile.getParentFile();
				if (folder.exists() || folder.mkdirs()) {
					outputStream = new FileOutputStream(destFile);
				}
			}
			if (outputStream != null) {
				long copiedLength = IOUtils.copyStream(inputStream, outputStream, Boolean.FALSE);
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Copy_length_File_Debug", copiedLength);
				}
				return Boolean.TRUE;
			}
		} catch (IOException e) {
			LOGGER.error("Target_Save_File_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		} finally {
			IOUtils.closeStream(outputStream);
			if (smbFile != null) {
				smbFile.close();
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Write content to the target file path, use default charset: UTF-8</h3>
	 * <h3 class="zh-CN">写入文件内容到目标文件路径，使用UTF-8编码</h3>
	 *
	 * @param content  <span class="en-US">file content string</span>
	 *                 <span class="zh-CN">文件内容字符串</span>
	 * @param filePath <span class="en-US">target file path</span>
	 *                 <span class="zh-CN">目标文件路径</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final String filePath, final String content) {
		return FileUtils.saveFile(filePath, new Properties(), content, Globals.DEFAULT_ENCODING);
	}

	/**
	 * <h3 class="en-US">Write content to the target file path, use default charset: UTF-8</h3>
	 * <h3 class="zh-CN">写入文件内容到目标文件路径，使用UTF-8编码</h3>
	 *
	 * @param content    <span class="en-US">file content string</span>
	 *                   <span class="zh-CN">文件内容字符串</span>
	 * @param filePath   <span class="en-US">target file path</span>
	 *                   <span class="zh-CN">目标文件路径</span>
	 * @param properties <span class="en-US">the properties configure of samba</span>
	 *                   <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final String filePath, final Properties properties, final String content) {
		return FileUtils.saveFile(filePath, properties, content, Globals.DEFAULT_ENCODING);
	}

	/**
	 * <h3 class="en-US">Write content to the target file path</h3>
	 * <h3 class="zh-CN">写入文件内容到目标文件路径</h3>
	 *
	 * @param content    <span class="en-US">file content string</span>
	 *                   <span class="zh-CN">文件内容字符串</span>
	 * @param filePath   <span class="en-US">target file path</span>
	 *                   <span class="zh-CN">目标文件路径</span>
	 * @param properties <span class="en-US">the properties configure of samba</span>
	 *                   <span class="zh-CN">访问samba的配置信息</span>
	 * @param encoding   <span class="en-US">Charset encoding</span>
	 *                   <span class="zh-CN">字符集编码</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean saveFile(final String filePath, final Properties properties,
	                               final String content, final String encoding) {
		PrintWriter printWriter = null;
		OutputStream outputStream = null;
		OutputStreamWriter outputStreamWriter = null;
		SmbFile smbFile = null;
		try {
			if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
				smbFile = new SmbFile(filePath, new BaseContext(new PropertyConfiguration(properties)));
				outputStream = new SmbFileOutputStream(smbFile);
			} else {
				outputStream = new FileOutputStream(filePath);
			}
			outputStreamWriter = new OutputStreamWriter(outputStream, encoding);
			printWriter = new PrintWriter(outputStreamWriter);

			printWriter.print(content);
			outputStreamWriter.flush();
			return Boolean.TRUE;
		} catch (Exception e) {
			LOGGER.error("Target_Save_File_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		} finally {
			IOUtils.closeStream(printWriter);
			IOUtils.closeStream(outputStreamWriter);
			IOUtils.closeStream(outputStream);
			if (smbFile != null) {
				smbFile.close();
			}
		}
	}

	/**
	 * <h3 class="en-US">Read content from the target file path, use default charset: UTF-8</h3>
	 * <h3 class="zh-CN">从目标文件路径读取文件内容，使用UTF-8编码</h3>
	 *
	 * @param filePath <span class="en-US">target file path</span>
	 *                 <span class="zh-CN">目标文件路径</span>
	 * @return <span class="en-US">File content as string</span>
	 * <span class="zh-CN">文件内容字符串</span>
	 */
	public static String readFile(final String filePath) {
		return FileUtils.readFile(filePath, Globals.DEFAULT_ENCODING);
	}

	/**
	 * <h3 class="en-US">Read content from the target file path</h3>
	 * <h3 class="zh-CN">从目标文件路径读取文件内容</h3>
	 *
	 * @param filePath <span class="en-US">target file path</span>
	 *                 <span class="zh-CN">目标文件路径</span>
	 * @param encoding <span class="en-US">Charset encoding</span>
	 *                 <span class="zh-CN">字符集编码</span>
	 * @return <span class="en-US">File content as string</span>
	 * <span class="zh-CN">文件内容字符串</span>
	 */
	public static String readFile(final String filePath, final String encoding) {
		try {
			return IOUtils.readContent(getURL(filePath).openStream(), encoding);
		} catch (Exception e) {
			return "";
		}
	}

	/**
	 * <h3 class="en-US">Remove the target file</h3>
	 * <h3 class="zh-CN">删除目标文件</h3>
	 *
	 * @param filePath <span class="en-US">target file path</span>
	 *                 <span class="zh-CN">目标文件路径</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean removeFile(final String filePath) {
		try {
			return FileUtils.removeFile(FileUtils.getFile(filePath));
		} catch (FileNotFoundException e) {
			return Boolean.TRUE;
		}
	}

	/**
	 * <h3 class="en-US">Remove the target file</h3>
	 * <h3 class="zh-CN">删除目标文件</h3>
	 *
	 * @param filePath <span class="en-US">target file path</span>
	 *                 <span class="zh-CN">目标文件路径</span>
	 * @param domain   <span class="en-US">Domain name for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName <span class="en-US">Username for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord <span class="en-US">Password for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的密码</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean removeFile(final String filePath, final String domain,
	                                 final String userName, final String passWord) {
		return FileUtils.removeFile(FileUtils.getFile(filePath, smbAuthenticator(domain, userName, passWord)));
	}

	/**
	 * <h3 class="en-US">Remove the target file</h3>
	 * <h3 class="zh-CN">删除目标文件</h3>
	 *
	 * @param file <span class="en-US">the <code>java.io.File</code> instance</span>
	 *             <span class="zh-CN"><code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean removeFile(final File file) {
		if (file == null) {
			return Boolean.TRUE;
		}

		if (file.exists()) {
			if (file.isDirectory()) {
				return FileUtils.removeDir(file);
			} else {
				return file.delete();
			}
		}
		return Boolean.TRUE;
	}

	/**
	 * <h3 class="en-US">Remove the target file</h3>
	 * <h3 class="zh-CN">删除目标文件</h3>
	 *
	 * @param smbFile <span class="en-US">the samba file instance</span>
	 *                <span class="zh-CN">samba文件实例对象</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean removeFile(final SmbFile smbFile) {
		if (smbFile == null) {
			return Boolean.TRUE;
		}

		try {
			if (smbFile.exists()) {
				if (smbFile.isDirectory()) {
					FileUtils.removeDir(smbFile);
				} else {
					smbFile.delete();
				}
			}
			return Boolean.TRUE;
		} catch (Exception e) {
			LOGGER.error("Remove_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Move a file from base path to the target path</h3>
	 * <h3 class="zh-CN">从原文件地址移动到目标文件地址</h3>
	 *
	 * @param originalPath <span class="en-US">Original path</span>
	 *                     <span class="zh-CN">原文件地址</span>
	 * @param targetPath   <span class="en-US">Target path</span>
	 *                     <span class="zh-CN">目标文件地址</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final String targetPath) {
		return FileUtils.moveFile(originalPath, targetPath, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move a file from base path to the target path</h3>
	 * <h3 class="zh-CN">从原文件地址移动到目标文件地址</h3>
	 *
	 * @param originalPath <span class="en-US">Original path</span>
	 *                     <span class="zh-CN">原文件地址</span>
	 * @param targetPath   <span class="en-US">Target path</span>
	 *                     <span class="zh-CN">目标文件地址</span>
	 * @param override     <span class="en-US">Override target if exists</span>
	 *                     <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final String targetPath, final boolean override) {
		return FileUtils.moveFile(originalPath, null, targetPath, null, override);
	}

	/**
	 * <h3 class="en-US">Move a file from samba path to target path</h3>
	 * <h3 class="zh-CN">从原samba文件地址移动到目标文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the cifs context</span>
	 *                        <span class="zh-CN">CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final CIFSContext originalContext, final String targetPath) {
		return FileUtils.moveFile(originalPath, originalContext, targetPath, null, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move a file from samba path to target path</h3>
	 * <h3 class="zh-CN">从原samba文件地址移动到目标文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param override        <span class="en-US">Override target if exists</span>
	 *                        <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final CIFSContext originalContext,
	                               final String targetPath, final boolean override) {
		return FileUtils.moveFile(originalPath, originalContext, targetPath, null, override);
	}

	/**
	 * <h3 class="en-US">Move a file from base path to target samba path</h3>
	 * <h3 class="zh-CN">从原文件地址移动到目标samba文件地址</h3>
	 *
	 * @param originalPath  <span class="en-US">Original path</span>
	 *                      <span class="zh-CN">原文件地址</span>
	 * @param targetPath    <span class="en-US">Target path</span>
	 *                      <span class="zh-CN">目标文件地址</span>
	 * @param targetContext <span class="en-US">the target cifs context</span>
	 *                      <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final String targetPath, final CIFSContext targetContext) {
		return FileUtils.moveFile(originalPath, null, targetPath, targetContext, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move a file from base path to target samba path</h3>
	 * <h3 class="zh-CN">从原文件地址移动到目标samba文件地址</h3>
	 *
	 * @param originalPath  <span class="en-US">Original path</span>
	 *                      <span class="zh-CN">原文件地址</span>
	 * @param targetPath    <span class="en-US">Target path</span>
	 *                      <span class="zh-CN">目标文件地址</span>
	 * @param targetContext <span class="en-US">the target cifs context</span>
	 *                      <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @param override      <span class="en-US">Override target if exists</span>
	 *                      <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final String targetPath,
	                               final CIFSContext targetContext, final boolean override) {
		return FileUtils.moveFile(originalPath, null, targetPath, targetContext, override);
	}

	/**
	 * <h3 class="en-US">Move a file from base samba path to the target samba path</h3>
	 * <h3 class="zh-CN">从原samba文件地址移动到目标samba文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param targetContext   <span class="en-US">the target cifs context</span>
	 *                        <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final CIFSContext originalContext,
	                               final String targetPath, final CIFSContext targetContext) {
		return FileUtils.moveFile(originalPath, originalContext, targetPath, targetContext, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move a file from base samba path to the target samba path</h3>
	 * <h3 class="zh-CN">从原samba文件地址移动到目标samba文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param targetContext   <span class="en-US">the target cifs context</span>
	 *                        <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @param override        <span class="en-US">Override target if exists</span>
	 *                        <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveFile(final String originalPath, final CIFSContext originalContext,
	                               final String targetPath, final CIFSContext targetContext,
	                               boolean override) {
		if (FileUtils.isExists(originalPath) && FileUtils.canRead(originalPath)) {
			if (override || !FileUtils.isExists(targetPath)) {
				try {
					File destFile = FileUtils.getFile(targetPath);
					if (destFile.exists()) {
						if (override && !FileUtils.removeFile(destFile)) {
							return Boolean.FALSE;
						}
					}

					return FileUtils.copy(originalPath, originalContext, targetPath, targetContext, override)
							&& FileUtils.removeFile(originalPath);
				} catch (Exception e) {
					LOGGER.error("Move_Files_Error");
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Stack_Message_Error", e);
					}
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Move directory from samba folder to target folder</h3>
	 * <h3 class="zh-CN">从原samba文件夹地址移动到目标文件夹地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original folder path</span>
	 *                        <span class="zh-CN">原文件夹地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件夹CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final String originalPath, final CIFSContext originalContext,
	                              final String targetPath) {
		return FileUtils.moveDir(originalPath, originalContext, targetPath, null, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move directory from samba folder to target folder</h3>
	 * <h3 class="zh-CN">从原samba文件夹地址移动到目标文件夹地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original folder path</span>
	 *                        <span class="zh-CN">原文件夹地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件夹CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param override        <span class="en-US">Override target if exists</span>
	 *                        <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final String originalPath, final CIFSContext originalContext,
	                              final String targetPath, final boolean override) {
		return FileUtils.moveDir(originalPath, originalContext, targetPath, null, override);
	}

	/**
	 * <h3 class="en-US">Move directory from folder to target samba folder</h3>
	 * <h3 class="zh-CN">从原文件夹地址移动到目标samba文件夹地址</h3>
	 *
	 * @param originalPath  <span class="en-US">Original folder path</span>
	 *                      <span class="zh-CN">原文件夹地址</span>
	 * @param targetPath    <span class="en-US">Target path</span>
	 *                      <span class="zh-CN">目标文件地址</span>
	 * @param targetContext <span class="en-US">the target cifs context</span>
	 *                      <span class="zh-CN">目标文件夹CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final String originalPath, final String targetPath, final CIFSContext targetContext) {
		return FileUtils.moveDir(originalPath, null, targetPath, targetContext, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move directory from folder to target samba folder</h3>
	 * <h3 class="zh-CN">从原文件夹地址移动到目标samba文件夹地址</h3>
	 *
	 * @param originalPath  <span class="en-US">Original folder path</span>
	 *                      <span class="zh-CN">原文件夹地址</span>
	 * @param targetPath    <span class="en-US">Target path</span>
	 *                      <span class="zh-CN">目标文件地址</span>
	 * @param targetContext <span class="en-US">the target cifs context</span>
	 *                      <span class="zh-CN">目标文件夹CIFS上下文配置信息</span>
	 * @param override      <span class="en-US">Override target if exists</span>
	 *                      <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final String originalPath, final String targetPath,
	                              final CIFSContext targetContext, final boolean override) {
		return FileUtils.moveDir(originalPath, null, targetPath, targetContext, override);
	}

	/**
	 * <h3 class="en-US">Move directory from samba folder to target samba folder</h3>
	 * <h3 class="zh-CN">从原samba文件夹地址移动到目标samba文件夹地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original folder path</span>
	 *                        <span class="zh-CN">原文件夹地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件夹CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param targetContext   <span class="en-US">the target cifs context</span>
	 *                        <span class="zh-CN">目标文件夹CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final String originalPath, final CIFSContext originalContext,
	                              final String targetPath, final CIFSContext targetContext) {
		return FileUtils.moveDir(originalPath, originalContext, targetPath, targetContext, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move directory from samba folder to target samba folder</h3>
	 * <h3 class="zh-CN">从原samba文件夹地址移动到目标samba文件夹地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original folder path</span>
	 *                        <span class="zh-CN">原文件夹地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件夹CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param targetContext   <span class="en-US">the target cifs context</span>
	 *                        <span class="zh-CN">目标文件夹CIFS上下文配置信息</span>
	 * @param override        <span class="en-US">Override target if exists</span>
	 *                        <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final String originalPath, final CIFSContext originalContext,
	                              final String targetPath, final CIFSContext targetContext,
	                              final boolean override) {
		if (StringUtils.isEmpty(originalPath) || !FileUtils.isDirectory(originalPath, originalContext)
				|| StringUtils.isEmpty(targetPath)) {
			return Boolean.FALSE;
		}
		if (FileUtils.copy(originalPath, originalContext, targetPath, targetContext, override)) {
			return FileUtils.removeDir(originalPath, originalContext);
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Move directory from samba folder to target samba folder</h3>
	 * <h3 class="zh-CN">从原samba文件夹地址移动到目标samba文件夹地址</h3>
	 *
	 * @param originalFolder <span class="en-US">the folder instance</span>
	 *                       <span class="zh-CN">文件夹实例对象</span>
	 * @param targetPath     <span class="en-US">Target path</span>
	 *                       <span class="zh-CN">目标文件地址</span>
	 * @param properties     <span class="en-US">the properties configure of samba</span>
	 *                       <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final File originalFolder, final String targetPath, final Properties properties) {
		return FileUtils.moveDir(originalFolder, targetPath, properties, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Move directory from samba folder to target samba folder</h3>
	 * <h3 class="zh-CN">从原samba文件夹地址移动到目标samba文件夹地址</h3>
	 *
	 * @param originalFolder <span class="en-US">the folder instance</span>
	 *                       <span class="zh-CN">文件夹实例对象</span>
	 * @param targetPath     <span class="en-US">Target path</span>
	 *                       <span class="zh-CN">目标文件地址</span>
	 * @param properties     <span class="en-US">the properties configure of samba</span>
	 *                       <span class="zh-CN">访问samba的配置信息</span>
	 * @param override       <span class="en-US">Override target if exists</span>
	 *                       <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean moveDir(final File originalFolder, final String targetPath,
	                              final Properties properties, final boolean override) {
		if (originalFolder == null || !originalFolder.exists()) {
			return Boolean.FALSE;
		}
		try {
			FileUtils.makeDir(targetPath, properties);

			boolean error = Boolean.FALSE;
			BasicFileAttributes basicFileAttributes =
					Files.readAttributes(originalFolder.toPath(), BasicFileAttributes.class);
			if (basicFileAttributes.isDirectory()) {
				File[] childFiles = originalFolder.listFiles();
				if (childFiles != null) {
					for (File tempFile : childFiles) {
						String childPath = targetPath + Globals.DEFAULT_PAGE_SEPARATOR + tempFile.getName();
						BasicFileAttributes fileAttributes =
								Files.readAttributes(tempFile.toPath(), BasicFileAttributes.class);
						if (fileAttributes.isDirectory()) {
							error = FileUtils.moveDir(tempFile, childPath, properties, override);
							removeFile(tempFile);
						} else if (fileAttributes.isRegularFile()) {
							error = FileUtils.moveFile(tempFile.getAbsolutePath(), childPath, override);
						}

						if (!error) {
							return Boolean.FALSE;
						}
					}
				}
				return Boolean.TRUE;
			} else if (basicFileAttributes.isRegularFile()) {
				return FileUtils.moveFile(originalFolder.getAbsolutePath(),
						targetPath + Globals.DEFAULT_PAGE_SEPARATOR + originalFolder.getName(), override);
			} else {
				return Boolean.FALSE;
			}
		} catch (Exception e) {
			LOGGER.error("Move_Directory_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Create directory</h3>
	 * <h3 class="zh-CN">创建文件夹</h3>
	 *
	 * @param targetPath <span class="en-US">Target path</span>
	 *                   <span class="zh-CN">目标文件夹地址</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean makeDir(final String targetPath) {
		return FileUtils.makeDir(targetPath, new Properties());
	}

	/**
	 * <h3 class="en-US">Makes a directory</h3>
	 * <h3 class="zh-CN">创建文件夹</h3>
	 *
	 * @param targetPath <span class="en-US">Target path</span>
	 *                   <span class="zh-CN">目标文件夹地址</span>
	 * @param properties <span class="en-US">the properties configure of samba</span>
	 *                   <span class="zh-CN">访问samba的配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean makeDir(final String targetPath, final Properties properties) {
		if (FileUtils.isExists(targetPath)) {
			return Boolean.TRUE;
		}

		if (targetPath.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = new SmbFile(targetPath,
					new BaseContext(new PropertyConfiguration(properties == null ? new Properties() : properties)))) {
				smbFile.mkdirs();
				return Boolean.TRUE;
			} catch (Exception e) {
				LOGGER.error("Create_Directory_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
				return Boolean.FALSE;
			}
		} else {
			try {
				File destDir = FileUtils.getFile(targetPath);
				return destDir.mkdirs();
			} catch (FileNotFoundException e) {
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * <h3 class="en-US">Makes a directory, including any necessary but nonexistent parent directories.</h3>
	 * <span class="en-US">
	 * If a file already exists with a specified name, but it is
	 * not a directory, then an IOException is thrown.
	 * If the directory cannot be created (or the file already exists but is not a directory)
	 * then an IOException is thrown.
	 * </span>
	 * <h3 class="zh-CN">创建一个目录，包括任何必要但不存在的父目录。</h3>
	 * <span class="zh-CN">
	 * 如果具有指定名称的文件已存在，但它不是目录，则抛出 IOException。如果无法创建目录（或者文件已存在但不是目录），则抛出 IOException。
	 * </span>
	 *
	 * @param directory <span class="en-US">directory to create, must not be {@code null}</span>
	 *                  <span class="zh-CN">要创建的目录，不为 {@code null}</span>
	 * @throws IOException <span class="en-US">if the directory cannot be created or the file already exists but is not a directory</span>
	 *                     <span class="zh-CN">如果无法创建目录或文件已存在但不是目录</span>
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
	 * <h3 class="en-US">Makes any necessary but nonexistent parent directories for a given File.</h3>
	 * <span class="en-US">If the parent directory cannot be created, then an IOException is thrown.</span>
	 * <h3 class="zh-CN">为给定文件创建任何必要但不存在的父目录。</h3>
	 * <span class="zh-CN">如果无法创建父目录，则会抛出 IOException。</span>
	 *
	 * @param file <span class="en-US">file with parent to create</span>
	 *             <span class="zh-CN">要创建父文件夹的实例对象</span>
	 * @throws IOException <span class="en-US">if the directory cannot be created or the file already exists but is not a directory</span>
	 *                     <span class="zh-CN">如果无法创建目录或文件已存在但不是目录</span>
	 */
	public static void forceMakeParent(final File file) throws IOException {
		if (file == null) {
			return;
		}
		FileUtils.forceMakeDir(file.getParentFile());
	}

	/**
	 * <h3 class="en-US">Copy a file from base path to the target path</h3>
	 * <h3 class="zh-CN">从原文件地址复制到目标文件地址</h3>
	 *
	 * @param originalPath <span class="en-US">Original path</span>
	 *                     <span class="zh-CN">原文件地址</span>
	 * @param targetPath   <span class="en-US">Target path</span>
	 *                     <span class="zh-CN">目标文件地址</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final String targetPath) {
		return FileUtils.copy(originalPath, null, targetPath, null, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Copy a file from base path to the target path</h3>
	 * <h3 class="zh-CN">从原文件地址复制到目标文件地址</h3>
	 *
	 * @param originalPath <span class="en-US">Original path</span>
	 *                     <span class="zh-CN">原文件地址</span>
	 * @param targetPath   <span class="en-US">Target path</span>
	 *                     <span class="zh-CN">目标文件地址</span>
	 * @param override     <span class="en-US">Override target if exists</span>
	 *                     <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final String targetPath, final boolean override) {
		return FileUtils.copy(originalPath, null, targetPath, null, override);
	}

	/**
	 * <h3 class="en-US">Copy file from base path to target samba path</h3>
	 * <h3 class="zh-CN">从原文件地址复制到目标samba文件地址</h3>
	 *
	 * @param originalPath  <span class="en-US">Original path</span>
	 *                      <span class="zh-CN">原文件地址</span>
	 * @param targetPath    <span class="en-US">Target path</span>
	 *                      <span class="zh-CN">目标文件地址</span>
	 * @param targetContext <span class="en-US">the target cifs context</span>
	 *                      <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final String targetPath, final CIFSContext targetContext) {
		return FileUtils.copy(originalPath, null, targetPath, targetContext, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Copy file from base path to target samba path</h3>
	 * <h3 class="zh-CN">从原文件地址复制到目标samba文件地址</h3>
	 *
	 * @param originalPath  <span class="en-US">Original path</span>
	 *                      <span class="zh-CN">原文件地址</span>
	 * @param targetPath    <span class="en-US">Target path</span>
	 *                      <span class="zh-CN">目标文件地址</span>
	 * @param targetContext <span class="en-US">the target cifs context</span>
	 *                      <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @param override      <span class="en-US">Override target if exists</span>
	 *                      <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final String targetPath,
	                           final CIFSContext targetContext, final boolean override) {
		return FileUtils.copy(originalPath, null, targetPath, targetContext, override);
	}

	/**
	 * <h3 class="en-US">Copy file from samba path to the target path</h3>
	 * <h3 class="zh-CN">从原samba文件地址复制到目标文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the cifs context</span>
	 *                        <span class="zh-CN">CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final CIFSContext originalContext, final String targetPath) {
		return FileUtils.copy(originalPath, originalContext, targetPath, null, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Copy file from samba path to the target path</h3>
	 * <h3 class="zh-CN">从原samba文件地址复制到目标文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param override        <span class="en-US">Override target if exists</span>
	 *                        <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final CIFSContext originalContext,
	                           final String targetPath, final boolean override) {
		return FileUtils.copy(originalPath, originalContext, targetPath, null, override);
	}

	/**
	 * <h3 class="en-US">Copy file from the base samba path to the target samba path</h3>
	 * <h3 class="zh-CN">从原samba文件地址复制到目标samba文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param targetContext   <span class="en-US">the target cifs context</span>
	 *                        <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final CIFSContext originalContext,
	                           final String targetPath, final CIFSContext targetContext) {
		return FileUtils.copy(originalPath, originalContext, targetPath, targetContext, Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Copy file from the base samba path to the target samba path</h3>
	 * <h3 class="zh-CN">从原samba文件地址复制到目标samba文件地址</h3>
	 *
	 * @param originalPath    <span class="en-US">Original path</span>
	 *                        <span class="zh-CN">原文件地址</span>
	 * @param originalContext <span class="en-US">the original cifs context</span>
	 *                        <span class="zh-CN">原文件CIFS上下文配置信息</span>
	 * @param targetPath      <span class="en-US">Target path</span>
	 *                        <span class="zh-CN">目标文件地址</span>
	 * @param targetContext   <span class="en-US">the target cifs context</span>
	 *                        <span class="zh-CN">目标文件CIFS上下文配置信息</span>
	 * @param override        <span class="en-US">Override target if exists</span>
	 *                        <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean copy(final String originalPath, final CIFSContext originalContext,
	                           final String targetPath, final CIFSContext targetContext,
	                           final boolean override) {
		if (StringUtils.isEmpty(originalPath) || StringUtils.isEmpty(targetPath)) {
			return Boolean.FALSE;
		}

		Object original = null;
		Object target = null;

		try {
			boolean directory;
			if (originalPath.startsWith(Globals.SAMBA_PROTOCOL)) {
				original = FileUtils.getFile(originalPath, originalContext);
				if (original == null) {
					return Boolean.FALSE;
				}
				directory = ((SmbFile) original).isDirectory();
			} else {
				original = FileUtils.getFile(originalPath);
				directory = ((File) original).isDirectory();
			}
			if (targetPath.startsWith(Globals.SAMBA_PROTOCOL)) {
				target = FileUtils.getFile(targetPath, targetContext);
			} else {
				target = FileUtils.getFile(targetPath);
			}
			if (directory) {
				return FileUtils.processDirectory(original, target, override);
			} else {
				return FileUtils.processFile(original, target, override);
			}
		} catch (Exception e) {
			LOGGER.error("Copy_Directory_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		} finally {
			if (original instanceof SmbFile) {
				((SmbFile) original).close();
			}
			if (target instanceof SmbFile) {
				((SmbFile) target).close();
			}
		}
	}

	/**
	 * <h3 class="en-US">Remove target directory</h3>
	 * <h3 class="zh-CN">删除目标文件夹</h3>
	 *
	 * @param directoryPath <span class="en-US">target directory path</span>
	 *                      <span class="zh-CN">目标文件夹路径</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean removeDir(final String directoryPath) {
		return FileUtils.removeDir(directoryPath, null);
	}

	/**
	 * <h3 class="en-US">Remove target directory</h3>
	 * <h3 class="zh-CN">删除目标文件夹</h3>
	 *
	 * @param directoryPath <span class="en-US">target directory path</span>
	 *                      <span class="zh-CN">目标文件夹路径</span>
	 * @param cifsContext   <span class="en-US">the cifs context</span>
	 *                      <span class="zh-CN">文件夹CIFS上下文配置信息</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	public static boolean removeDir(final String directoryPath, final CIFSContext cifsContext) {
		if (directoryPath.startsWith(Globals.SAMBA_PROTOCOL)) {
			return FileUtils.removeDir(FileUtils.getFile(directoryPath, cifsContext));
		} else {
			try {
				return FileUtils.removeDir(FileUtils.getFile(directoryPath));
			} catch (Exception e) {
				LOGGER.error("Remove_Directory_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * <h3 class="en-US">Calculate CRC value of the given file path</h3>
	 * <h3 class="zh-CN">计算目标文件的CRC值</h3>
	 *
	 * @param filePath <span class="en-US">file path</span>
	 *                 <span class="zh-CN">文件地址</span>
	 * @return <span class="en-US">CRC value</span>
	 * <span class="zh-CN">CRC值</span>
	 */
	public static long calcFileCRC(final String filePath) {
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
			LOGGER.error("CRC_Calculate_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
		}

		return Globals.DEFAULT_VALUE_LONG;
	}

	/**
	 * <h3 class="en-US">Check file path is a directory</h3>
	 * <h3 class="zh-CN">检查文件路径是文件夹</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String to check</span>
	 *                         <span class="zh-CN">要检查的位置字符串</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isDirectory(final String resourceLocation) {
		return FileUtils.isDirectory(resourceLocation, null);
	}

	/**
	 * <h3 class="en-US">Check file path is a directory</h3>
	 * <h3 class="zh-CN">检查文件路径是文件夹</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String to check</span>
	 *                         <span class="zh-CN">要检查的位置字符串</span>
	 * @param cifsContext      <span class="en-US">the cifs context</span>
	 *                         <span class="zh-CN">文件夹CIFS上下文配置信息</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isDirectory(final String resourceLocation, final CIFSContext cifsContext) {
		if (StringUtils.isEmpty(resourceLocation)) {
			return Boolean.FALSE;
		}

		if (resourceLocation.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = new SmbFile(resourceLocation, cifsContext)) {
				return smbFile.isDirectory();
			} catch (Exception e) {
				return Boolean.FALSE;
			}
		} else {
			try {
				File directory = FileUtils.getFile(resourceLocation);
				return (directory.exists() && directory.isDirectory());
			} catch (Exception e) {
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * <h3 class="en-US">Check the current file is existed</h3>
	 * <h3 class="zh-CN">检查当前文件是否存在</h3>
	 *
	 * @param filePath <span class="en-US">Current file path</span>
	 *                 <span class="zh-CN">当前文件地址</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isExists(final String filePath) {
		return isExists(filePath, null);
	}

	/**
	 * <h3 class="en-US">Check the current file is existed</h3>
	 * <h3 class="zh-CN">检查当前文件是否存在</h3>
	 *
	 * @param filePath      <span class="en-US">Current file path</span>
	 *                      <span class="zh-CN">当前文件地址</span>
	 * @param authenticator <span class="en-US">Client authenticator instance</span>
	 *                      <span class="zh-CN">客户端身份验证器实例对象</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isExists(final String filePath, final NtlmPasswordAuthenticator authenticator) {
		return FileUtils.isExists(filePath, null, authenticator);
	}

	/**
	 * <h3 class="en-US">Check the current file is existed</h3>
	 * <h3 class="zh-CN">检查当前文件是否存在</h3>
	 *
	 * @param filePath      <span class="en-US">Current file path</span>
	 *                      <span class="zh-CN">当前文件地址</span>
	 * @param properties    <span class="en-US">the properties configure of samba</span>
	 *                      <span class="zh-CN">访问samba的配置信息</span>
	 * @param authenticator <span class="en-US">Client authenticator instance</span>
	 *                      <span class="zh-CN">客户端身份验证器实例对象</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isExists(final String filePath, final Properties properties,
	                               final NtlmPasswordAuthenticator authenticator) {
		if (StringUtils.isEmpty(filePath)) {
			return Boolean.FALSE;
		}

		if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = new SmbFile(filePath, generateContext(properties, authenticator))) {
				return smbFile.exists();
			} catch (Exception e) {
				return Boolean.FALSE;
			}
		} else {
			try {
				File file = FileUtils.getFile(filePath);
				return file.exists();
			} catch (FileNotFoundException e) {
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * <h3 class="en-US">Read data length of the given entry path in the given file path</h3>
	 * <h3 class="zh-CN">读取给定压缩文件中资源路径的数据长度</h3>
	 *
	 * @param filePath  <span class="en-US">the file path</span>
	 *                  <span class="zh-CN">给定文件路径</span>
	 * @param entryPath <span class="en-US">the entry path</span>
	 *                  <span class="zh-CN">条目资源路径</span>
	 * @return <span class="en-US">Read entry length</span>
	 * <span class="zh-CN">读取的资源路径的数据长度</span>
	 */
	public static int readEntryLength(final String filePath, final String entryPath) {
		InputStream inputStream = null;
		JarFile jarFile = null;
		try {
			if (filePath.endsWith(URL_PROTOCOL_JAR)) {
				jarFile = new JarFile(getFile(filePath));
				JarEntry packageEntry = jarFile.getJarEntry(entryPath);

				if (packageEntry != null) {
					inputStream = jarFile.getInputStream(jarFile.getJarEntry(entryPath));
					return inputStream.available();
				}
			} else if (filePath.endsWith(URL_PROTOCOL_ZIP)) {
				ZipFile zipFile = ZipFile.openZipFile(filePath);
				return zipFile.readEntryLength(entryPath);
			}
		} catch (Exception e) {
			LOGGER.error("Entry_Length_Load_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		} finally {
			IOUtils.closeStream(inputStream);
			IOUtils.closeStream(jarFile);
		}
		return Globals.DEFAULT_VALUE_INT;
	}

	/**
	 * <h3 class="en-US">Check existed of the given entry path in the given file path</h3>
	 * <h3 class="zh-CN">检查给定压缩文件中资源路径是否存在</h3>
	 *
	 * @param filePath  <span class="en-US">the file path</span>
	 *                  <span class="zh-CN">给定文件路径</span>
	 * @param entryPath <span class="en-US">the entry path</span>
	 *                  <span class="zh-CN">条目资源路径</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isEntryExists(final String filePath, final String entryPath) throws ZipException {
		if (StringUtils.isEmpty(filePath) || StringUtils.isEmpty(entryPath)) {
			return Boolean.FALSE;
		}

		if (filePath.toLowerCase().endsWith(URL_PROTOCOL_JAR)) {
			JarFile jarFile = null;
			try {
				jarFile = new JarFile(getFile(filePath));
				return jarFile.getJarEntry(entryPath) != null;
			} catch (Exception e) {
				LOGGER.error("Entry_Content_Load_Error");
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			} finally {
				if (jarFile != null) {
					try {
						jarFile.close();
					} catch (Exception e) {
						LOGGER.error("Archive_Close_File_Error");
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug("Stack_Message_Error", e);
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
	 * <h3 class="en-US">Open input stream of the given entry path in given file object instance</h3>
	 * <h3 class="zh-CN">打开给定压缩文件实例对象中资源路径的输入流</h3>
	 *
	 * @param fileObject <span class="en-US">the file object</span>
	 *                   <span class="zh-CN">文件实例对象</span>
	 * @param entryPath  <span class="en-US">the entry path</span>
	 *                   <span class="zh-CN">条目资源路径</span>
	 * @return <span class="en-US">input stream instance</span>
	 * <span class="zh-CN">输入流实例对象</span>
	 * @throws IOException <span class="en-US">when opening input stream error</span>
	 *                     <span class="zh-CN">打开输入流时出错</span>
	 */
	public static InputStream openInputStream(final Object fileObject, final String entryPath) throws IOException, ZipException {
		if (fileObject == null || StringUtils.isEmpty(entryPath)) {
			return null;
		}

		if (fileObject instanceof JarFile) {
			JarEntry jarEntry = ((JarFile) fileObject).getJarEntry(entryPath);
			if (jarEntry != null) {
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
	 * <h3 class="en-US">Check the current file can read</h3>
	 * <h3 class="zh-CN">检查当前文件是否可以读取</h3>
	 *
	 * @param filePath <span class="en-US">the file path to check</span>
	 *                 <span class="zh-CN">要检查的路径地址</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean canRead(final String filePath) {
		return canRead(filePath, null, null, null);
	}

	/**
	 * <h3 class="en-US">Check the current file can read</h3>
	 * <h3 class="zh-CN">检查当前文件是否可以读取</h3>
	 *
	 * @param filePath <span class="en-US">the file path to check</span>
	 *                 <span class="zh-CN">要检查的路径地址</span>
	 * @param domain   <span class="en-US">Domain name for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName <span class="en-US">Username for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord <span class="en-US">Password for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的密码</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean canRead(final String filePath, final String domain,
	                              final String userName, final String passWord) {
		if (StringUtils.isEmpty(filePath)) {
			return Boolean.FALSE;
		}

		if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = getFile(filePath, smbAuthenticator(domain, userName, passWord))) {
				return smbFile != null && smbFile.canRead();
			} catch (Exception e) {
				return Boolean.FALSE;
			}
		} else {
			try {
				File file = FileUtils.getFile(filePath);
				return file.canRead();
			} catch (FileNotFoundException e) {
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * <h3 class="en-US">Check the current file can write</h3>
	 * <h3 class="zh-CN">检查当前文件是否可以写入</h3>
	 *
	 * @param filePath <span class="en-US">the file path to check</span>
	 *                 <span class="zh-CN">要检查的路径地址</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean canWrite(String filePath) {
		return canWrite(filePath, null, null, null);
	}

	/**
	 * <h3 class="en-US">Check the current file can write</h3>
	 * <h3 class="zh-CN">检查当前文件是否可以写入</h3>
	 *
	 * @param filePath <span class="en-US">the file path to check</span>
	 *                 <span class="zh-CN">要检查的路径地址</span>
	 * @param domain   <span class="en-US">Domain name for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName <span class="en-US">Username for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord <span class="en-US">Password for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的密码</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean canWrite(String filePath, String domain, String userName, String passWord) {
		if (StringUtils.isEmpty(filePath)) {
			return Boolean.FALSE;
		}

		if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
			try (SmbFile smbFile = getFile(filePath, smbAuthenticator(domain, userName, passWord))) {
				return smbFile == null || !smbFile.exists() || smbFile.canWrite();
			} catch (Exception e) {
				return Boolean.FALSE;
			}
		} else {
			try {
				File file = FileUtils.getFile(filePath);
				return file.canWrite();
			} catch (FileNotFoundException e) {
				return Boolean.FALSE;
			}
		}
	}

	/**
	 * <h3 class="en-US">Check the current file can execute</h3>
	 * <h3 class="zh-CN">检查当前文件是否可以执行</h3>
	 *
	 * @param filePath <span class="en-US">the file path to check</span>
	 *                 <span class="zh-CN">要检查的路径地址</span>
	 * @return <span class="en-US">Check result</span>
	 * <span class="zh-CN">检查结果</span>
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
	 * <h3 class="en-US">Merge segment file data and save to the target path</h3>
	 * <h3 class="zh-CN">合并分割的文件并保存到目标路径</h3>
	 *
	 * @param savePath         <span class="en-US">target file path</span>
	 *                         <span class="zh-CN">目标文件路径</span>
	 * @param segmentationInfo <span class="en-US">Segment Data Information instance</span>
	 *                         <span class="zh-CN">分割数据信息定义实例对象</span>
	 * @return <span class="en-US">Process result</span>
	 * <span class="zh-CN">处理结果</span>
	 */
	public static boolean mergeFile(final String savePath, final SegmentationInfo segmentationInfo) {
		try (RandomAccessFile randomAccessFile = new RandomAccessFile(savePath, "rw")) {
			String extName = StringUtils.getFilenameExtension(savePath);
			if (extName.isEmpty()) {
				extName = Globals.DEFAULT_VALUE_STRING;
			}
			if (!segmentationInfo.getExtName().equalsIgnoreCase(extName)) {
				LOGGER.warn("Not_Match_Ext_Name_Files_Warn");
			}
			long totalSize = 0;
			randomAccessFile.setLength(segmentationInfo.getTotalSize());

			for (SegmentationBlock segmentationBlock : segmentationInfo.getBlockList()) {
				if (segmentationBlock == null) {
					return Boolean.FALSE;
				}

				if (FileUtils.mergeFile(randomAccessFile, segmentationBlock)) {
					totalSize += segmentationBlock.getBlockSize();
				}
			}

			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Size_Write_Files_Debug", totalSize);
			}

			if (totalSize != segmentationInfo.getTotalSize()) {
				FileUtils.removeFile(savePath);
				return Boolean.FALSE;
			}
			return Boolean.TRUE;
		} catch (Exception e) {
			LOGGER.error("Merge_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Segment file data by given target path</h3>
	 * <h3 class="zh-CN">将目标路径的文件分割处理</h3>
	 *
	 * @param filePath  <span class="en-US">target file path</span>
	 *                  <span class="zh-CN">目标文件路径</span>
	 * @param blockSize <span class="en-US">Segment block size</span>
	 *                  <span class="zh-CN">分割块大小</span>
	 * @return <span class="en-US">Segment Data Information instance</span>
	 * <span class="zh-CN">分割数据信息定义实例对象</span>
	 */
	public static SegmentationInfo segmentFile(final String filePath, final int blockSize) {
		return segmentFile(filePath, blockSize, null, null, null);
	}

	/**
	 * <h3 class="en-US">Segment file data by given target path</h3>
	 * <h3 class="zh-CN">将目标路径的文件分割处理</h3>
	 *
	 * @param filePath  <span class="en-US">target file path</span>
	 *                  <span class="zh-CN">目标文件路径</span>
	 * @param blockSize <span class="en-US">Segment block size</span>
	 *                  <span class="zh-CN">分割块大小</span>
	 * @param domain    <span class="en-US">Domain name for NAS file</span>
	 *                  <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName  <span class="en-US">Username for NAS file</span>
	 *                  <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord  <span class="en-US">Password for NAS file</span>
	 *                  <span class="zh-CN">NAS文件的密码</span>
	 * @return <span class="en-US">Segment Data Information instance</span>
	 * <span class="zh-CN">分割数据信息定义实例对象</span>
	 */
	public static SegmentationInfo segmentFile(final String filePath, final int blockSize,
	                                           final String domain, final String userName, final String passWord) {
		if (!FileUtils.isExists(filePath, smbAuthenticator(domain, userName, passWord))) {
			return null;
		}

		List<SegmentationBlock> segmentationBlockList = new ArrayList<>();
		InputStream fileInputStream = null;
		ByteArrayOutputStream byteArrayOutputStream;

		try {
			String extName = StringUtils.getFilenameExtension(filePath);
			if (extName.isEmpty()) {
				extName = Globals.DEFAULT_VALUE_STRING;
			} else {
				extName = extName.toLowerCase();
			}
			Object fileObject;
			if (filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
				fileObject = new SmbFile(filePath, generateContext(smbAuthenticator(domain, userName, passWord)));
				fileInputStream = new SmbFileInputStream((SmbFile) fileObject);
			} else {
				fileObject = getFile(filePath);
				fileInputStream = new FileInputStream((File) fileObject);
			}
			long fileSize = fileSize(fileObject);

			byte[] readBuffer = new byte[blockSize];
			int index = 0;
			int readLength;
			while ((readLength = fileInputStream.read(readBuffer)) != -1) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Read_Block_Files_Debug", index, readLength);
				}
				byteArrayOutputStream = new ByteArrayOutputStream(blockSize);
				byteArrayOutputStream.write(readBuffer, 0, readLength);
				SegmentationBlock segmentationBlock =
						new SegmentationBlock((long) index * blockSize, byteArrayOutputStream.toByteArray());
				segmentationBlockList.add(segmentationBlock);
				index++;
			}

			return new SegmentationInfo(extName, fileSize, blockSize,
					ConvertUtils.toHex(SecurityUtils.SHA256(fileObject)), segmentationBlockList);
		} catch (FileNotFoundException e) {
			LOGGER.error("Not_Found_File_Error", filePath);
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		} catch (IOException e) {
			LOGGER.error("Read_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		} finally {
			IOUtils.closeStream(fileInputStream);
		}

		return null;
	}

	/**
	 * <h3 class="en-US">Generate CIFSContext instance.</h3>
	 * <h3 class="zh-CN">生成 CIFSContext 实例。</h3>
	 *
	 * @param authenticator <span class="en-US">Client authenticator instance</span>
	 *                      <span class="zh-CN">客户端身份验证器实例对象</span>
	 * @return <span class="en-US">Generated instance</span>
	 * <span class="zh-CN">生成的实例对象</span>
	 * @throws CIFSException <span class="en-US">If CIFS properties has error</span>
	 *                       <span class="zh-CN">如果CIFS属性信息出现错误</span>
	 */
	public static CIFSContext generateContext(final NtlmPasswordAuthenticator authenticator)
			throws CIFSException {
		return FileUtils.generateContext(null, authenticator);
	}

	/**
	 * <h3 class="en-US">Generate CIFSContext instance.</h3>
	 * <h3 class="zh-CN">生成 CIFSContext 实例。</h3>
	 *
	 * @param properties    <span class="en-US">the properties configure of samba</span>
	 *                      <span class="zh-CN">访问samba的配置信息</span>
	 * @param authenticator <span class="en-US">Client authenticator instance</span>
	 *                      <span class="zh-CN">客户端身份验证器实例对象</span>
	 * @return <span class="en-US">Generated instance</span>
	 * <span class="zh-CN">生成的实例对象</span>
	 * @throws CIFSException <span class="en-US">If CIFS properties has error</span>
	 *                       <span class="zh-CN">如果CIFS属性信息出现错误</span>
	 */
	public static CIFSContext generateContext(final Properties properties,
	                                          final NtlmPasswordAuthenticator authenticator)
			throws CIFSException {
		CIFSContext cifsContext =
				new BaseContext(new PropertyConfiguration(properties == null ? new Properties() : properties));
		if (authenticator != null) {
			cifsContext = cifsContext.withCredentials(authenticator);
		}
		return cifsContext;
	}

	/**
	 * <h3 class="en-US">Generate samba authenticator instance</h3>
	 * <h3 class="zh-CN">生成samba身份验证器</h3>
	 *
	 * @param domain   <span class="en-US">Domain name for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName <span class="en-US">Username for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord <span class="en-US">Password for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的密码</span>
	 * @return <span class="en-US">authenticator instance</span>
	 * <span class="zh-CN">身份验证器实例对象</span>
	 */
	public static NtlmPasswordAuthenticator smbAuthenticator(final String domain, final String userName,
	                                                         final String passWord) {
		return new NtlmPasswordAuthenticator(domain, userName, passWord);
	}

	/**
	 * <h3 class="en-US">Resolve the given resource location to a <code>jcifs.smb.SmbFile</code></h3>
	 * <h3 class="zh-CN">将给定资源位置解析为 <code>jcifs.smb.SmbFile</code></h3>
	 *
	 * @param smbLocation <span class="en-US">the samba file location</span>
	 *                    <span class="zh-CN">samba文件位置</span>
	 * @param cifsContext <span class="en-US">the cifs context</span>
	 *                    <span class="zh-CN">CIFS上下文配置信息</span>
	 * @return <span class="en-US">a corresponding <code>jcifs.smb.SmbFile</code> object or <code>null</code> if an error occurs</span>
	 * <span class="zh-CN">对应的<code>jcifs.smb.SmbFile</code>对象，如果出现异常则返回<code>null</code></span>
	 */
	private static SmbFile getFile(final String smbLocation, final CIFSContext cifsContext) {
		if (StringUtils.isEmpty(smbLocation)) {
			return null;
		}
		try {
			return new SmbFile(smbLocation, cifsContext);
		} catch (Exception e) {
			return null;
		}
	}

	/**
	 * <h3 class="en-US">Remove target directory</h3>
	 * <h3 class="zh-CN">删除目标文件夹</h3>
	 *
	 * @param directory <span class="en-US">the <code>java.io.File</code> instance</span>
	 *                  <span class="zh-CN"><code>java.io.File</code>实例对象</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	private static boolean removeDir(final Object directory) {
		if (directory == null) {
			return Boolean.FALSE;
		}

		try {
			final boolean smbFile;
			final CIFSContext cifsContext;
			final String basePath;
			String[] fileList;
			if (directory instanceof SmbFile) {
				fileList = ((SmbFile) directory).list();
				smbFile = Boolean.TRUE;
				cifsContext = ((SmbFile) directory).getContext();
				basePath = ((SmbFile) directory).getPath();
			} else {
				fileList = ((File) directory).list();
				smbFile = Boolean.FALSE;
				cifsContext = null;
				basePath = ((File) directory).getAbsolutePath();
			}
			if (fileList != null) {
				for (String filePath : fileList) {
					Object childFile;
					boolean isDirectory;
					if (smbFile) {
						childFile = new SmbFile(basePath + "/" + filePath, cifsContext);
						isDirectory = ((SmbFile) childFile).isDirectory();
					} else {
						childFile = new File(basePath, filePath);
						isDirectory = ((File) childFile).isDirectory();
					}
					if (isDirectory) {
						if (!FileUtils.removeDir(childFile)) {
							return Boolean.FALSE;
						}
					} else {
						if (smbFile) {
							((SmbFile) childFile).delete();
						} else {
							if (!((File) childFile).delete()) {
								return Boolean.FALSE;
							}
						}
					}
				}
			}
			if (directory instanceof SmbFile) {
				((SmbFile) directory).delete();
				return Boolean.TRUE;
			} else {
				return ((File) directory).delete();
			}
		} catch (Exception e) {
			LOGGER.error("Remove_Directory_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Replace page separator to "|"</h3>
	 * <h3 class="zh-CN">将页面分隔符替换为“|”</h3>
	 *
	 * @param path <span class="en-US">file path</span>
	 *             <span class="zh-CN">文件路径</span>
	 * @return <span class="en-US">replaced the file path</span>
	 * <span class="zh-CN">替换后的文件路径</span>
	 */
	private static String replacePageSeparator(String path) {
		String replacePath = StringUtils.replace(path, Globals.DEFAULT_PAGE_SEPARATOR, "|");
		replacePath = StringUtils.replace(replacePath, Globals.DEFAULT_ZIP_PAGE_SEPARATOR, "|");
		replacePath = StringUtils.replace(replacePath, Globals.DEFAULT_JAR_PAGE_SEPARATOR, "|");
		if (replacePath.endsWith("|")) {
			replacePath = replacePath.substring(0, replacePath.length() - 1);
		}
		return replacePath;
	}

	/**
	 * <h3 class="en-US">Write segment block data and save to random access file instance</h3>
	 * <h3 class="zh-CN">将分块数据写入目标文件</h3>
	 *
	 * @param randomAccessFile  <span class="en-US">target file path</span>
	 *                          <span class="zh-CN">目标文件路径</span>
	 * @param segmentationBlock <span class="en-US">Segment Data Block</span>
	 *                          <span class="zh-CN">分块数据文件</span>
	 * @return <span class="en-US">Process result</span>
	 * <span class="zh-CN">处理结果</span>
	 */
	private static boolean mergeFile(final RandomAccessFile randomAccessFile,
	                                 final SegmentationBlock segmentationBlock) throws IOException {
		if (segmentationBlock == null || !segmentationBlock.securityCheck()) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Invalid_Block_Segment_Error");
			}
			return Boolean.FALSE;
		}

		randomAccessFile.seek(segmentationBlock.getPosition());
		randomAccessFile.write(StringUtils.base64Decode(segmentationBlock.getDataInfo()));
		return Boolean.TRUE;
	}

	/**
	 * <h2 class="en-US">Implements class for FileFilter by check path using regex string</h2>
	 * <h2 class="zh-CN">使用正则表达式匹配路径的FileFilter实现类</h2>
	 */
	private static final class FilenameRegexFilter implements FilenameFilter {
		/**
		 * <span class="en-US">Regex string</span>
		 * <span class="zh-CN">正则表达式</span>
		 */
		private final String fileNameRegex;

		/**
		 * <h3 class="en-US">Constructor for FilenameRegexFilter</h3>
		 * <h3 class="zh-CN">正则表达式匹配路径过滤器的构造方法</h3>
		 *
		 * @param fileNameRegex <span class="en-US">Regex string</span>
		 *                      <span class="zh-CN">正则表达式</span>
		 */
		public FilenameRegexFilter(String fileNameRegex) {
			this.fileNameRegex = fileNameRegex;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see FileFilter#accept(File)
		 */
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
	 * <h2 class="en-US">Implements class for FileFilter by check file extension name</h2>
	 * <h2 class="zh-CN">检查文件扩展名的FileFilter实现类</h2>
	 */
	private static final class FilenameExtensionFilter implements FilenameFilter {
		/**
		 * <span class="en-US">Matched extension name</span>
		 * <span class="zh-CN">检查的扩展名</span>
		 */
		private final String fileExtName;

		/**
		 * <h3 class="en-US">Constructor for FilenameExtensionFilter</h3>
		 * <h3 class="zh-CN">文件扩展名过滤器的构造方法</h3>
		 *
		 * @param fileExtName <span class="en-US">Matched extension name</span>
		 *                    <span class="zh-CN">检查的扩展名</span>
		 */
		public FilenameExtensionFilter(String fileExtName) {
			this.fileExtName = fileExtName;
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see FileFilter#accept(File)
		 */
		public boolean accept(File dir, String name) {
			if (this.fileExtName != null && dir != null && dir.isDirectory()
					&& dir.exists() && name != null) {
				String fileExtName = StringUtils.getFilenameExtension(name);
				return fileExtName.equalsIgnoreCase(this.fileExtName);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h2 class="en-US">Implements class for FileFilter by check path is directory</h2>
	 * <h2 class="zh-CN">检查路径是文件夹的FileFilter实现类</h2>
	 */
	private static final class DirectoryFileFilter implements FileFilter {
		/**
		 * <h3 class="en-US">Constructor for DirectoryFileFilter</h3>
		 * <h3 class="zh-CN">DirectoryFileFilter的构造方法</h3>
		 */
		DirectoryFileFilter() {
		}

		/**
		 * (Non-Javadoc)
		 *
		 * @see FileFilter#accept(File)
		 */
		@Override
		public boolean accept(File pathname) {
			return pathname.isDirectory();
		}
	}

	/**
	 * <h3 class="en-US">Move a file from base samba path to the target samba path</h3>
	 * <h3 class="zh-CN">从原samba文件地址移动到目标samba文件地址</h3>
	 *
	 * @param originalFile <span class="en-US">Original file instance</span>
	 *                     <span class="zh-CN">原文件实例对象</span>
	 * @param targetFile   <span class="en-US">Target file instance</span>
	 *                     <span class="zh-CN">目标文件实例对象</span>
	 * @param override     <span class="en-US">Override target if exists</span>
	 *                     <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	private static boolean processFile(final Object originalFile, final Object targetFile, final boolean override) {
		if (originalFile == null || targetFile == null) {
			return Boolean.FALSE;
		}

		try {
			if (targetFile instanceof SmbFile) {
				if (!override && ((SmbFile) targetFile).exists()) {
					return Boolean.FALSE;
				}
				try (InputStream inputStream = (originalFile instanceof SmbFile)
						? new SmbFileInputStream((SmbFile) originalFile) : new FileInputStream((File) originalFile);
				     OutputStream outputStream = new SmbFileOutputStream((SmbFile) targetFile)) {
					int readLength;
					byte[] readBuffer = new byte[Globals.DEFAULT_BUFFER_SIZE];

					while ((readLength = inputStream.read(readBuffer)) != -1) {
						outputStream.write(readBuffer, Globals.INITIALIZE_INT_VALUE, readLength);
					}
					return Boolean.TRUE;
				} catch (Exception e) {
					LOGGER.error("Copy_Files_Error");
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Stack_Message_Error", e);
					}
					return Boolean.FALSE;
				}
			} else {
				if (!override && ((File) targetFile).exists()) {
					return Boolean.FALSE;
				}
				try (InputStream inputStream = (originalFile instanceof SmbFile)
						? new SmbFileInputStream((SmbFile) originalFile) : new FileInputStream((File) originalFile);
				     OutputStream outputStream = new FileOutputStream((File) targetFile)) {
					int readLength;
					byte[] readBuffer = new byte[Globals.DEFAULT_BUFFER_SIZE];

					while ((readLength = inputStream.read(readBuffer)) != -1) {
						outputStream.write(readBuffer, Globals.INITIALIZE_INT_VALUE, readLength);
					}
					return Boolean.TRUE;
				} catch (Exception e) {
					LOGGER.error("Copy_Files_Error");
					if (LOGGER.isDebugEnabled()) {
						LOGGER.debug("Stack_Message_Error", e);
					}
					return Boolean.FALSE;
				}
			}
		} catch (Exception e) {
			LOGGER.error("Move_Files_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}

	/**
	 * <h3 class="en-US">Move a file from base path to the target path</h3>
	 * <h3 class="zh-CN">从原文件地址移动到目标文件地址</h3>
	 *
	 * @param originalDirectory <span class="en-US">Original folder instance</span>
	 *                          <span class="zh-CN">原文件夹实例对象</span>
	 * @param targetDirectory   <span class="en-US">Target folder instance</span>
	 *                          <span class="zh-CN">目标文件夹实例对象</span>
	 * @param override          <span class="en-US">Override target if exists</span>
	 *                          <span class="zh-CN">覆盖目标文件</span>
	 * @return <span class="en-US"><code>Boolean.TRUE</code> for success and <code>Boolean.FALSE</code> for error</span>
	 * <span class="zh-CN">成功返回<code>Boolean.TRUE</code>，失败返回<code>Boolean.FALSE</code></span>
	 */
	private static boolean processDirectory(final Object originalDirectory, final Object targetDirectory,
	                                        final boolean override) {
		if (originalDirectory == null || targetDirectory == null) {
			return Boolean.FALSE;
		}

		try {
			String targetBasePath;
			CIFSContext cifsContext = null;
			if (targetDirectory instanceof SmbFile) {
				((SmbFile) targetDirectory).mkdirs();
				targetBasePath = ((SmbFile) targetDirectory).getPath();
				cifsContext = ((SmbFile) targetDirectory).getContext();
			} else {
				if (((File) targetDirectory).exists() || ((File) targetDirectory).mkdirs()) {
					targetBasePath = ((File) targetDirectory).getAbsolutePath();
				} else {
					return Boolean.FALSE;
				}
			}

			boolean processResult = Boolean.TRUE;
			if (originalDirectory instanceof SmbFile) {
				SmbFile[] childFiles = ((SmbFile) originalDirectory).listFiles();
				for (SmbFile tempFile : childFiles) {
					String childPath = targetBasePath + Globals.DEFAULT_PAGE_SEPARATOR + tempFile.getName();
					Object childFile;
					if (targetDirectory instanceof SmbFile) {
						childFile = new SmbFile(childPath, cifsContext);
					} else {
						childFile = FileUtils.getFile(childPath);
					}
					if (tempFile.isDirectory()) {
						processResult &= FileUtils.processDirectory(tempFile, childFile, override);
					} else if (tempFile.isFile()) {
						processResult &= FileUtils.processFile(tempFile, childFile, override);
					}
				}
			} else {
				File[] childFiles = ((File) originalDirectory).listFiles();
				if (childFiles != null) {
					for (File tempFile : childFiles) {
						BasicFileAttributes basicFileAttributes =
								Files.readAttributes(tempFile.toPath(), BasicFileAttributes.class);
						String childPath = targetBasePath + Globals.DEFAULT_PAGE_SEPARATOR + tempFile.getName();
						Object childFile;
						if (targetDirectory instanceof SmbFile) {
							childFile = new SmbFile(childPath, cifsContext);
						} else {
							childFile = FileUtils.getFile(childPath);
						}
						if (basicFileAttributes.isDirectory()) {
							processResult &= FileUtils.processDirectory(tempFile, childFile, override);
						} else if (basicFileAttributes.isRegularFile()) {
							processResult &= FileUtils.processFile(tempFile, childFile, override);
						}
					}
				}
			}
			return processResult;
		} catch (Exception e) {
			LOGGER.error("Directory_Move_Error");
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
			return Boolean.FALSE;
		}
	}
}
