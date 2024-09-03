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

package org.nervousync.beans.path;

import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Jar path define</h2>
 * <h2 class="zh-CN">Jar路径定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jul 31, 2023 16:27:08 $
 */
public class TargetPath {
	/**
	 * <span class="en-US">Separator between JAR URL and the path within the JAR</span>
	 * <span class="zh-CN">JAR URL 和 JAR 内路径之间的分隔符</span>
	 */
	public static final String JAR_URL_SEPARATOR = "!/";
	/**
	 * <span class="en-US">Archive file path</span>
	 * <span class="zh-CN">压缩文件路径</span>
	 */
	private final String filePath;
	/**
	 * <span class="en-US">Entry path</span>
	 * <span class="zh-CN">资源路径</span>
	 */
	private final String entryPath;

	/**
	 * <h3 class="en-US">Constructor for TargetPath</h3>
	 * <h3 class="zh-CN">Jar路径定义的构造方法</h3>
	 *
	 * @param filePath  <span class="en-US">Archive file path</span>
	 *                  <span class="zh-CN">压缩文件路径</span>
	 * @param entryPath <span class="en-US">Entry path</span>
	 *                  <span class="zh-CN">资源路径</span>
	 */
	private TargetPath(final String filePath, final String entryPath) {
		this.filePath = filePath;
		this.entryPath = entryPath;
	}

	/**
	 * <h3 class="en-US">Static method for parse resource location string to TargetPath instance</h3>
	 * <h3 class="zh-CN">静态方法用于解析资源路径字符串为JarPath实例对象</h3>
	 *
	 * @param resourceLocation <span class="en-US">the location String</span>
	 *                         <span class="zh-CN">位置字符串</span>
	 * @return <span class="en-US">Parsed TargetPath instance or <code>null</code> if resource location string invalid</span>
	 * <span class="zh-CN">解析后的 TargetPath 实例对象，如果位置字符串不是合法的资源路径则返回 <code>null</code></span>
	 */
	public static TargetPath parse(final String resourceLocation) {
		if (StringUtils.containsIgnoreCase(resourceLocation, JAR_URL_SEPARATOR)) {
			int index = resourceLocation.indexOf(JAR_URL_SEPARATOR);
			return new TargetPath(resourceLocation.substring(0, index),
					resourceLocation.substring(index + JAR_URL_SEPARATOR.length()));
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Static method for generate TargetPath instance</h3>
	 * <h3 class="zh-CN">静态方法用于解析资源路径字符串为JarPath实例对象</h3>
	 *
	 * @param filePath  <span class="en-US">Archive file path</span>
	 *                  <span class="zh-CN">压缩文件路径</span>
	 * @param entryPath <span class="en-US">Entry path</span>
	 *                  <span class="zh-CN">资源路径</span>
	 * @return <span class="en-US">Generated TargetPath instance or <code>null</code> if filePath or entryPath is <code>null</code></span>
	 * <span class="zh-CN">生成的 TargetPath 实例对象，如果压缩文件路径或资源路径为 <code>null</code> 则返回 <code>null</code></span>
	 */
	public static TargetPath newInstance(final String filePath, final String entryPath) {
		if (filePath == null || filePath.isEmpty() || entryPath == null || entryPath.isEmpty()) {
			return null;
		}
		return new TargetPath(filePath, entryPath);
	}

	/**
	 * <h3 class="en-US">Getter method for file path</h3>
	 * <h3 class="zh-CN">Jar文件路径的Getter方法</h3>
	 *
	 * @return <span class="en-US">Jar file path</span>
	 * <span class="zh-CN">Jar文件路径</span>
	 */
	public String getFilePath() {
		return filePath;
	}

	/**
	 * <h3 class="en-US">Getter method for entry path</h3>
	 * <h3 class="zh-CN">Jar资源路径的Getter方法</h3>
	 *
	 * @return <span class="en-US">Jar entry path</span>
	 * <span class="zh-CN">Jar资源路径</span>
	 */
	public String getEntryPath() {
		return entryPath;
	}
}
