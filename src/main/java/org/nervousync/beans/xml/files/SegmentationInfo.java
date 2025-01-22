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
package org.nervousync.beans.xml.files;

import jakarta.xml.bind.annotation.*;
import org.nervousync.beans.core.BeanObject;

import java.util.List;

/**
 * <h2 class="en-US">Segment Data Information Define</h2>
 * <h2 class="zh-CN">分割数据信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Jun 9, 2015 09:43:23 $
 */
@XmlType(name = "segment_info", namespace = "https://nervousync.org/schemas/segment")
@XmlRootElement(name = "segment_info", namespace = "https://nervousync.org/schemas/segment")
@XmlAccessorType(XmlAccessType.NONE)
public final class SegmentationInfo extends BeanObject {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 2885564700967742489L;
	/**
	 * <span class="en-US">Total data size</span>
	 * <span class="zh-CN">数据大小</span>
	 */
	@XmlElement(name = "total_size")
	private long totalSize;
	/**
	 * <span class="en-US">Block data size</span>
	 * <span class="zh-CN">数据块大小</span>
	 */
	@XmlElement(name = "block_size")
	private int blockSize;
	/**
	 * <span class="en-US">File extension name</span>
	 * <span class="zh-CN">文件扩展名</span>
	 */
	@XmlElement(name = "ext_name")
	private String extName;
	/**
	 * <span class="en-US">Block data identified value of SHA256</span>
	 * <span class="zh-CN">数据块验证值，使用SHA256</span>
	 */
	@XmlElement(name = "signature_sha")
	private String sha;
	/**
	 * <span class="en-US">Block data list</span>
	 * <span class="zh-CN">数据块列表</span>
	 */
	@XmlElementWrapper(name = "block_list")
	@XmlElement(name = "segment_block")
	private List<SegmentationBlock> blockList;

	/**
	 * <h3 class="en-US">Default constructor for SegmentationInfo</h3>
	 * <h3 class="zh-CN">SegmentationInfo的默认构造函数</h3>
	 */
	public SegmentationInfo() {
	}

	/**
	 * <h3 class="en-US">Constructor for SegmentationInfo</h3>
	 * <span class="en-US">Using given extension name, total size, block size, identified value and blocklist</span>
	 * <h3 class="zh-CN">SegmentationInfo的构造函数</h3>
	 * <span class="zh-CN">使用给定的文件扩展名，数据大小，文件验证码以及数据块列表</span>
	 *
	 * @param extName   <span class="en-US">File extension name</span>
	 *                  <span class="zh-CN">文件扩展名</span>
	 * @param totalSize <span class="en-US">Total data size</span>
	 *                  <span class="zh-CN">数据大小</span>
	 * @param blockSize <span class="en-US">Block data size</span>
	 *                  <span class="zh-CN">数据块大小</span>
	 * @param sha       <span class="en-US">Block data identified value of SHA256</span>
	 *                  <span class="zh-CN">数据块验证值，使用SHA256</span>
	 * @param blockList <span class="en-US">Block data list</span>
	 *                  <span class="zh-CN">数据块列表</span>
	 */
	public SegmentationInfo(String extName, long totalSize, int blockSize, String sha,
	                        List<SegmentationBlock> blockList) {
		this.extName = extName;
		this.totalSize = totalSize;
		this.blockSize = blockSize;
		this.sha = sha;
		this.blockList = blockList;
	}

	/**
	 * <h3 class="en-US">Getter method for total data size</h3>
	 * <h3 class="zh-CN">数据大小的Getter方法</h3>
	 *
	 * @return <span class="en-US">Total data size</span>
	 * <span class="zh-CN">数据大小</span>
	 */
	public long getTotalSize() {
		return totalSize;
	}

	/**
	 * <h3 class="en-US">Getter method for block size</h3>
	 * <h3 class="zh-CN">数据块长度的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block data size</span>
	 * <span class="zh-CN">数据块大小</span>
	 */
	public int getBlockSize() {
		return blockSize;
	}

	/**
	 * <h3 class="en-US">Getter method for file extension name</h3>
	 * <h3 class="zh-CN">文件扩展名的Getter方法</h3>
	 *
	 * @return <span class="en-US">File extension name</span>
	 * <span class="zh-CN">文件扩展名</span>
	 */
	public String getExtName() {
		return extName;
	}

	/**
	 * <h3 class="en-US">Getter method for identified value</h3>
	 * <h3 class="zh-CN">数据块验证值的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block data identified value of SHA256</span>
	 * <span class="zh-CN">数据块验证值，使用SHA256</span>
	 */
	public String getSha() {
		return sha;
	}

	/**
	 * <h3 class="en-US">Getter method for block data list</h3>
	 * <h3 class="zh-CN">数据块列表的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block data list</span>
	 * <span class="zh-CN">数据块列表</span>
	 */
	public List<SegmentationBlock> getBlockList() {
		return blockList;
	}
}
