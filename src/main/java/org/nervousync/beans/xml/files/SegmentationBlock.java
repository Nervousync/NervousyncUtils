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
import org.nervousync.beans.transfer.cdata.CDataAdapter;
import org.nervousync.beans.transfer.basic.DateTimeAdapter;
import org.nervousync.beans.core.BeanObject;
import org.nervousync.utils.ConvertUtils;
import org.nervousync.utils.SecurityUtils;
import org.nervousync.utils.StringUtils;

import jakarta.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import java.util.Date;
import java.util.Objects;

/**
 * <h2 class="en-US">Segment Data Block Define</h2>
 * <h2 class="zh-CN">分割数据块定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $Date: Oct 15, 2018 12:41:27 $
 */
@XmlType(name = "segment_block", namespace = "https://nervousync.org/schemas/segment")
@XmlRootElement(name = "segment_block", namespace = "https://nervousync.org/schemas/segment")
@XmlAccessorType(XmlAccessType.NONE)
public final class SegmentationBlock extends BeanObject {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = 2993229461743423521L;
	/**
	 * <span class="en-US">Block begin position</span>
	 * <span class="zh-CN">数据块起始地址</span>
	 */
	@XmlElement(name = "position")
	private long position;
	/**
	 * <span class="en-US">Block data size</span>
	 * <span class="zh-CN">数据块大小</span>
	 */
	@XmlElement(name = "block_size")
	private long blockSize;
	/**
	 * <span class="en-US">Block data identified value of SHA256</span>
	 * <span class="zh-CN">数据块验证值，使用SHA256</span>
	 */
	@XmlElement(name = "signature_sha")
	private String sha;
	/**
	 * <span class="en-US">Block data information, base64 encoded data bytes</span>
	 * <span class="zh-CN">数据块信息，使用Base64编码</span>
	 */
	@XmlElement(name = "data_info")
	@XmlJavaTypeAdapter(CDataAdapter.class)
	private String dataInfo;
	/**
	 * <span class="en-US">Block generate time</span>
	 * <span class="zh-CN">数据块生成时间</span>
	 */
	@XmlElement(name = "current_time")
	@XmlJavaTypeAdapter(DateTimeAdapter.class)
	private Date currentTime;

	/**
	 * <h3 class="en-US">Default constructor for SegmentationBlock</h3>
	 * <h3 class="zh-CN">SegmentationBlock的默认构造函数</h3>
	 */
	public SegmentationBlock() {
	}

	/**
	 * <h3 class="en-US">Constructor for SegmentationBlock</h3>
	 * <span class="en-US">Using given block begin position and binary array of data content</span>
	 * <h3 class="zh-CN">SegmentationBlock的构造函数</h3>
	 * <span class="zh-CN">使用给定的数据块起始地址和数据的字节数组</span>
	 *
	 * @param position    <span class="en-US">Block begin position</span>
	 *                    <span class="zh-CN">数据块起始地址</span>
	 * @param dataContent <span class="en-US">Binary array of data content</span>
	 *                    <span class="zh-CN">数据的字节数组</span>
	 */
	public SegmentationBlock(long position, byte[] dataContent) {
		this.sha = ConvertUtils.toHex(SecurityUtils.SHA256(dataContent));
		this.position = position;
		this.blockSize = dataContent.length;
		this.dataInfo = StringUtils.base64Encode(dataContent);
		this.currentTime = new Date();
	}

	/**
	 * <h3 class="en-US">Getter method for block begin position</h3>
	 * <h3 class="zh-CN">数据块起始地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block begin position</span>
	 * <span class="zh-CN">数据块起始地址</span>
	 */
	public long getPosition() {
		return position;
	}

	/**
	 * <h3 class="en-US">Getter method for block size</h3>
	 * <h3 class="zh-CN">数据块长度的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block data size</span>
	 * <span class="zh-CN">数据块大小</span>
	 */
	public long getBlockSize() {
		return blockSize;
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
	 * <h3 class="en-US">Getter method for block data information</h3>
	 * <h3 class="zh-CN">数据块信息的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block data information, base64 encoded data bytes</span>
	 * <span class="zh-CN">数据块信息，使用Base64编码</span>
	 */
	public String getDataInfo() {
		return dataInfo;
	}

	/**
	 * <h3 class="en-US">Getter method for block generate time</h3>
	 * <h3 class="zh-CN">数据块生成时间的Getter方法</h3>
	 *
	 * @return <span class="en-US">Block generate time</span>
	 * <span class="zh-CN">数据块生成时间</span>
	 */
	public Date getCurrentTime() {
		return currentTime == null ? null : (Date) currentTime.clone();
	}

	/**
	 * <h3 class="en-US">Verify current data block</h3>
	 * <h3 class="zh-CN">验证当前数据块</h3>
	 *
	 * @return <span class="en-US"><code>true</code> for valid, <code>false</code> for invalid</span>
	 * <span class="zh-CN"><code>true</code>验证通过，<code>false</code>验证失败</span>
	 */
	public boolean securityCheck() {
		byte[] dataContent = StringUtils.base64Decode(this.dataInfo);
		try {
			return dataContent.length == this.blockSize
					&& Objects.equals(ConvertUtils.toHex(SecurityUtils.SHA256(dataContent)), this.sha);
		} catch (Exception e) {
			return Boolean.FALSE;
		}
	}
}
