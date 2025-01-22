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

import org.nervousync.commons.Globals;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.exceptions.zip.ZipException;

import java.io.UnsupportedEncodingException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * <h2 class="en-US">Raw data process utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Read boolean/short/int/long/String from binary data bytes</ul>
 *     <ul>Write boolean/short/int/long/String into binary data bytes</ul>
 *     <ul>Convert a char array to binary data bytes</ul>
 *     <ul>Convert the bit array to byte</ul>
 * </span>
 * <h2 class="zh-CN">二进制数据处理工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>从二进制数组中读取boolean/short/int/long/String类型的数据</ul>
 *     <ul>向二进制数组中写入boolean/short/int/long/String类型的数据</ul>
 *     <ul>转换字节数组为二进制数组</ul>
 *     <ul>转换位数组为字节</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 28, 2017 17:34:55 $
 */
public final class RawUtils {
	/**
	 * <span class="en-US">Default index of data bytes</span>
	 * <span class="zh-CN">默认的数组起始下标</span>
	 */
	private static final int DEFAULT_INDEX = 0;

	/**
	 * <h3 class="en-US">Private constructor for RawUtils</h3>
	 * <h3 class="zh-CN">二进制数据处理工具集的私有构造方法</h3>
	 */
	private RawUtils() {
	}

	/**
	 * <h3 class="en-US">Read boolean from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取boolean类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US"><code>true</code> If value is 1 or <code>false</code> for otherwise</span>
	 * <span class="zh-CN">如果读取的数据为数字1则返回<code>true</code>，其他情况返回<code>false</code></span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static boolean readBoolean(final byte[] dataBytes) throws DataInvalidException {
		return readBoolean(dataBytes, DEFAULT_INDEX);
	}

	/**
	 * <h3 class="en-US">Read boolean from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取boolean类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @return <span class="en-US"><code>true</code> If value is 1 or <code>false</code> for otherwise</span>
	 * <span class="zh-CN">如果读取的数据为数字1则返回<code>true</code>，其他情况返回<code>false</code></span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static boolean readBoolean(final byte[] dataBytes, final int position) throws DataInvalidException {
		if (dataBytes.length <= position) {
			throw new DataInvalidException(0x000000130001L, "Out_Of_Index_Raw_Error", dataBytes.length, position, 1);
		}
		return dataBytes[position] == Globals.DEFAULT_STATUS_TRUE;
	}

	/**
	 * <h3 class="en-US">Write boolean into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入boolean类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeBoolean(final byte[] dataBytes, final boolean value) throws DataInvalidException {
		writeBoolean(dataBytes, DEFAULT_INDEX, value);
	}

	/**
	 * <h3 class="en-US">Write boolean into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入boolean类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeBoolean(final byte[] dataBytes, final int position, final boolean value)
			throws DataInvalidException {
		if (dataBytes.length <= position) {
			throw new DataInvalidException(0x000000130001L, "Out_Of_Index_Raw_Error", dataBytes.length, position, 1);
		}
		dataBytes[position] = (byte) (value ? Globals.DEFAULT_STATUS_TRUE : Globals.DEFAULT_STATUS_FALSE);
	}

	/**
	 * <h3 class="en-US">Read short from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static short readShort(final byte[] dataBytes) throws DataInvalidException {
		return readShort(dataBytes, DEFAULT_INDEX);
	}

	/**
	 * <h3 class="en-US">Read short from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static short readShort(final byte[] dataBytes, final ByteOrder byteOrder) throws DataInvalidException {
		return readShort(dataBytes, DEFAULT_INDEX, byteOrder);
	}

	/**
	 * <h3 class="en-US">Read short from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static short readShort(final byte[] dataBytes, final int position) throws DataInvalidException {
		return readShort(dataBytes, position, ByteOrder.BIG_ENDIAN);
	}

	/**
	 * <h3 class="en-US">Read short from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static short readShort(final byte[] dataBytes, final int position, final ByteOrder byteOrder)
			throws DataInvalidException {
		return (short) readNumber(dataBytes, position, byteOrder, 2);
	}

	/**
	 * <h3 class="en-US">Write short into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeShort(final byte[] dataBytes, final short value) throws DataInvalidException {
		writeShort(dataBytes, DEFAULT_INDEX, value);
	}

	/**
	 * <h3 class="en-US">Write short into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeShort(final byte[] dataBytes, final ByteOrder byteOrder, final short value)
			throws DataInvalidException {
		writeShort(dataBytes, DEFAULT_INDEX, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Write short into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeShort(final byte[] dataBytes, final int position, final short value)
			throws DataInvalidException {
		writeShort(dataBytes, position, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write short into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入short类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeShort(final byte[] dataBytes, final int position,
	                              final ByteOrder byteOrder, final short value) throws DataInvalidException {
		writeNumber(dataBytes, position, Short.SIZE, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Read int from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static int readInt(final byte[] dataBytes) throws DataInvalidException {
		return readInt(dataBytes, DEFAULT_INDEX);
	}

	/**
	 * <h3 class="en-US">Read int from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static int readInt(final byte[] dataBytes, final ByteOrder byteOrder) throws DataInvalidException {
		return readInt(dataBytes, DEFAULT_INDEX, byteOrder);
	}

	/**
	 * <h3 class="en-US">Read int from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static int readInt(final byte[] dataBytes, final int position) throws DataInvalidException {
		return readInt(dataBytes, position, ByteOrder.BIG_ENDIAN);
	}

	/**
	 * <h3 class="en-US">Read int from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static int readInt(final byte[] dataBytes, final int position, final ByteOrder byteOrder)
			throws DataInvalidException {
		return (int) readNumber(dataBytes, position, byteOrder, 4);
	}

	/**
	 * <h3 class="en-US">Write int into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeInt(final byte[] dataBytes, final int value) throws DataInvalidException {
		writeInt(dataBytes, DEFAULT_INDEX, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write int into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeInt(final byte[] dataBytes, final ByteOrder byteOrder, final int value)
			throws DataInvalidException {
		writeInt(dataBytes, DEFAULT_INDEX, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Write int into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeInt(final byte[] dataBytes, final int position, final int value)
			throws DataInvalidException {
		writeInt(dataBytes, position, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write int into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入int类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeInt(final byte[] dataBytes, final int position,
	                            final ByteOrder byteOrder, final int value) throws DataInvalidException {
		writeNumber(dataBytes, position, Integer.SIZE, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Read long from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static long readLong(final byte[] dataBytes) throws DataInvalidException {
		return readLong(dataBytes, DEFAULT_INDEX);
	}

	/**
	 * <h3 class="en-US">Read long from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static long readLong(final byte[] dataBytes, final ByteOrder byteOrder) throws DataInvalidException {
		return readLong(dataBytes, DEFAULT_INDEX, byteOrder);
	}

	/**
	 * <h3 class="en-US">Read long from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static long readLong(final byte[] dataBytes, final int position) throws DataInvalidException {
		return readLong(dataBytes, position, ByteOrder.BIG_ENDIAN);
	}

	/**
	 * <h3 class="en-US">Read long from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static long readLong(final byte[] dataBytes, final int position, final ByteOrder byteOrder)
			throws DataInvalidException {
		return (long) readNumber(dataBytes, position, byteOrder, 8);
	}

	/**
	 * <h3 class="en-US">Write long into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeLong(final byte[] dataBytes, final long value) throws DataInvalidException {
		writeLong(dataBytes, DEFAULT_INDEX, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write long into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeLong(final byte[] dataBytes, final ByteOrder byteOrder, final long value)
			throws DataInvalidException {
		writeLong(dataBytes, DEFAULT_INDEX, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Write long into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeLong(final byte[] dataBytes, final int position, final long value)
			throws DataInvalidException {
		writeLong(dataBytes, position, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write long into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入long类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeLong(final byte[] dataBytes, final int position,
	                             final ByteOrder byteOrder, final long value) throws DataInvalidException {
		writeNumber(dataBytes, position, Long.SIZE, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes) throws DataInvalidException {
		return readString(dataBytes, Globals.DEFAULT_VALUE_INT);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int length) throws DataInvalidException {
		return readString(dataBytes, DEFAULT_INDEX, length);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int position, final int length)
			throws DataInvalidException {
		return readString(dataBytes, position, length, ByteOrder.BIG_ENDIAN);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int length, final ByteOrder byteOrder)
			throws DataInvalidException {
		return readString(dataBytes, length, Globals.DEFAULT_ENCODING, byteOrder);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int position,
	                                final int length, final ByteOrder byteOrder) throws DataInvalidException {
		return readString(dataBytes, position, length, Globals.DEFAULT_ENCODING, byteOrder);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param encoding  <span class="en-US">Charset encoding</span>
	 *                  <span class="zh-CN">字符集编码</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int length, final String encoding)
			throws DataInvalidException {
		return readString(dataBytes, length, encoding, ByteOrder.BIG_ENDIAN);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param encoding  <span class="en-US">Charset encoding</span>
	 *                  <span class="zh-CN">字符集编码</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int position,
	                                final int length, final String encoding) throws DataInvalidException {
		return readString(dataBytes, position, length, encoding, ByteOrder.BIG_ENDIAN);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param encoding  <span class="en-US">Charset encoding</span>
	 *                  <span class="zh-CN">字符集编码</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static String readString(final byte[] dataBytes, final int length, final String encoding,
	                                final ByteOrder byteOrder) throws DataInvalidException {
		return readString(dataBytes, DEFAULT_INDEX, length, encoding, byteOrder);
	}

	/**
	 * <h3 class="en-US">Read String from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param encoding  <span class="en-US">Charset encoding</span>
	 *                  <span class="zh-CN">字符集编码</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Read string</span>
	 * <span class="zh-CN">读取的字符串</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds or charset encoding wasn't supported</span>
	 *                              <span class="zh-CN">如果数组下标越界或字符集编码不支持</span>
	 */
	public static String readString(final byte[] dataBytes, final int position, final int length,
	                                final String encoding, final ByteOrder byteOrder) throws DataInvalidException {
		if (position < 0 || dataBytes == null) {
			throw new DataInvalidException(0x000000FF0001L, "Parameter_Invalid_Error");
		}
		int readLength = (length == Globals.DEFAULT_VALUE_INT) ? dataBytes.length - position : length;
		if (dataBytes.length < (position + readLength)) {
			throw new DataInvalidException(0x000000130002L, "Length_Not_Enough_Raw_Error");
		}
		try {
			byte[] readBytes = new byte[readLength];
			initBuffer(dataBytes, position, readLength, byteOrder).get(readBytes);
			return new String(readBytes, encoding);
		} catch (UnsupportedEncodingException e) {
			throw new DataInvalidException(0x000000FF0002L, "Not_Support_Encoding_Error", e);
		}
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeString(final byte[] dataBytes, final String value) throws DataInvalidException {
		writeString(dataBytes, DEFAULT_INDEX, Globals.DEFAULT_ENCODING, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeString(final byte[] dataBytes, final int position, final String value)
			throws DataInvalidException {
		writeString(dataBytes, position, Globals.DEFAULT_ENCODING, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeString(final byte[] dataBytes, final ByteOrder byteOrder, final String value)
			throws DataInvalidException {
		writeString(dataBytes, DEFAULT_INDEX, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	public static void writeString(final byte[] dataBytes, final int position,
	                               final ByteOrder byteOrder, final String value) throws DataInvalidException {
		writeString(dataBytes, position, Globals.DEFAULT_ENCODING, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds or charset encoding wasn't supported</span>
	 *                              <span class="zh-CN">如果数组下标越界或字符集编码不支持</span>
	 */
	public static void writeString(final byte[] dataBytes, final String value, final String encoding)
			throws DataInvalidException {
		writeString(dataBytes, ByteOrder.BIG_ENDIAN, value, encoding);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds or charset encoding wasn't supported</span>
	 *                              <span class="zh-CN">如果数组下标越界或字符集编码不支持</span>
	 */
	public static void writeString(final byte[] dataBytes, final int position,
	                               final String value, final String encoding) throws DataInvalidException {
		writeString(dataBytes, position, encoding, ByteOrder.BIG_ENDIAN, value);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds or charset encoding wasn't supported</span>
	 *                              <span class="zh-CN">如果数组下标越界或字符集编码不支持</span>
	 */
	public static void writeString(final byte[] dataBytes, final ByteOrder byteOrder,
	                               final String value, final String encoding) throws DataInvalidException {
		writeString(dataBytes, DEFAULT_INDEX, encoding, byteOrder, value);
	}

	/**
	 * <h3 class="en-US">Write String into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入String类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param encoding  <span class="en-US">Charset encoding</span>
	 *                  <span class="zh-CN">字符集编码</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds or charset encoding wasn't supported</span>
	 *                              <span class="zh-CN">如果数组下标越界或字符集编码不支持</span>
	 */
	public static void writeString(final byte[] dataBytes, final int position, final String encoding,
	                               final ByteOrder byteOrder, final String value) throws DataInvalidException {
		if (StringUtils.isEmpty(value)) {
			return;
		}
		try {
			byte[] valueBytes = initBuffer(value.getBytes(encoding), byteOrder).array();
			if ((position + valueBytes.length) <= dataBytes.length) {
				System.arraycopy(valueBytes, 0, dataBytes, position, valueBytes.length);
			} else {
				throw new DataInvalidException(0x000000130001L, "Out_Of_Index_Raw_Error",
						dataBytes.length, position, valueBytes.length);
			}
		} catch (UnsupportedEncodingException e) {
			throw new DataInvalidException(0x000000FF0002L, "Not_Support_Encoding_Error", e);
		}
	}

	/**
	 * <h3 class="en-US">Convert a char array to binary data bytes</h3>
	 * <h3 class="zh-CN">转换字节数组为二进制数组</h3>
	 *
	 * @param charArray <span class="en-US">char array</span>
	 *                  <span class="zh-CN">字节数组</span>
	 * @return <span class="en-US">Converted Binary data bytes</span>
	 * <span class="zh-CN">转换后的二进制字节数组</span>
	 */
	public static byte[] charArrayToByteArray(final char[] charArray) {
		if (charArray == null) {
			throw new NullPointerException();
		}

		byte[] bytes = new byte[charArray.length];

		for (int i = 0; i < charArray.length; i++) {
			bytes[i] = (byte) charArray[i];
		}

		return bytes;
	}

	/**
	 * <h3 class="en-US">Convert the bit array to byte</h3>
	 * <h3 class="zh-CN">转换位数组为字节</h3>
	 *
	 * @param bitArray <span class="en-US">bit array</span>
	 *                 <span class="zh-CN">位数组</span>
	 * @return <span class="en-US">Converted byte value</span>
	 * <span class="zh-CN">转换后的字节值</span>
	 * @throws ZipException <span class="en-US">If bitArray is null or invalid</span>
	 *                      <span class="zh-CN">如果位数组为null或者长度非法</span>
	 */
	public static byte bitArrayToByte(final int[] bitArray) throws ZipException {
		if (bitArray == null) {
			throw new ZipException(0x000000FF0001L, "Parameter_Invalid_Error");
		}

		if (bitArray.length != 8) {
			throw new ZipException(0x000000130003L, "Length_Bits_Invalid_Raw_Error");
		}

		if (Arrays.stream(bitArray).anyMatch(bit -> (bit != 0 && bit != 1))) {
			throw new ZipException(0x000000130004L, "Data_Bits_Invalid_Raw_Error");
		}

		int calValue = 0;
		for (int i = 0; i < bitArray.length; i++) {
			calValue += (int) (Math.pow(2, i) * bitArray[i]);
		}
		return (byte) calValue;
	}

	/**
	 * <h3 class="en-US">Initialize ByteBuffer by given data bytes and byte order type</h3>
	 * <h3 class="zh-CN">使用给定的字节数组和排序类型初始化ByteBuffer实例对象</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Initialized ByteBuffer instance</span>
	 * <span class="zh-CN">初始化的ByteBuffer实例对象</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	private static ByteBuffer initBuffer(final byte[] dataBytes, final ByteOrder byteOrder)
			throws DataInvalidException {
		return initBuffer(dataBytes, 0, dataBytes.length, byteOrder);
	}

	/**
	 * <h3 class="en-US">Initialize ByteBuffer by given data bytes and byte order type</h3>
	 * <h3 class="zh-CN">使用给定的字节数组和排序类型初始化ByteBuffer实例对象</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param length    <span class="en-US">Read data bytes length</span>
	 *                  <span class="zh-CN">读取的二进制字节长度</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @return <span class="en-US">Initialized ByteBuffer instance</span>
	 * <span class="zh-CN">初始化的ByteBuffer实例对象</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	private static ByteBuffer initBuffer(final byte[] dataBytes, final int position, final int length,
	                                     final ByteOrder byteOrder) throws DataInvalidException {
		if (dataBytes.length < (position + length)) {
			throw new DataInvalidException(0x000000130001L, "Out_Of_Index_Raw_Error",
					dataBytes.length, position, length);
		}
		return ByteBuffer.wrap(dataBytes, position, length).order(byteOrder);
	}

	/**
	 * <h3 class="en-US">Write number into binary data bytes</h3>
	 * <h3 class="zh-CN">向二进制数组中写入数值类型的数据</h3>
	 *
	 * @param dataBytes <span class="en-US">Binary data bytes</span>
	 *                  <span class="zh-CN">二进制字节数组</span>
	 * @param position  <span class="en-US">Begin position of data bytes</span>
	 *                  <span class="zh-CN">字节数组的起始下标</span>
	 * @param dataSize  <span class="en-US">Data bytes length</span>
	 *                  <span class="zh-CN">写入的数据长度</span>
	 * @param byteOrder <span class="en-US">Byte order type</span>
	 *                  <span class="zh-CN">大端/小端</span>
	 * @param value     <span class="en-US">Write value</span>
	 *                  <span class="zh-CN">写入的数据</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	private static void writeNumber(final byte[] dataBytes, final int position, final int dataSize,
	                                final ByteOrder byteOrder, final Object value) throws DataInvalidException {
		if (dataSize % Byte.SIZE != 0) {
			throw new DataInvalidException(0x000000130005L, "Data_Size_Invalid_Raw_Error");
		}
		int dataLength = dataSize / Byte.SIZE;
		if (dataBytes.length < (position + dataLength)) {
			throw new DataInvalidException(0x000000130001L, "Out_Of_Index_Raw_Error",
					dataBytes.length, position, dataLength);
		}
		final ByteBuffer byteBuffer = initBuffer(dataBytes, position, dataLength, byteOrder);
		switch (dataSize) {
			case Short.SIZE:
				byteBuffer.putShort((short) value);
				break;
			case Integer.SIZE:
				byteBuffer.putInt((int) value);
				break;
			case Long.SIZE:
				byteBuffer.putLong((long) value);
				break;
			default:
				throw new DataInvalidException(0x000000130006L, "Data_Size_Unknown_Raw_Error");
		}
	}

	/**
	 * <h3 class="en-US">Read number from binary data bytes</h3>
	 * <h3 class="zh-CN">从二进制数组中读取数值类型的数据</h3>
	 *
	 * @param dataBytes  <span class="en-US">Binary data bytes</span>
	 *                   <span class="zh-CN">二进制字节数组</span>
	 * @param position   <span class="en-US">Begin position of data bytes</span>
	 *                   <span class="zh-CN">字节数组的起始下标</span>
	 * @param byteOrder  <span class="en-US">Byte order type</span>
	 *                   <span class="zh-CN">大端/小端</span>
	 * @param dataLength <span class="en-US">Data bytes length</span>
	 *                   <span class="zh-CN">读取的数据长度</span>
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的数值</span>
	 * @throws DataInvalidException <span class="en-US">If array index out of bounds</span>
	 *                              <span class="zh-CN">如果数组下标越界</span>
	 */
	private static Object readNumber(final byte[] dataBytes, final int position, final ByteOrder byteOrder,
	                                 final int dataLength) throws DataInvalidException {
		if (dataBytes.length < (position + dataLength)) {
			throw new DataInvalidException(0x000000130001L, "Out_Of_Index_Raw_Error",
					dataBytes.length, position, 8);
		}
		final ByteBuffer byteBuffer = initBuffer(dataBytes, position, dataLength, byteOrder);
		switch (dataLength) {
			case 2:
				return byteBuffer.getShort();
			case 4:
				return byteBuffer.getInt();
			case 8:
				return byteBuffer.getLong();
			default:
				throw new DataInvalidException(0x000000130006L, "Data_Size_Unknown_Raw_Error");
		}
	}
}
