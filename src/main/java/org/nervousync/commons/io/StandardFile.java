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
package org.nervousync.commons.io;

import java.io.Closeable;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;

import jakarta.annotation.Nonnull;
import org.nervousync.commons.Globals;
import org.nervousync.utils.FileUtils;

import jcifs.smb.SmbRandomAccessFile;

/**
 * <h2 class="en-US">Custom RandomAccessFile</h2>
 * <span class="en-US">Supported local files and NAS files(protocol: smb://)</span>
 * <h2 class="zh-CN">自定义的RandomAccessFile</h2>
 * <span class="en-US">支持本地文件和网络文件（协议：smb://）</span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.0 $ $Date: Apr 22, 2022 11:49:46 AM $
 */
public class StandardFile implements DataInput, DataOutput, Closeable {
	/**
	 * <span class="en-US">Current file path</span>
	 * <span class="zh-CN">当前文件地址</span>
	 */
	private final String filePath;
	/**
	 * <span class="en-US">Domain name for NAS file</span>
	 * <span class="zh-CN">NAS文件的域名地址</span>
	 */
	private final String domain;
	/**
	 * <span class="en-US">Username for NAS file</span>
	 * <span class="zh-CN">NAS文件的用户名</span>
	 */
	private final String userName;
	/**
	 * <span class="en-US">Password for NAS file</span>
	 * <span class="zh-CN">NAS文件的密码</span>
	 */
	private final String passWord;
	/**
	 * <span class="en-US">Instance of RandomAccessFile/SmbRandomAccessFile</span>
	 * <span class="zh-CN">RandomAccessFile的SmbRandomAccessFile的实例对象</span>
	 */
	private Object originObject = null;

	/**
	 * <h3 class="en-US">Constructor for using NervousyncRandomAccessFile open local file</h3>
	 * <h3 class="zh-CN">NervousyncRandomAccessFile的构造函数，用于打开本地文件</h3>
	 *
	 * @param filePath <span class="en-US">Current file path</span>
	 *                 <span class="zh-CN">当前文件地址</span>
	 * @throws FileNotFoundException <span class="en-US">If target file was not found</span>
	 *                               <span class="zh-CN">文件未找到时抛出异常</span>
	 */
	public StandardFile(final String filePath) throws FileNotFoundException {
		this(filePath, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Constructor for using NervousyncRandomAccessFile open local file with writable mode</h3>
	 * <h3 class="zh-CN">NervousyncRandomAccessFile的构造函数，用于打开本地文件</h3>
	 *
	 * @param filePath <span class="en-US">Current file path</span>
	 *                 <span class="zh-CN">当前文件地址</span>
	 * @param writable <span class="en-US">Open in or not in writable mode</span>
	 *                 <span class="zh-CN">是否以写入模式打开文件</span>
	 * @throws FileNotFoundException <span class="en-US">If target file was not found</span>
	 *                               <span class="zh-CN">文件未找到时抛出异常</span>
	 */
	public StandardFile(final String filePath, final boolean writable) throws FileNotFoundException {
		this(filePath, writable, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING, Globals.DEFAULT_VALUE_STRING);
	}

	/**
	 * <h3 class="en-US">Constructor for using NervousyncRandomAccessFile open samba file</h3>
	 * <h3 class="zh-CN">NervousyncRandomAccessFile的构造函数，用于打开网络文件</h3>
	 *
	 * @param filePath <span class="en-US">Samba file path</span>
	 *                 <span class="zh-CN">网络文件地址</span>
	 * @param domain   <span class="en-US">Domain name for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName <span class="en-US">Username for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord <span class="en-US">Password for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的密码</span>
	 * @throws FileNotFoundException <span class="en-US">If connect to samba file has error occurs</span>
	 *                               <span class="zh-CN">连接到Samba服务器时抛出异常</span>
	 */
	public StandardFile(final String filePath, final String domain,
	                    final String userName, final String passWord) throws FileNotFoundException {
		this(filePath, Boolean.FALSE, domain, userName, passWord);
	}

	/**
	 * <h3 class="en-US">Constructor for using NervousyncRandomAccessFile open smb file with writable mode</h3>
	 * <h3 class="zh-CN">NervousyncRandomAccessFile的构造函数，用于打开本地文件</h3>
	 *
	 * @param filePath <span class="en-US">Samba file path</span>
	 *                 <span class="zh-CN">网络文件地址</span>
	 * @param writable <span class="en-US">Open in or not in writable mode</span>
	 *                 <span class="zh-CN">是否以写入模式打开文件</span>
	 * @param domain   <span class="en-US">Domain name for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的域名地址</span>
	 * @param userName <span class="en-US">Username for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的用户名</span>
	 * @param passWord <span class="en-US">Password for NAS file</span>
	 *                 <span class="zh-CN">NAS文件的密码</span>
	 * @throws FileNotFoundException <span class="en-US">If connect to samba file has error occurs</span>
	 *                               <span class="zh-CN">连接到Samba服务器时抛出异常</span>
	 */
	public StandardFile(final String filePath, final boolean writable, final String domain,
	                    final String userName, final String passWord) throws FileNotFoundException {
		this.filePath = filePath;
		if (this.filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
			this.domain = domain;
			this.userName = userName;
			this.passWord = passWord;
		} else {
			this.domain = Globals.DEFAULT_VALUE_STRING;
			this.userName = Globals.DEFAULT_VALUE_STRING;
			this.passWord = Globals.DEFAULT_VALUE_STRING;
		}
		this.openFile(writable ? "rw" : "r");
	}

	/**
	 * <h3 class="en-US">Read current file total length</h3>
	 * <h3 class="zh-CN">读取当前文件的数据长度</h3>
	 *
	 * @return <span class="en-US">Total length</span>
	 * <span class="zh-CN">数据长度</span>
	 * @throws IOException <span class="en-US">If I/O error occurs when read file length failed</span>
	 *                     <span class="zh-CN">读取当前文件的数据长度时出现I/O错误</span>
	 */
	public long length() throws IOException {
		return FileUtils.fileSize(this.filePath,
				FileUtils.generateContext(FileUtils.smbAuthenticator(this.domain, this.userName, this.passWord)));
	}

	/**
	 * <h3 class="en-US">Getter method for current file path</h3>
	 * <h3 class="zh-CN">当前文件地址的Getter方法</h3>
	 *
	 * @return <span class="en-US">Current file path</span>
	 * <span class="zh-CN">当前文件地址</span>
	 */
	public String getFilePath() {
		return filePath;
	}

	/**
	 * <h3 class="en-US">Getter method for current file read pointer</h3>
	 * <h3 class="zh-CN">当前文件读取指针位置的Getter方法</h3>
	 *
	 * @return <span class="en-US">Current file read pointer</span>
	 * <span class="zh-CN">当前文件读取指针位置</span>
	 * @throws IOException <span class="en-US">If I/O error occurs when read file pointer</span>
	 *                     <span class="zh-CN">读取当前文件的读取指针时出现I/O错误</span>
	 */
	public long getFilePointer() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).getFilePointer();
		} else {
			return ((RandomAccessFile) this.originObject).getFilePointer();
		}
	}

	/**
	 * <h3 class="en-US">Sets the file-pointer offset</h3>
	 * <span class="en-US">
	 * Measured from the beginning of this file, at which the next read or write occurs.
	 * The offset may be set beyond the end of the file.
	 * Setting the offset beyond the end of the file does not change the file length.
	 * The file length will change only by writing after the offset has been set beyond the end of the file.
	 * </span>
	 * <h3 class="zh-CN">设置当前文件读取指针的位移</h3>
	 * <span class="zh-CN">
	 * 从该文件的开头开始测量，此时发生下一次读取或写入。 偏移量可以设置为超出文件末尾。
	 * 设置超出文件末尾的偏移量不会更改文件长度。 文件长度仅会在偏移量设置为超出文件末尾后写入才会更改。
	 * </span>
	 * Set the file-pointer to position
	 *
	 * @param pos target position
	 * @throws IOException Seek position failed
	 */
	public void seek(long pos) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).seek(pos);
		} else {
			((RandomAccessFile) this.originObject).seek(pos);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.Closeable#close()
	 */
	@Override
	public void close() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).close();
		} else {
			((RandomAccessFile) this.originObject).close();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#write(int)
	 */
	@Override
	public void write(int b) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).write(b);
		} else {
			((RandomAccessFile) this.originObject).write(b);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#write(byte[])
	 */
	@Override
	public void write(@Nonnull byte[] b) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).write(b);
		} else {
			((RandomAccessFile) this.originObject).write(b);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#write(byte[], int, int)
	 */
	@Override
	public void write(@Nonnull byte[] b, int off, int len) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).write(b, off, len);
		} else {
			((RandomAccessFile) this.originObject).write(b, off, len);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeBoolean(boolean)
	 */
	@Override
	public void writeBoolean(boolean v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeBoolean(v);
		} else {
			((RandomAccessFile) this.originObject).writeBoolean(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeByte(int)
	 */
	@Override
	public void writeByte(int v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeByte(v);
		} else {
			((RandomAccessFile) this.originObject).writeByte(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeShort(int)
	 */
	@Override
	public void writeShort(int v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeShort(v);
		} else {
			((RandomAccessFile) this.originObject).writeShort(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeChar(int)
	 */
	@Override
	public void writeChar(int v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeChar(v);
		} else {
			((RandomAccessFile) this.originObject).writeChar(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeInt(int)
	 */
	@Override
	public void writeInt(int v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeInt(v);
		} else {
			((RandomAccessFile) this.originObject).writeInt(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeLong(long)
	 */
	@Override
	public void writeLong(long v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeLong(v);
		} else {
			((RandomAccessFile) this.originObject).writeLong(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeFloat(float)
	 */
	@Override
	public void writeFloat(float v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeFloat(v);
		} else {
			((RandomAccessFile) this.originObject).writeFloat(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeDouble(double)
	 */
	@Override
	public void writeDouble(double v) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeDouble(v);
		} else {
			((RandomAccessFile) this.originObject).writeDouble(v);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeBytes(java.lang.String)
	 */
	@Override
	public void writeBytes(@Nonnull String s) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeBytes(s);
		} else {
			((RandomAccessFile) this.originObject).writeBytes(s);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeChars(java.lang.String)
	 */
	@Override
	public void writeChars(@Nonnull String s) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeChars(s);
		} else {
			((RandomAccessFile) this.originObject).writeChars(s);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataOutput#writeUTF(java.lang.String)
	 */
	@Override
	public void writeUTF(@Nonnull String s) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).writeUTF(s);
		} else {
			((RandomAccessFile) this.originObject).writeUTF(s);
		}
	}

	/**
	 * Read data
	 *
	 * @param b read buffer
	 * @return read length
	 * @throws IOException If the first byte cannot be read for any reason other than ends of current file, or if the random access file has been closed, or if some other I/O error occurs.
	 */
	public int read(byte[] b) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).read(b, Globals.INITIALIZE_INT_VALUE, b.length);
		} else {
			return ((RandomAccessFile) this.originObject).read(b, Globals.INITIALIZE_INT_VALUE, b.length);
		}
	}

	/**
	 * Read data
	 *
	 * @param b   read buffer
	 * @param off buffer offset
	 * @param len read length
	 * @return read length
	 * @throws IOException If the first byte cannot be read for any reason other than ends of current file, or if the random access file has been closed, or if some other I/O error occurs.
	 */
	public int read(byte[] b, int off, int len) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).read(b, off, len);
		} else {
			return ((RandomAccessFile) this.originObject).read(b, off, len);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readFully(byte[])
	 */
	@Override
	public void readFully(@Nonnull byte[] b) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).readFully(b);
		} else {
			((RandomAccessFile) this.originObject).readFully(b);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readFully(byte[], int, int)
	 */
	@Override
	public void readFully(@Nonnull byte[] b, int off, int len) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			((SmbRandomAccessFile) this.originObject).readFully(b, off, len);
		} else {
			((RandomAccessFile) this.originObject).readFully(b, off, len);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#skipBytes(int)
	 */
	@Override
	public int skipBytes(int n) throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).skipBytes(n);
		} else {
			return ((RandomAccessFile) this.originObject).skipBytes(n);
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readBoolean()
	 */
	@Override
	public boolean readBoolean() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readBoolean();
		} else {
			return ((RandomAccessFile) this.originObject).readBoolean();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readByte()
	 */
	@Override
	public byte readByte() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readByte();
		} else {
			return ((RandomAccessFile) this.originObject).readByte();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readUnsignedByte()
	 */
	@Override
	public int readUnsignedByte() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readUnsignedByte();
		} else {
			return ((RandomAccessFile) this.originObject).readUnsignedByte();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readShort()
	 */
	@Override
	public short readShort() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readShort();
		} else {
			return ((RandomAccessFile) this.originObject).readShort();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readUnsignedShort()
	 */
	@Override
	public int readUnsignedShort() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readUnsignedShort();
		} else {
			return ((RandomAccessFile) this.originObject).readUnsignedShort();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readChar()
	 */
	@Override
	public char readChar() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readChar();
		} else {
			return ((RandomAccessFile) this.originObject).readChar();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readInt()
	 */
	@Override
	public int readInt() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readInt();
		} else {
			return ((RandomAccessFile) this.originObject).readInt();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readLong()
	 */
	@Override
	public long readLong() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readLong();
		} else {
			return ((RandomAccessFile) this.originObject).readLong();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readFloat()
	 */
	@Override
	public float readFloat() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readFloat();
		} else {
			return ((RandomAccessFile) this.originObject).readFloat();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readDouble()
	 */
	@Override
	public double readDouble() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readDouble();
		} else {
			return ((RandomAccessFile) this.originObject).readDouble();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readLine()
	 */
	@Override
	public String readLine() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readLine();
		} else {
			return ((RandomAccessFile) this.originObject).readLine();
		}
	}

	/*
	 * (non-Javadoc)
	 * @see java.io.DataInput#readUTF()
	 */
	@Override
	@Nonnull
	public String readUTF() throws IOException {
		if (this.originObject instanceof SmbRandomAccessFile) {
			return ((SmbRandomAccessFile) this.originObject).readUTF();
		} else {
			return ((RandomAccessFile) this.originObject).readUTF();
		}
	}

	/**
	 * Open target file
	 *
	 * @param mode Open type(Read-Only/Read-Write)
	 * @throws FileNotFoundException if target file was not found
	 */
	private void openFile(String mode) throws FileNotFoundException {
		if (this.filePath.startsWith(Globals.SAMBA_PROTOCOL)) {
			try {
				this.originObject = FileUtils.getFile(this.filePath,
						FileUtils.smbAuthenticator(this.domain, this.userName, this.passWord));
			} catch (Exception e) {
				throw new FileNotFoundException("Open file error! File location: " + this.filePath);
			}
		} else {
			this.originObject = new RandomAccessFile(this.filePath, mode);
		}
	}
}
