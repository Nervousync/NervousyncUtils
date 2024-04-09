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
package org.nervousync.beans.servlet.response;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.zip.GZIPInputStream;

import javax.net.ssl.HttpsURLConnection;

import org.nervousync.http.header.SimpleHeader;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.IOUtils;
import org.nervousync.commons.Globals;
import org.nervousync.utils.LoggerUtils;
import org.nervousync.utils.StringUtils;

/**
 * <h2 class="en-US">Response information define</h2>
 * <h2 class="zh-CN">网络响应信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.2 $ $Date: Nov 11, 2022 12:25:33 $
 */
public final class ResponseInfo {
    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());
    /**
	 * <span class="en-US">Response HTTP status code</span>
	 * <span class="zh-CN">响应的HTTP状态代码</span>
     */
    private int statusCode;
    /**
	 * <span class="en-US">Response header information map</span>
	 * <span class="zh-CN">响应头信息映射表</span>
     */
    private final Map<String, String> headerMaps = new HashMap<>();
    /**
	 * <span class="en-US">String value for http response header "Content-Type"</span>
	 * <span class="zh-CN">响应头"Content-Type"的字符串值</span>
     */
    private String contentType;
    /**
	 * <span class="en-US">Character encoding for http response data</span>
	 * <span class="zh-CN">响应数据使用的编码集</span>
     */
    private String charset = null;
    /**
	 * <span class="en-US">String value of response header "identified"</span>
	 * <span class="zh-CN">响应头"identified"的字符串值</span>
     */
    private String identifiedCode;
    /**
	 * <span class="en-US">Response content length</span>
	 * <span class="zh-CN">响应数据的长度</span>
     */
    private int contentLength;
    /**
	 * <span class="en-US">Response content binary data bytes</span>
	 * <span class="zh-CN">响应数据的二进制字节数组</span>
     */
    private byte[] responseContent;
    /**
     * <h3 class="en-US">Constructor for ResponseInfo</h3>
     * <span class="en-US">Parse response information from HttpResponse.ResponseInfo and ResponseBody input stream</span>
     * <h3 class="zh-CN">ResponseInfo的构造函数</h3>
     * <span class="zh-CN">从HttpResponse.ResponseInfo实例对象和响应体输入数据流中解析响应数据</span>
     *
     * @param responseInfo  <span class="en-US">Instance of HttpResponse.ResponseInfo</span>
     *                      <span class="zh-CN">HttpResponse.ResponseInfo实例对象</span>
     * @see java.net.http.HttpResponse.ResponseInfo
     * @param inputStream   <span class="en-US">ResponseBody input stream</span>
     *                      <span class="zh-CN">响应体输入数据流</span>
     */
    public ResponseInfo(final HttpResponse.ResponseInfo responseInfo, final InputStream inputStream) {
        this.statusCode = responseInfo.statusCode();
        responseInfo.headers().map().forEach((key, values) -> {
            if (key != null && values != null && !values.isEmpty()) {
                StringBuilder stringBuilder = new StringBuilder();
                for (String headerValue : values) {
                    stringBuilder.append(" ").append(headerValue);
                }
                this.headerMaps.put(key.toUpperCase(), stringBuilder.substring(1));
            }
        });
        this.contentType = this.headerMaps.get("CONTENT-TYPE");
        if (this.contentType != null && this.contentType.contains("charset=")) {
            this.charset = this.contentType.substring(this.contentType.indexOf("charset="));
            if (this.contentType.contains("\"")) {
                this.charset = this.charset.substring(0, this.charset.indexOf("\""));
            }
            this.charset = this.charset.substring(this.charset.indexOf("=") + 1);
            if (this.charset.contains(";")) {
                this.charset = this.charset.substring(0, this.charset.indexOf(";"));
            }
        }
        this.identifiedCode = this.headerMaps.get("IDENTIFIED");
        GZIPInputStream gzipInputStream = null;
        try {
            if (this.headerMaps.getOrDefault("CONTENT-ENCODING", Globals.DEFAULT_VALUE_STRING).contains("gzip")) {
                gzipInputStream = new GZIPInputStream(inputStream);
                this.responseContent = IOUtils.readBytes(gzipInputStream);
            } else {
                this.responseContent = IOUtils.readBytes(inputStream);
            }
        } catch (IOException e) {
            this.responseContent = new byte[0];
        } finally {
            IOUtils.closeStream(gzipInputStream);
            IOUtils.closeStream(inputStream);
        }
        this.contentLength = this.responseContent.length;
    }
    /**
     * <h3 class="en-US">Constructor for ResponseInfo</h3>
     * <span class="en-US">Parse response information from HttpURLConnection instance</span>
     * <h3 class="zh-CN">ResponseInfo的构造函数</h3>
     * <span class="zh-CN">从HttpURLConnection实例对象解析响应数据</span>
     *
     * @param urlConnection     <span class="en-US">Instance of HttpURLConnection</span>
     *                          <span class="zh-CN">HttpURLConnection实例对象</span>
     * @see java.net.HttpURLConnection
     */
    public ResponseInfo(final HttpURLConnection urlConnection) {
        InputStream inputStream = null;
        ByteArrayOutputStream byteArrayOutputStream = null;

        try {
            this.statusCode = urlConnection.getResponseCode();
            this.contentLength = urlConnection.getContentLength();
            if (this.statusCode == HttpsURLConnection.HTTP_OK) {
                this.contentType = urlConnection.getContentType();
                if (this.contentType != null
                        && this.contentType.contains("charset=")) {
                    this.charset = this.contentType.substring(this.contentType.indexOf("charset="));
                    if (this.contentType.contains("\"")) {
                        this.charset = this.charset.substring(0, this.charset.indexOf("\""));
                    }
                    this.charset = this.charset.substring(this.charset.indexOf("=") + 1);
                    if (this.charset.contains(";")) {
                        this.charset = this.charset.substring(0, this.charset.indexOf(";"));
                    }
                }

                inputStream = urlConnection.getInputStream();
                if (Optional.ofNullable(urlConnection.getContentEncoding())
                        .map(contentEncoding -> contentEncoding.toLowerCase().contains("gzip"))
                        .orElse(Boolean.FALSE)) {
                    inputStream = new GZIPInputStream(inputStream);
                }
            } else {
                inputStream = urlConnection.getErrorStream();
            }

            Map<String, List<String>> headerFields = urlConnection.getHeaderFields();
            if (headerFields != null && !headerFields.isEmpty()) {
                for (Map.Entry<String, List<String>> entry : headerFields.entrySet()) {
                    List<String> headerValues = entry.getValue();
                    if (entry.getKey() != null && headerValues != null && !headerValues.isEmpty()) {
                        StringBuilder stringBuilder = new StringBuilder();
                        for (String headerValue : headerValues) {
                            stringBuilder.append(" ").append(headerValue);
                        }
                        this.headerMaps.put(entry.getKey().toUpperCase(), stringBuilder.substring(1));
                    }
                }
            }

            byteArrayOutputStream = new ByteArrayOutputStream(Globals.DEFAULT_BUFFER_SIZE);

            byte[] buffer = new byte[Globals.DEFAULT_BUFFER_SIZE];

            if (inputStream != null) {
                int readLength;
                while ((readLength = inputStream.read(buffer)) != -1) {
                    byteArrayOutputStream.write(buffer, 0, readLength);
                }
            }

            this.responseContent = byteArrayOutputStream.toByteArray();

            if (this.charset == null) {
                String tempContent = new String(this.responseContent, Globals.DEFAULT_ENCODING);
                if (tempContent.contains("charset=")) {
                    this.charset = tempContent.substring(tempContent.indexOf("charset="));
                    this.charset = this.charset.substring(0, this.charset.indexOf("\""));
                    this.charset = this.charset.substring(this.charset.indexOf("=") + 1);
                    if (this.charset.contains(";")) {
                        this.charset = this.charset.substring(0, this.charset.indexOf(";"));
                    }
                } else {
                    this.charset = Globals.DEFAULT_ENCODING;
                }
            }

            this.identifiedCode = urlConnection.getHeaderField("identified");
        } catch (IOException e) {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Response_Data_Error", e);
            }
        } finally {
            IOUtils.closeStream(inputStream);
            IOUtils.closeStream(byteArrayOutputStream);
        }
    }
    /**
	 * <h3 class="en-US">Getter method for response HTTP status code</h3>
	 * <h3 class="zh-CN">响应的HTTP状态代码的Getter方法</h3>
     */
    public int getStatusCode() {
        return statusCode;
    }
    /**
	 * <h3 class="en-US">Getter method for response header map</h3>
	 * <h3 class="zh-CN">响应头信息映射表的Getter方法</h3>
     */
    public Map<String, String> getHeaderMaps() {
        return headerMaps;
    }
    /**
	 * <h3 class="en-US">Getter method for response content type</h3>
	 * <h3 class="zh-CN">响应头"Content-Type"字符串值的Getter方法</h3>
     */
    public String getContentType() {
        return contentType;
    }
    /**
	 * <h3 class="en-US">Getter method for response character encoding</h3>
	 * <h3 class="zh-CN">响应数据使用的编码集的Getter方法</h3>
     */
    public String getCharset() {
        return charset;
    }
    /**
	 * <h3 class="en-US">Getter method for string value of response header "identified"</h3>
	 * <h3 class="zh-CN">响应头"identified"字符串值的Getter方法</h3>
     */
    public String getIdentifiedCode() {
        return identifiedCode;
    }
    /**
	 * <h3 class="en-US">Getter method for response content length</h3>
	 * <h3 class="zh-CN">响应数据的长度的Getter方法</h3>
     */
    public int getContentLength() {
        return contentLength;
    }
    /**
	 * <h3 class="en-US">Getter method for response content binary data bytes</h3>
	 * <h3 class="zh-CN">响应数据的二进制字节数组的Getter方法</h3>
     */
    public byte[] getResponseContent() {
        return responseContent == null ? new byte[0] : responseContent.clone();
    }
    /**
	 * <h3 class="en-US">Parse response data to the instance list of given class type</h3>
	 * <h3 class="zh-CN">转换响应数据为指定类型的对象列表</h3>
     *
     * @param clazz     <span class="en-US">Class type</span>
     *                  <span class="zh-CN">数据对象类</span>
     * @param <T>       <span class="en-US">Template type of list</span>
     *                  <span class="zh-CN">列表的参数化类型</span>
     *
     * @return  <span class="en-US">instance list of given class type, or empty list if has error</span>
     *          <span class="zh-CN">数据对象列表，当有异常时返回空列表</span>
     */
    public <T> List<T> parseList(final Class<T> clazz) {
        return StringUtils.stringToList(this.parseString(), this.charset, clazz);
    }
    /**
	 * <h3 class="en-US">Parse response data to the instance of given class type</h3>
	 * <h3 class="zh-CN">转换响应数据为指定类型的对象</h3>
     *
     * @param clazz     <span class="en-US">Class type</span>
     *                  <span class="zh-CN">数据对象类</span>
     * @param <T>       <span class="en-US">Template type of list</span>
     *                  <span class="zh-CN">列表的参数化类型</span>
     *
     * @return  <span class="en-US">instance of given class type, or null if has error</span>
     *          <span class="zh-CN">转换后的数据实例对象，当有异常时返回null</span>
     */
    public <T> T parseObject(final Class<T> clazz) {
        if (StringUtils.notBlank(this.contentType)
                && (this.contentType.toLowerCase().contains("xml")
                        || this.contentType.toLowerCase().contains("json")
                        || this.contentType.toLowerCase().contains("yaml")
                        || this.contentType.toLowerCase().contains("yml"))) {
            return StringUtils.stringToObject(this.parseString(), clazz);
        }
        ByteArrayInputStream byteArrayInputStream = null;
        ObjectInputStream objectInputStream = null;

        try {
            byteArrayInputStream = new ByteArrayInputStream(this.responseContent);
            objectInputStream = new ObjectInputStream(byteArrayInputStream);
            return clazz.cast(objectInputStream.readObject());
        } catch (Exception e) {
            if (this.logger.isDebugEnabled()) {
                this.logger.debug("Convert_Object_Error", e);
            }
            return null;
        } finally {
            IOUtils.closeStream(byteArrayInputStream);
            IOUtils.closeStream(objectInputStream);
        }
    }
    /**
	 * <h3 class="en-US">Parse response data to string</h3>
	 * <h3 class="zh-CN">转换响应数据为字符串</h3>
     *
     * @return  <span class="en-US">String value of response data or empty string if an UnsupportedEncodingException occurs</span>
     *          <span class="zh-CN">响应数据字符串，当有UnsupportedEncodingException异常时返回空字符串</span>
     */
    public String parseString() {
        String charsetName = StringUtils.isEmpty(this.charset) ? Globals.DEFAULT_ENCODING : this.charset;
        try {
            String string = new String(this.getResponseContent(), charsetName);
            while (string.charAt(string.length() - 1) == '\n') {
                string = string.substring(0, string.length() - 1);
            }
            while (string.charAt(string.length() - 1) == '\r') {
                string = string.substring(0, string.length() - 1);
            }
            return string;
        } catch (UnsupportedEncodingException e) {
            this.logger.error("Response_Data_Error", e);
            return Globals.DEFAULT_VALUE_STRING;
        }
    }
    /**
	 * <h3 class="en-US">Parse response data to local file and save to target path</h3>
	 * <h3 class="zh-CN">转换响应数据为文件，并写入数据到目标地址</h3>
     *
     * @param savePath  <span class="en-US">Target save path</span>
     *                  <span class="zh-CN">目标地址</span>
     *
     * @return  <span class="en-US">Instance of java.io.File</span>
     *          <span class="zh-CN">java.io.File实例对象</span>
     * @throws FileNotFoundException
	 * <span class="en-US">If an error occurs when save binary data to target path</span>
	 * <span class="zh-CN">当写入数据到目标地址时捕获异常</span>
     */
    public File parseFile(final String savePath) throws FileNotFoundException {
        return FileUtils.saveFile(this.getResponseContent(), savePath) ? FileUtils.getFile(savePath) : null;
    }
    /**
	 * <h3 class="en-US">Retrieve response header value by given header name</h3>
	 * <h3 class="zh-CN">根据给定的响应头键值读取对应的数据值</h3>
     *
     * @param headerName    <span class="en-US">Response header name</span>
     *                      <span class="zh-CN">响应头键值</span>
     *
     * @return  <span class="en-US">Response header value or empty string if header name not exists</span>
     *          <span class="zh-CN">响应头数据值，如果数据不存在则返回空字符串</span>
     */
    public String getHeader(final String headerName) {
        return this.headerMaps.getOrDefault(headerName.toUpperCase(), Globals.DEFAULT_VALUE_STRING);
    }
    /**
	 * <h3 class="en-US">Retrieve response header list</h3>
	 * <h3 class="zh-CN">获取响应头数据列表</h3>
     *
     * @return  <span class="en-US">Response header list. Convert key-value to SimpleHeader instance</span>
     *          <span class="zh-CN">响应头数据列表，转换键-值为SimpleHeader实例对象</span>
     */
    public List<SimpleHeader> headerList() {
        List<SimpleHeader> headerList = new ArrayList<>();
        for (Map.Entry<String, String> entry : this.headerMaps.entrySet()) {
            headerList.add(new SimpleHeader(entry.getKey(), entry.getValue()));
        }
        return headerList;
    }
}
