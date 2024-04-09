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

package org.nervousync.office.excel.core;

import org.apache.poi.ss.usermodel.Workbook;
import org.nervousync.office.excel.ExcelWriter;
import org.nervousync.utils.IOUtils;
import org.nervousync.utils.LoggerUtils;

import java.io.IOException;
import java.io.OutputStream;

/**
 * <h2 class="en-US">Excel file writer abstract class</h2>
 * <h2 class="zh-CN">Excel文件写入器抽象类</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Nov 13, 2023 14:50:21 $
 */
public abstract class AbstractExcelWriter implements ExcelWriter {

    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    protected transient final LoggerUtils.Logger logger = LoggerUtils.getLogger(this.getClass());
    /**
     * <span class="en-US">Excel workbook instance object</span>
     * <span class="zh-CN">Excel工作簿实例对象</span>
     */
    protected final Workbook workbook;

    /**
     * <h3 class="en-US">Constructor method for excel writer</h3>
     * <h3 class="zh-CN">写入器构造方法</h3>
     *
     * @param workbook <span class="en-US">Excel workbook instance object</span>
     *                 <span class="zh-CN">Excel工作簿实例对象</span>
     */
    protected AbstractExcelWriter(final Workbook workbook) {
        this.workbook = workbook;
    }

    /**
     * <h3 class="en-US">Write data to the given output stream</h3>
     * <h3 class="zh-CN">将数据写入到给定的输出流中</h3>
     *
     * @param outputStream <span class="en-US">Data output stream instance object</span>
     *                     <span class="zh-CN">数据输出流实例对象</span>
     * @throws IOException <span class="en-US">An error occurred while writing data to the output stream</span>
     *                     <span class="zh-CN">写入数据到输出流时出错</span>
     */
    @Override
    public void write(final OutputStream outputStream) throws IOException {
        this.workbook.write(outputStream);
    }

    /**
     * <h3 class="en-US">Close current data writer</h3>
     * <h3 class="zh-CN">关闭当前数据写入器</h3>
     */
    @Override
    public final void close() {
        IOUtils.closeStream(this.workbook);
    }
}
