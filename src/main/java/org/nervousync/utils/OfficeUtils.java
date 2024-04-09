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

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.openxml4j.exceptions.InvalidFormatException;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.streaming.SXSSFWorkbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.utils.DataInvalidException;
import org.nervousync.office.excel.ExcelReader;
import org.nervousync.office.excel.ExcelWriter;
import org.nervousync.office.excel.impl.EventModelReaderImpl;
import org.nervousync.office.excel.impl.ExcelWriterImpl;
import org.nervousync.office.excel.impl.UserModelReaderImpl;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * <h2 class="en-US">Office Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Read the total number of records from Excel file</ul>
 *     <ul>Read details of Excel file</ul>
 *     <ul>Write data to Excel file</ul>
 * </span>
 * <h2 class="zh-CN">Office工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>读取Excel文件的总记录数</ul>
 *     <ul>读取Excel文件的详细信息</ul>
 *     <ul>写入数据到Excel文件</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 13, 2023 15:13:37 $
 */
public final class OfficeUtils {

    /**
     * <span class="en-US">Multilingual supported logger instance</span>
     * <span class="zh-CN">多语言支持的日志对象</span>
     */
    private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(OfficeUtils.class);

    private final static int DEFAULT_ROW_ACCESS_WINDOW_SIZE = 100;
    public static final String EXCEL_FILE_EXT_NAME_2003 = "xls";
    public static final String EXCEL_FILE_EXT_NAME_2007 = "xlsx";

    private OfficeUtils() {
    }

    /**
     * <h3 class="en-US">Get the maximum number of records in all data sheets</h3>
     * <h3 class="zh-CN">获取所有数据表的最大记录数</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @return <span class="en-US">Mapping table between data table name and maximum number of sheets</span>
     * <span class="zh-CN">数据表名与最大记录数的映射表</span>
     */
    public static Map<String, Integer> excelRowsCount(final String filePath) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.maxRows();
        } catch (Exception e) {
            return new HashMap<>();
        }
    }

    /**
     * <h3 class="en-US">Get the maximum number of records based on the given data file path and sheet name</h3>
     * <h3 class="zh-CN">根据给定的文件地址和数据表名称获取最大记录数</h3>
     *
     * @param filePath  <span class="en-US">File storage path</span>
     *                  <span class="zh-CN">文件存储路径</span>
     * @param sheetName <span class="en-US">Data sheet name</span>
     *                  <span class="zh-CN">数据表名称</span>
     * @return <span class="en-US">Maximum number of records read</span>
     * <span class="zh-CN">读取的最大记录数</span>
     */
    public static int excelRowsCount(final String filePath, final String sheetName) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.maxRow(sheetName);
        } catch (Exception e) {
            return Globals.DEFAULT_VALUE_INT;
        }
    }

    /**
     * <h3 class="en-US">Checks whether the given data sheet names exists in the given data file path</h3>
     * <h3 class="zh-CN">检查给定的文件地址中数据表名是否存在</h3>
     *
     * @param filePath   <span class="en-US">File storage path</span>
     *                   <span class="zh-CN">文件存储路径</span>
     * @param sheetNames <span class="en-US">Data sheet names to check</span>
     *                   <span class="zh-CN">要检查的数据表名称</span>
     * @return <span class="en-US">Check result</span>
     * <span class="zh-CN">检查结果</span>
     */
    public static boolean sheetExists(final String filePath, final String... sheetNames) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.checkExists(sheetNames);
        } catch (Exception e) {
            return Boolean.FALSE;
        }
    }

    /**
     * <h3 class="en-US">Read data from all data sheets based on the given file path</h3>
     * <h3 class="zh-CN">根据给定的文件地址读取所有数据表中的数据</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @return <span class="en-US">Mapping table of read data sheet name and data list</span>
     * <span class="zh-CN">读取的数据表名和数据列表的映射表</span>
     */
    public static Map<String, List<List<String>>> readExcel(final String filePath) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.read();
        } catch (Exception e) {
            return new HashMap<>();
        }
    }

    /**
     * <h3 class="en-US">Read data from all data sheets based on the given file path, starting and ending row numbers</h3>
     * <h3 class="zh-CN">根据给定的文件地址、起始、终止行号读取所有数据表中的数据</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @param beginRow <span class="en-US">Begin row number</span>
     *                 <span class="zh-CN">起始行号</span>
     * @param endRow   <span class="en-US">End row number</span>
     *                 <span class="zh-CN">终止行号</span>
     * @return <span class="en-US">Mapping table of read data sheet name and data list</span>
     * <span class="zh-CN">读取的数据表名和数据列表的映射表</span>
     */
    public static Map<String, List<List<String>>> readExcel(final String filePath, final int beginRow, final int endRow) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.read(beginRow, endRow);
        } catch (Exception e) {
            return new HashMap<>();
        }
    }

    /**
     * <h3 class="en-US">Read data based on the given file path, data sheet name</h3>
     * <h3 class="zh-CN">根据给定的文件地址、数据表名称读取数据</h3>
     *
     * @param filePath  <span class="en-US">File storage path</span>
     *                  <span class="zh-CN">文件存储路径</span>
     * @param sheetName <span class="en-US">Data sheet name</span>
     *                  <span class="zh-CN">数据表名称</span>
     * @return <span class="en-US">Read data list</span>
     * <span class="zh-CN">读取的数据列表</span>
     */
    public static List<List<String>> readExcel(final String filePath, final String sheetName) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.read(sheetName);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    /**
     * <h3 class="en-US">Read data based on the given file path, data sheet name, starting and ending row numbers</h3>
     * <h3 class="zh-CN">根据给定的文件地址、数据表名称和起始、终止行号读取数据</h3>
     *
     * @param filePath  <span class="en-US">File storage path</span>
     *                  <span class="zh-CN">文件存储路径</span>
     * @param sheetName <span class="en-US">Data sheet name</span>
     *                  <span class="zh-CN">数据表名称</span>
     * @param beginRow  <span class="en-US">Begin row number</span>
     *                  <span class="zh-CN">起始行号</span>
     * @param endRow    <span class="en-US">End row number</span>
     *                  <span class="zh-CN">终止行号</span>
     * @return <span class="en-US">Read data list</span>
     * <span class="zh-CN">读取的数据列表</span>
     */
    public static List<List<String>> readExcel(final String filePath, final String sheetName,
                                               final int beginRow, final int endRow) {
        try (ExcelReader excelReader = newReader(filePath)) {
            return excelReader.read(sheetName, beginRow, endRow);
        } catch (Exception e) {
            return new ArrayList<>();
        }
    }

    /**
     * <h3 class="en-US">Generate an Excel workbook writer instance object based on the given file address</h3>
     * <h3 class="zh-CN">根据给定文件地址生成Excel工作簿写入器实例对象</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @return <span class="en-US">Excel reader instance object</span>
     * <span class="zh-CN">Excel读取器实例对象</span>
     * @throws DataInvalidException <span class="en-US">If the file format is incorrect</span>
     *                              <span class="zh-CN">如果文件格式不正确</span>
     */
    public static ExcelWriter newWriter(final String filePath) throws DataInvalidException {
        return new ExcelWriterImpl(filePath);
    }

    /**
     * <h3 class="en-US">Open the Excel workbook at the given address</h3>
     * <h3 class="zh-CN">打开给定地址的Excel工作簿</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @return <span class="en-US">Workbook instance object</span>
     * <span class="zh-CN">工作簿实例对象</span>
     * @throws DataInvalidException <span class="en-US">If the file format is incorrect</span>
     *                              <span class="zh-CN">如果文件格式不正确</span>
     */
    public static Workbook openWorkbook(final String filePath) throws DataInvalidException {
        String fileExtName = StringUtils.getFilenameExtension(filePath).toLowerCase();
        if (FileUtils.isExists(filePath)) {
            try (InputStream inputStream = FileUtils.getURL(filePath).openStream()) {
                switch (fileExtName) {
                    case EXCEL_FILE_EXT_NAME_2003:
                        return new HSSFWorkbook(inputStream);
                    case EXCEL_FILE_EXT_NAME_2007:
                        return new XSSFWorkbook(inputStream);
                    default:
                        throw new DataInvalidException(0x000000AE0001L, "Office_Ext_Name_Invalid", fileExtName);
                }
            } catch (IOException e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Stack_Message_Error", e);
                }
            }
        }
        throw new DataInvalidException(0x000000AE0002L, "Office_Excel_File_Not_Exists", filePath);
    }

    /**
     * <h3 class="en-US">Create a new Excel workbook</h3>
     * <h3 class="zh-CN">创建新的Excel工作簿</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @return <span class="en-US">Workbook instance object</span>
     * <span class="zh-CN">工作簿实例对象</span>
     * @throws DataInvalidException <span class="en-US">If the file format is incorrect</span>
     *                              <span class="zh-CN">如果文件格式不正确</span>
     */
    public static Workbook createWorkbook(final String filePath) throws DataInvalidException {
        String fileExtName = StringUtils.getFilenameExtension(filePath).toLowerCase();
        switch (fileExtName) {
            case EXCEL_FILE_EXT_NAME_2003:
                return new HSSFWorkbook();
            case EXCEL_FILE_EXT_NAME_2007:
                return new SXSSFWorkbook(DEFAULT_ROW_ACCESS_WINDOW_SIZE);
            default:
                throw new DataInvalidException(0x000000AE0001L, "Office_Ext_Name_Invalid", fileExtName);
        }
    }

    /**
     * <h3 class="en-US">Generate an Excel workbook reader instance object based on the given file address</h3>
     * <h3 class="zh-CN">根据给定文件地址生成Excel工作簿读取器实例对象</h3>
     *
     * @param filePath <span class="en-US">File storage path</span>
     *                 <span class="zh-CN">文件存储路径</span>
     * @return <span class="en-US">Excel reader instance object</span>
     * <span class="zh-CN">Excel读取器实例对象</span>
     * @throws IOException            <span class="en-US">If an exception occurs while reading the file</span>
     *                                <span class="zh-CN">如果读取文件时出现异常</span>
     * @throws InvalidFormatException <span class="en-US">If the file format is incorrect</span>
     *                                <span class="zh-CN">如果文件格式不正确</span>
     * @throws DataInvalidException   <span class="en-US">If the file format is incorrect</span>
     *                                <span class="zh-CN">如果文件格式不正确</span>
     */
    private static ExcelReader newReader(final String filePath)
            throws IOException, InvalidFormatException, DataInvalidException {
        String fileExtName = StringUtils.getFilenameExtension(filePath).toLowerCase();
        switch (fileExtName) {
            case EXCEL_FILE_EXT_NAME_2003:
                return new UserModelReaderImpl(filePath);
            case EXCEL_FILE_EXT_NAME_2007:
                return new EventModelReaderImpl(filePath);
            default:
                throw new DataInvalidException(0x000000AE0001L, "Office_Ext_Name_Invalid", fileExtName);
        }
    }
}
