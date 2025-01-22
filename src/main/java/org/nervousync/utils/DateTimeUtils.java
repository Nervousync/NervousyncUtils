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

import java.text.DateFormat;
import java.text.ParseException;
import java.time.*;
import java.time.chrono.ChronoZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.FormatStyle;
import java.time.temporal.TemporalAdjusters;
import java.util.*;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * <h2 class="en-US">Date time utilities</h2>
 * <h2 class="zh-CN">日期时间工具集</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 13, 2010 11:15:20 $
 */
public final class DateTimeUtils {

	/**
	 * <span class="en-US">Static value for date format yyyy/MM/dd</span>
	 * <span class="zh-CN">日期格式 yyyy/MM/dd 的静态值</span>
	 */
	public static final String DEFAULT_DATE_PATTERN = "yyyy/MM/dd";
	/**
	 * <span class="en-US">Static value for date format yyyy-MM-dd'T'HH:mm:ss</span>
	 * <span class="zh-CN">日期格式 yyyy-MM-dd'T'HH:mm:ss 的静态值</span>
	 */
	public static final String DEFAULT_DATETIME_PATTERN_ISO8601 = "yyyy-MM-dd'T'HH:mm:ss";
	/**
	 * <span class="en-US">Static value for date format EEE, dd MMM yyyy HH:mm:ss 'GMT'. Using for generated Response header: Last-Modified</span>
	 * <span class="zh-CN">日期格式 EEE, dd MMM yyyy HH:mm:ss 'GMT' 的静态值。用于生成的响应头：Last-Modified</span>
	 */
	public static final String LAST_MODIFIED_DATETIME_PATTERN = "EEE, dd MMM yyyy HH:mm:ss 'GMT'";
	/**
	 * <span class="en-US">Static value for date format EEE, dd-MMM-yyyy HH:mm:ss 'GMT'</span>
	 * <span class="zh-CN">日期格式 EEE, dd-MMM-yyyy HH:mm:ss 'GMT' 的静态值</span>
	 */
	public static final String COOKIE_DATETIME_PATTERN = "EEE, dd-MMM-yyyy HH:mm:ss 'GMT'";

	/**
	 * <span class="en-US">Static DateTimeFormatter instance for date format yyyy/MM/dd</span>
	 * <span class="zh-CN">静态DateTimeFormatter实例，使用的日期格式：yyyy/MM/dd</span>
	 */
	public static final DateTimeFormatter DEFAULT_ISO8601_PATTERN =
			DateTimeFormatter.ofPattern(DEFAULT_DATETIME_PATTERN_ISO8601);
	/**
	 * <span class="en-US">Static DateTimeFormatter instance for the site map date format</span>
	 * <span class="zh-CN">静态DateTimeFormatter实例，使用SiteMap的日期格式</span>
	 */
	public static final DateTimeFormatter DEFAULT_SITE_MAP_PATTERN =
			DateTimeFormatter.ofPattern(DEFAULT_DATETIME_PATTERN_ISO8601 + DateTimeUtils.getTimeZone());
	/**
	 * <span class="en-US">Static DateTimeFormatter instance for date format yyyyMMdd</span>
	 * <span class="zh-CN">静态DateTimeFormatter实例，使用的日期格式：yyyyMMdd</span>
	 */
	public static final DateTimeFormatter DEFAULT_INT_PATTERN = DateTimeFormatter.ofPattern("yyyyMMdd");
	/**
	 * <span class="en-US">Static DateTimeFormatter instance for date format HHmmssSSS</span>
	 * <span class="zh-CN">静态DateTimeFormatter实例，使用的日期格式：HHmmssSSS</span>
	 */
	public static final DateTimeFormatter DEFAULT_TIME_PATTERN = DateTimeFormatter.ofPattern("HHmmssSSS");
	/**
	 * <span class="en-US">Static DateTimeFormatter instance for date format yyyyMMddHHmm</span>
	 * <span class="zh-CN">静态DateTimeFormatter实例，使用的日期格式：yyyyMMddHHmm</span>
	 */
	public static final DateTimeFormatter DEFAULT_LONG_PATTERN = DateTimeFormatter.ofPattern("yyyyMMddHHmm");
	/**
	 * <span class="en-US">Current UTC Clock Instance</span>
	 * <span class="zh-CN">当前UTC时钟实例对象</span>
	 */
	private static final UTCClock UTC_CLOCK = new UTCClock();

	/**
	 * <h3 class="en-US">Private constructor for DateTimeUtils</h3>
	 * <h3 class="zh-CN">日期时间工具集的私有构造方法</h3>
	 */
	private DateTimeUtils() {
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with ISO8601 format</h3>
	 * <h3 class="zh-CN">使用ISO8601标准格式化给定的日期实例对象</h3>
	 *
	 * @param date <span class="en-US">date instance</span>
	 *             <span class="zh-CN">日期实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDateForSiteMap(final Date date) {
		if (date == null) {
			return Globals.DEFAULT_VALUE_STRING;
		}
		return formatDate(date, DEFAULT_SITE_MAP_PATTERN);
	}

	/**
	 * <h3 class="en-US">Parses given string according to <code>java.util.Date</code> with ISO8601 format</h3>
	 * <h3 class="zh-CN">使用ISO8601标准解析给定日期字符串为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 */
	public static Date parseSiteMapDate(final String string) {
		return parseDate(string, DEFAULT_DATETIME_PATTERN_ISO8601 + DateTimeUtils.getTimeZone());
	}

	/**
	 * <h3 class="en-US">Formats current GMT datetime, according to string, with vCard format</h3>
	 * <h3 class="zh-CN">使用vCard标准格式化当前的GMT时间</h3>
	 *
	 * @return <span class="en-US">formatted date time string and ending character is 'Z'</span>
	 * <span class="zh-CN">格式化后的日期时间字符串并以字符'Z'结尾</span>
	 */
	public static String formatGMTDateForVCard() {
		return ZonedDateTime.ofInstant(Instant.now(), ZoneId.of("+00:00"))
				.format(DateTimeFormatter.ofPattern(DEFAULT_DATETIME_PATTERN_ISO8601 + "'Z'"));
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with vCard format</h3>
	 * <h3 class="zh-CN">使用vCard标准格式化给定的日期实例对象</h3>
	 *
	 * @param date <span class="en-US">date instance</span>
	 *             <span class="zh-CN">日期实例对象</span>
	 * @return <span class="en-US">formatted date time string and ending character is 'Z'</span>
	 * <span class="zh-CN">格式化后的日期时间字符串并以字符'Z'结尾</span>
	 */
	public static String formatDateForVCard(final Date date) {
		if (date == null) {
			return null;
		}
		return formatDate(date, DEFAULT_ISO8601_PATTERN) + "Z";
	}

	/**
	 * <h3 class="en-US">Parses given GMT date time string according to <code>java.util.Date</code></h3>
	 * <h3 class="zh-CN">解析给定的GMT日期字符串为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 */
	public static Date parseGMTDate(final String string) {
		return parseDate(string, COOKIE_DATETIME_PATTERN);
	}

	/**
	 * <h3 class="en-US">Parses given string according to <code>java.util.Date</code> using given date time format</h3>
	 * <h3 class="zh-CN">使用给定的日期时间格式解析给定的日期字符串为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param format <span class="en-US">date time format</span>
	 *               <span class="zh-CN">日期时间格式</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 */
	public static Date parseDate(final String string, final String format) {
		if (StringUtils.isEmpty(string)) {
			return null;
		}
		String datetimeFormat = StringUtils.isEmpty(format) ? DEFAULT_DATE_PATTERN : format;
		return Date.from(LocalDate.parse(string, DateTimeFormatter.ofPattern(datetimeFormat))
				.atStartOfDay(ZoneId.systemDefault()).toInstant());
	}

	/**
	 * <h3 class="en-US">Converts the given UTC timestamp to local time</h3>
	 * <h3 class="zh-CN">转换给定的UTC时间戳为本地时间</h3>
	 *
	 * @param utcTime <span class="en-US">UTC timestamp (unit: milliseconds)</span>
	 *                <span class="zh-CN">UTC时间戳（单位：毫秒）</span>
	 * @return <span class="en-US">Converted LocalDateTime instance</span>
	 * <span class="zh-CN">转换后的本地日期时间实例对象</span>
	 */
	public static LocalDateTime utcToLocal(final long utcTime) {
		if (utcTime < 0L) {
			return null;
		}
		TimeZone timeZone = Calendar.getInstance().getTimeZone();
		return Instant.ofEpochMilli(utcTime + timeZone.getRawOffset()).atZone(timeZone.toZoneId()).toLocalDateTime();
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with last modify format</h3>
	 * <h3 class="zh-CN">使用Last-Modify标准格式化给定的日期实例对象</h3>
	 *
	 * @param date <span class="en-US">date instance</span>
	 *             <span class="zh-CN">日期实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String lastModified(final Date date) {
		return formatDate(date, DateTimeFormatter.ofPattern(LAST_MODIFIED_DATETIME_PATTERN));
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with last modify format</h3>
	 * <h3 class="zh-CN">使用Last-Modify标准格式化给定的日期实例对象</h3>
	 *
	 * @param timeMilliseconds <span class="en-US">date time milliseconds</span>
	 *                         <span class="zh-CN">日期时间的毫秒数</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String lastModified(final long timeMilliseconds) {
		return formatDate(new Date(timeMilliseconds), DateTimeFormatter.ofPattern(LAST_MODIFIED_DATETIME_PATTERN));
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with system format</h3>
	 * <h3 class="zh-CN">使用系统格式化给定的日期实例对象</h3>
	 *
	 * @param date <span class="en-US">date instance</span>
	 *             <span class="zh-CN">日期实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDate(final Date date) {
		return formatDate(date, DateTimeFormatter.ofLocalizedDateTime(FormatStyle.FULL));
	}

	/**
	 * <h3 class="en-US">Formats current date, according to int with "yyyyMMdd" format</h3>
	 * <h3 class="zh-CN">使用"yyyyMMdd"格式化当前日期时间为数字</h3>
	 *
	 * @return <span class="en-US">formatted date time int value</span>
	 * <span class="zh-CN">格式化后的日期时间数字格式</span>
	 */
	public static int currentDate() {
		return Integer.parseInt(LocalDate.now().format(DEFAULT_INT_PATTERN));
	}

	/**
	 * <h3 class="en-US">Formats current UTC date according to int with "yyyyMMdd" format</h3>
	 * <h3 class="zh-CN">使用"yyyyMMdd"格式化当前日期时间为数字</h3>
	 *
	 * @return <span class="en-US">formatted UTC date time int value</span>
	 * <span class="zh-CN">格式化后的UTC日期时间数字格式</span>
	 */
	public static int currentUTCDate() {
		return Integer.parseInt(DateTimeUtils.formatDate(new Date(currentUTCTimeMillis()), DEFAULT_INT_PATTERN));
	}

	/**
	 * <h3 class="en-US">Format and calculate date according to int with "yyyyMMdd" format by given expire time</h3>
	 * <h3 class="zh-CN">使用"yyyyMMdd"格式化并计算过期日期时间为数字</h3>
	 *
	 * @param expireTime <span class="en-US">Expire time milliseconds</span>
	 *                   <span class="zh-CN">过期时间的毫秒数</span>
	 * @return <span class="en-US">formatted and calculated date time int value</span>
	 * <span class="zh-CN">格式化并计算后的日期时间数字格式</span>
	 */
	public static int expireDay(final long expireTime) {
		return Integer.parseInt(DateTimeUtils.formatDate(new Date(currentTimeMillis() + expireTime),
				DEFAULT_INT_PATTERN));
	}

	/**
	 * <h3 class="en-US">Format and calculate UTC date according to int with "yyyyMMdd" format by given expire time</h3>
	 * <h3 class="zh-CN">使用"yyyyMMdd"格式化并计算过期UTC日期时间为数字</h3>
	 *
	 * @param expireTime <span class="en-US">Expire time milliseconds</span>
	 *                   <span class="zh-CN">过期时间的毫秒数</span>
	 * @return <span class="en-US">formatted and calculated UTC date time int value</span>
	 * <span class="zh-CN">格式化并计算后的UTC日期时间数字格式</span>
	 */
	public static int expireUTCDay(long expireTime) {
		return Integer.parseInt(DateTimeUtils.formatDate(new Date(currentUTCTimeMillis() + expireTime),
				DEFAULT_INT_PATTERN));
	}

	/**
	 * <h3 class="en-US">Format and calculate date according to int with "yyyyMMdd" format by given month count</h3>
	 * <h3 class="zh-CN">使用"yyyyMMdd"格式化并计算过期日期时间为数字</h3>
	 *
	 * @param monthCount <span class="en-US">Expire month count</span>
	 *                   <span class="zh-CN">过期月份计数</span>
	 * @return <span class="en-US">formatted and calculated date time int value</span>
	 * <span class="zh-CN">格式化并计算后的日期时间数字格式</span>
	 */
	public static long expireMonth(int monthCount) {
		return currentTimeMillis() + (expireDayCount(monthCount) * 24 * 60 * 60 * 1000L);
	}

	/**
	 * <h3 class="en-US">Format and calculate UTC date according to int with "yyyyMMdd" format by given month count</h3>
	 * <h3 class="zh-CN">使用"yyyyMMdd"格式化并计算过期UTC日期时间为数字</h3>
	 *
	 * @param monthCount <span class="en-US">Expire month count</span>
	 *                   <span class="zh-CN">过期月份计数</span>
	 * @return <span class="en-US">formatted and calculated UTC date time int value</span>
	 * <span class="zh-CN">格式化并计算后的UTC日期时间数字格式</span>
	 */
	public static long expireUTCMonth(int monthCount) {
		return currentUTCTimeMillis() + (expireDayCount(monthCount) * 24 * 60 * 60 * 1000L);
	}

	/**
	 * <h3 class="en-US">Formats current date, according to int with "yyyyMMddHHmm" format</h3>
	 * <h3 class="zh-CN">使用"yyyyMMddHHmm"格式化当前日期时间为数字</h3>
	 *
	 * @return <span class="en-US">formatted date time int value</span>
	 * <span class="zh-CN">格式化后的日期时间数字格式</span>
	 */
	public static long currentTime() {
		return Long.parseLong(formatDate(new Date(currentTimeMillis()), DEFAULT_LONG_PATTERN));
	}

	/**
	 * <h3 class="en-US">Formats current UTC date according to int with "yyyyMMddHHmm" format</h3>
	 * <h3 class="zh-CN">使用"yyyyMMddHHmm"格式化当前UTC日期时间为数字</h3>
	 *
	 * @return <span class="en-US">formatted date time int value</span>
	 * <span class="zh-CN">格式化后的日期时间数字格式</span>
	 */
	public static long currentUTCTime() {
		return Long.parseLong(formatDate(new Date(currentUTCTimeMillis()), DEFAULT_LONG_PATTERN));
	}

	/**
	 * <h3 class="en-US">Read current year number</h3>
	 * <h3 class="zh-CN">读取当前年份</h3>
	 *
	 * @return <span class="en-US">Current Year</span>
	 * <span class="zh-CN">当前年份</span>
	 */
	public static int currentYear() {
		return Calendar.getInstance().get(Calendar.YEAR);
	}

	/**
	 * <h3 class="en-US">Read current month number</h3>
	 * <h3 class="zh-CN">读取当前月份</h3>
	 *
	 * @return <span class="en-US">Current month</span>
	 * <span class="zh-CN">当前月份</span>
	 */
	public static int currentMonth() {
		return Calendar.getInstance().get(Calendar.MONTH) + 1;
	}

	/**
	 * <h3 class="en-US">Read current-day number</h3>
	 * <h3 class="zh-CN">读取当前日期</h3>
	 *
	 * @return <span class="en-US">Current day</span>
	 * <span class="zh-CN">当前日期</span>
	 */
	public static int currentDay() {
		return Calendar.getInstance().get(Calendar.DAY_OF_MONTH);
	}

	/**
	 * <h3 class="en-US">Read current year hour</h3>
	 * <h3 class="zh-CN">读取当前小时</h3>
	 *
	 * @return <span class="en-US">Current hour</span>
	 * <span class="zh-CN">当前小时</span>
	 */
	public static int currentHour() {
		return Calendar.getInstance().get(Calendar.HOUR_OF_DAY);
	}

	/**
	 * <h3 class="en-US">Read current year minute</h3>
	 * <h3 class="zh-CN">读取当前分钟</h3>
	 *
	 * @return <span class="en-US">Current minute</span>
	 * <span class="zh-CN">当前分钟</span>
	 */
	public static int currentMinute() {
		return Calendar.getInstance().get(Calendar.MINUTE);
	}

	/**
	 * <h3 class="en-US">Calculate day count of given year and month</h3>
	 * <h3 class="zh-CN">计算给定的年份和月份有多少天</h3>
	 *
	 * @param year  <span class="en-US">Given year</span>
	 *              <span class="zh-CN">给定的年份</span>
	 * @param month <span class="en-US">Given month</span>
	 *              <span class="zh-CN">给定的月份</span>
	 * @return <span class="en-US">Day count</span>
	 * <span class="zh-CN">天数</span>
	 */
	public static int getDaysOfMonth(final int year, final int month) {
		Calendar calendar = Calendar.getInstance();
		switch (month) {
			case 1:
				calendar.set(year, Calendar.JANUARY, 1);
				break;
			case 2:
				calendar.set(year, Calendar.FEBRUARY, 1);
				break;
			case 3:
				calendar.set(year, Calendar.MARCH, 1);
				break;
			case 4:
				calendar.set(year, Calendar.APRIL, 1);
				break;
			case 5:
				calendar.set(year, Calendar.MAY, 1);
				break;
			case 6:
				calendar.set(year, Calendar.JUNE, 1);
				break;
			case 7:
				calendar.set(year, Calendar.JULY, 1);
				break;
			case 8:
				calendar.set(year, Calendar.AUGUST, 1);
				break;
			case 9:
				calendar.set(year, Calendar.SEPTEMBER, 1);
				break;
			case 10:
				calendar.set(year, Calendar.OCTOBER, 1);
				break;
			case 11:
				calendar.set(year, Calendar.NOVEMBER, 1);
				break;
			case 12:
				calendar.set(year, Calendar.DECEMBER, 1);
				break;
			default:
				return Globals.DEFAULT_VALUE_INT;
		}
		return calendar.getActualMaximum(Calendar.DAY_OF_MONTH);
	}

	/**
	 * <h3 class="en-US">Converts input time from Java to DOS format</h3>
	 * <h3 class="zh-CN">转换给定的Java日期为DOS日期</h3>
	 *
	 * @param time <span class="en-US">Given time value</span>
	 *             <span class="zh-CN">给定的时间值</span>
	 * @return <span class="en-US">time in DOS format</span>
	 * <span class="zh-CN">DOS格式的日期</span>
	 */
	public static long toDosTime(final long time) {
		Calendar cal = Calendar.getInstance();
		cal.setTimeInMillis(time);

		long year = cal.get(Calendar.YEAR);
		if (year < 1980) {
			return (1 << 21) | (1 << 16);
		}
		return (year - 1980) << 25
				| (cal.get(Calendar.MONTH) + 1) << 21
				| cal.get(Calendar.DATE) << 16
				| cal.get(Calendar.HOUR_OF_DAY) << 11
				| cal.get(Calendar.MINUTE) << 5
				| cal.get(Calendar.SECOND) >> 1;
	}

	/**
	 * <h3 class="en-US">Converts input time from DOS to Java format</h3>
	 * <h3 class="zh-CN">转换给定的DOS日期为Java日期</h3>
	 *
	 * @param dosTime <span class="en-US">Given time value</span>
	 *                <span class="zh-CN">给定的时间值</span>
	 * @return <span class="en-US">time in Java format</span>
	 * <span class="zh-CN">Java格式的日期</span>
	 */
	public static long dosToJavaTime(final long dosTime) {
		int month;
		switch ((int) ((dosTime >> 21) & 0x0F)) {
			case 1:
				month = Calendar.JANUARY;
				break;
			case 2:
				month = Calendar.FEBRUARY;
				break;
			case 3:
				month = Calendar.MARCH;
				break;
			case 4:
				month = Calendar.APRIL;
				break;
			case 5:
				month = Calendar.MAY;
				break;
			case 6:
				month = Calendar.JUNE;
				break;
			case 7:
				month = Calendar.JULY;
				break;
			case 8:
				month = Calendar.AUGUST;
				break;
			case 9:
				month = Calendar.SEPTEMBER;
				break;
			case 10:
				month = Calendar.OCTOBER;
				break;
			case 11:
				month = Calendar.NOVEMBER;
				break;
			case 12:
				month = Calendar.DECEMBER;
				break;
			default:
				return Globals.DEFAULT_VALUE_LONG;
		}
		Calendar calendar = Calendar.getInstance();
		calendar.set((int) (((dosTime >> 25) & 0x7F) + 1980), month,
				(int) ((dosTime >> 16) & 0x1F),
				(int) ((dosTime >> 11) & 0x1F),
				(int) ((dosTime >> 5) & 0x3F),
				(int) ((dosTime << 1) & 0x3E));
		calendar.clear(Calendar.MILLISECOND);
		return calendar.getTimeInMillis();
	}

	/**
	 * <h3 class="en-US">Retrieve current time in milliseconds.</h3>
	 * <h3 class="zh-CN">读取当前时间与1970-01-01差值的毫秒数</h3>
	 *
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的值</span>
	 */
	public static long currentTimeMillis() {
		return UTC_CLOCK.currentTimeMillis();
	}

	/**
	 * <h3 class="en-US">Retrieve current UTC time in milliseconds.</h3>
	 * <h3 class="zh-CN">读取当前UTC时间与1970-01-01差值的毫秒数</h3>
	 *
	 * @return <span class="en-US">Read value</span>
	 * <span class="zh-CN">读取的值</span>
	 */
	public static long currentUTCTimeMillis() {
		return UTC_CLOCK.currentUTCTimeMillis();
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given DateTimeFormatter instance</h3>
	 * <h3 class="zh-CN">使用给定的日期时间格式化实例对象将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date              <span class="en-US">date instance</span>
	 *                          <span class="zh-CN">日期实例对象</span>
	 * @param dateTimeFormatter <span class="en-US">DateTimeFormatter instance</span>
	 *                          <span class="zh-CN">日期时间格式化实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDate(final Date date, final DateTimeFormatter dateTimeFormatter) {
		return DateTimeUtils.formatDate(date, dateTimeFormatter, TimeZone.getDefault());
	}

	/**
	 * <h3 class="en-US">Formats given date according and time zone to string with given DateTimeFormatter instance</h3>
	 * <h3 class="zh-CN">使用给定的日期时间格式化实例对象和时区将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date              <span class="en-US">date instance</span>
	 *                          <span class="zh-CN">日期实例对象</span>
	 * @param dateTimeFormatter <span class="en-US">DateTimeFormatter instance</span>
	 *                          <span class="zh-CN">日期时间格式化实例对象</span>
	 * @param timeZone          <span class="en-US">Timezone instance</span>
	 *                          <span class="zh-CN">时区实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDate(final Date date, final DateTimeFormatter dateTimeFormatter,
	                                final TimeZone timeZone) {
		Date useDate = (date == null) ? new Date() : date;
		return useDate.toInstant().atZone(timeZone.toZoneId()).toLocalDateTime()
				.format(dateTimeFormatter);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance and date style code</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期风格代码将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date      <span class="en-US">date instance</span>
	 *                  <span class="zh-CN">日期实例对象</span>
	 * @param locale    <span class="en-US">locale instance</span>
	 *                  <span class="zh-CN">地区实例对象</span>
	 * @param dateStyle <span class="en-US">date style code</span>
	 *                  <span class="zh-CN">日期风格代码</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDate(final Date date, final Locale locale, final int dateStyle) {
		return DateFormat.getDateInstance(dateStyle, locale).format(date);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance using date style <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期风格代码<code>DateFormat.MEDIUM</code>将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date   <span class="en-US">date instance</span>
	 *               <span class="zh-CN">日期实例对象</span>
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">地区实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDate(final Date date, final Locale locale) {
		return formatDate(date, locale, DateFormat.MEDIUM);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance and date style code</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期风格代码将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string    <span class="en-US">formatted date time string</span>
	 *                  <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale    <span class="en-US">locale instance</span>
	 *                  <span class="zh-CN">地区实例对象</span>
	 * @param dateStyle <span class="en-US">date style code</span>
	 *                  <span class="zh-CN">日期风格代码</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseDate(final String string, final Locale locale, final int dateStyle) throws ParseException {
		return DateFormat.getDateInstance(dateStyle, locale).parse(string);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance and date style <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期风格<code>DateFormat.MEDIUM</code>将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">地区实例对象</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseDate(final String string, final Locale locale) throws ParseException {
		return parseDate(string, locale, DateFormat.MEDIUM);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance and time style code</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和时间风格代码将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param time      <span class="en-US">date instance</span>
	 *                  <span class="zh-CN">日期实例对象</span>
	 * @param locale    <span class="en-US">locale instance</span>
	 *                  <span class="zh-CN">地区实例对象</span>
	 * @param timeStyle <span class="en-US">time style code</span>
	 *                  <span class="zh-CN">时间风格代码</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatTime(final Date time, final Locale locale, final int timeStyle) {
		DateFormat formatter = DateFormat.getTimeInstance(timeStyle, locale);
		return formatter.format(time);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance using time style <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和时间风格代码<code>DateFormat.MEDIUM</code>将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param time   <span class="en-US">date instance</span>
	 *               <span class="zh-CN">日期实例对象</span>
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">地区实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatTime(final Date time, final Locale locale) {
		return formatTime(time, locale, DateFormat.MEDIUM);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance and time style code</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期风格代码将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string    <span class="en-US">formatted date time string</span>
	 *                  <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale    <span class="en-US">locale instance</span>
	 *                  <span class="zh-CN">地区实例对象</span>
	 * @param timeStyle <span class="en-US">time style code</span>
	 *                  <span class="zh-CN">时间风格代码</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseTime(final String string, final Locale locale, final int timeStyle) throws ParseException {
		return DateFormat.getTimeInstance(timeStyle, locale).parse(string);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance and time style <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和时间风格<code>DateFormat.MEDIUM</code>将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">地区实例对象</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseTime(final String string, final Locale locale) throws ParseException {
		return parseTime(string, locale, DateFormat.MEDIUM);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance, date style code and time style code</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象、日期风格代码和时间风格代码将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date      <span class="en-US">date instance</span>
	 *                  <span class="zh-CN">日期实例对象</span>
	 * @param locale    <span class="en-US">locale instance</span>
	 *                  <span class="zh-CN">地区实例对象</span>
	 * @param dateStyle <span class="en-US">date style code</span>
	 *                  <span class="zh-CN">日期风格代码</span>
	 * @param timeStyle <span class="en-US">time style code</span>
	 *                  <span class="zh-CN">时间风格代码</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDateTime(final Date date, final Locale locale, final int dateStyle, final int timeStyle) {
		return DateFormat.getDateTimeInstance(dateStyle, timeStyle, locale).format(date);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance using date style <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期、时间风格代码<code>DateFormat.MEDIUM</code>将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date   <span class="en-US">date instance</span>
	 *               <span class="zh-CN">日期实例对象</span>
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">地区实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDateTime(final Date date, final Locale locale) {
		return formatDateTime(date, locale, DateFormat.MEDIUM, DateFormat.MEDIUM);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with system locale instance using date style <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用系统地区实例对象和日期、时间风格代码<code>DateFormat.MEDIUM</code>将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date <span class="en-US">date instance</span>
	 *             <span class="zh-CN">日期实例对象</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String formatDateTime(final Date date) {
		return formatDateTime(date, Globals.DEFAULT_LOCALE);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance, date style code and time style code</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象、日期风格代码和时间风格代码将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string    <span class="en-US">formatted date time string</span>
	 *                  <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale    <span class="en-US">locale instance</span>
	 *                  <span class="zh-CN">地区实例对象</span>
	 * @param dateStyle <span class="en-US">date style code</span>
	 *                  <span class="zh-CN">日期风格代码</span>
	 * @param timeStyle <span class="en-US">time style code</span>
	 *                  <span class="zh-CN">时间风格代码</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseDateTime(final String string, final Locale locale, final int dateStyle, final int timeStyle)
			throws ParseException {
		return DateFormat.getDateTimeInstance(dateStyle, timeStyle, locale).parse(string);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance, date style and time style using <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和日期时间风格<code>DateFormat.MEDIUM</code>将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale <span class="en-US">locale instance</span>
	 *               <span class="zh-CN">地区实例对象</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseDateTime(final String string, final Locale locale) throws ParseException {
		return parseDateTime(string, locale, DateFormat.MEDIUM, DateFormat.MEDIUM);
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with system locale instance, date style and time style using <code>DateFormat.MEDIUM</code></h3>
	 * <h3 class="zh-CN">使用系统地区实例对象和日期时间风格<code>DateFormat.MEDIUM</code>将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string <span class="en-US">formatted date time string</span>
	 *               <span class="zh-CN">格式化的日期时间字符串</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws ParseException <span class="en-US">if given string could not be properly parsed according to given locale and style</span>
	 *                        <span class="zh-CN">如果给定的字符串无法根据给定的区域设置和样式正确解析</span>
	 */
	public static Date parseDateTime(final String string) throws ParseException {
		return parseDateTime(string, Globals.DEFAULT_LOCALE);
	}

	/**
	 * <h3 class="en-US">Formats given date according to string with given locale instance and date pattern string</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和格式代码将给定的日期实例对象转换为字符串</h3>
	 *
	 * @param date    <span class="en-US">date instance</span>
	 *                <span class="zh-CN">日期实例对象</span>
	 * @param locale  <span class="en-US">locale instance</span>
	 *                <span class="zh-CN">地区实例对象</span>
	 * @param pattern <span class="en-US">Pattern string</span>
	 *                <span class="zh-CN">格式字符串</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String format(final Date date, final Locale locale, final String pattern) {
		return Optional.ofNullable(date)
				.map(Date::toInstant)
				.map(instant -> instant.atZone(ZoneId.systemDefault()))
				.map(ZonedDateTime::toLocalDateTime)
				.map(localDateTime -> localDateTime.format(DateTimeFormatter.ofPattern(pattern, locale)))
				.orElse(LocalDateTime.now().format(DateTimeFormatter.ofPattern(pattern, locale)));
	}

	/**
	 * <h3 class="en-US">Parse given string according to date with given locale instance and date pattern string</h3>
	 * <h3 class="zh-CN">使用给定的地区实例对象和格式代码将给定的字符串转换为日期实例对象</h3>
	 *
	 * @param string  <span class="en-US">formatted date time string</span>
	 *                <span class="zh-CN">格式化的日期时间字符串</span>
	 * @param locale  <span class="en-US">locale instance</span>
	 *                <span class="zh-CN">地区实例对象</span>
	 * @param pattern <span class="en-US">Pattern string</span>
	 *                <span class="zh-CN">格式字符串</span>
	 * @return <span class="en-US">date instance</span>
	 * <span class="zh-CN">日期实例对象</span>
	 * @throws DateTimeParseException <span class="en-US">if given string could not be properly parsed according to given pattern string</span>
	 *                                <span class="zh-CN">如果给定的字符串无法根据给定的格式字符串正确解析</span>
	 */
	public static Date parse(final String string, final Locale locale, final String pattern)
			throws DateTimeParseException {
		if (StringUtils.isEmpty(string)) {
			return null;
		}
		return Optional.of(LocalDateTime.parse(string, DateTimeFormatter.ofPattern(pattern, locale)))
				.map(localDateTime -> localDateTime.atZone(ZoneId.systemDefault()))
				.map(ChronoZonedDateTime::toInstant)
				.map(Date::from)
				.orElse(null);
	}

	/**
	 * <h3 class="en-US">Check current year is leap year</h3>
	 * <h3 class="zh-CN">检查当前年份是否为闰年</h3>
	 *
	 * @return <span class="en-US">check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isLeapYear() {
		return LocalDate.now().isLeapYear();
	}

	/**
	 * <h3 class="en-US">Check given year is leap year</h3>
	 * <h3 class="zh-CN">检查给定的年份是否为闰年</h3>
	 *
	 * @param year <span class="en-US">which year will check</span>
	 *             <span class="zh-CN">将要检查的年份</span>
	 * @return <span class="en-US">check result</span>
	 * <span class="zh-CN">检查结果</span>
	 */
	public static boolean isLeapYear(final int year) {
		return (year % 400 == 0) || ((year % 100 != 0) && (year % 4 == 0));
	}

	/**
	 * <h3 class="en-US">Retrieve first day of current month and format to string the using given pattern</h3>
	 * <h3 class="zh-CN">读取当前月份的第一天并使用给定的格式字符串将日期转换为格式化的字符串</h3>
	 *
	 * @param pattern <span class="en-US">Pattern string</span>
	 *                <span class="zh-CN">格式字符串</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String getCurrentMonthFirstDay(final String pattern) {
		return LocalDateTime.now().with(TemporalAdjusters.firstDayOfMonth())
				.format(DateTimeFormatter.ofPattern(pattern));
	}

	/**
	 * <h3 class="en-US">Retrieve last day of current month and format to string the using given pattern</h3>
	 * <h3 class="zh-CN">读取当前月份的最后一天并使用给定的格式字符串将日期转换为格式化的字符串</h3>
	 *
	 * @param pattern <span class="en-US">Pattern string</span>
	 *                <span class="zh-CN">格式字符串</span>
	 * @return <span class="en-US">formatted date time string</span>
	 * <span class="zh-CN">格式化后的日期时间字符串</span>
	 */
	public static String getCurrentMonthLastDay(final String pattern) {
		return LocalDateTime.now().with(TemporalAdjusters.lastDayOfMonth())
				.format(DateTimeFormatter.ofPattern(pattern));
	}

	/**
	 * <h3 class="en-US">Calculate days count of given month count from current day</h3>
	 * <h3 class="zh-CN">根据给定的月数计算当前日期往后月数有多少天</h3>
	 *
	 * @param monthCount <span class="en-US">Expire month count</span>
	 *                   <span class="zh-CN">过期月份计数</span>
	 * @return <span class="en-US">Calculated day count</span>
	 * <span class="zh-CN">计算的天数结果</span>
	 */
	private static int expireDayCount(int monthCount) {
		int dayCount = Globals.INITIALIZE_INT_VALUE;
		int currentYear = currentYear();
		int currentMonth = currentMonth();
		for (int i = 0; i < monthCount; i++) {
			dayCount += getDaysOfMonth(currentYear, currentMonth);
			currentMonth++;
		}
		return dayCount;
	}

	/**
	 * <h3 class="en-US">Get default time zone string</h3>
	 * <h3 class="zh-CN">读取默认的时区并转换为字符串</h3>
	 *
	 * @return <span class="en-US">formatted time zone string</span>
	 * <span class="zh-CN">格式化后的时区字符串</span>
	 */
	private static String getTimeZone() {
		StringBuilder stringBuilder = new StringBuilder();
		int zoneCode = TimeZone.getDefault().getRawOffset() / (1000 * 60 * 60);
		stringBuilder.append(zoneCode >= 0 ? "+" : "-");
		if (zoneCode < 0) {
			zoneCode = Math.abs(zoneCode);
		}
		stringBuilder.append(zoneCode < 10 ? "0" : "").append(zoneCode).append(":00");
		return stringBuilder.toString();
	}

	/**
	 * <h2 class="en-US">UTC Clock</h2>
	 * <h2 class="zh-CN">UTC时钟</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0.0 $ $Date: Jan 13, 2010 11:46:19 $
	 */
	private static final class UTCClock {
		/**
		 * <span class="en-US">Current local time milliseconds</span>
		 * <span class="zh-CN">当前本地时间的毫秒数</span>
		 */
		private final AtomicLong currentLocalTime = new AtomicLong(System.currentTimeMillis());
		/**
		 * <span class="en-US">Current UTC time milliseconds</span>
		 * <span class="zh-CN">当前UTC时间的毫秒数</span>
		 */
		private final AtomicLong currentUTCTime =
				new AtomicLong(System.currentTimeMillis() - TimeZone.getDefault().getRawOffset());

		/**
		 * <h3 class="en-US">Constructor method for UTC clock</h3>
		 * <h3 class="zh-CN">UTC时钟的构造方法</h3>
		 */
		public UTCClock() {
			ScheduledThreadPoolExecutor threadPoolExecutor =
					new ScheduledThreadPoolExecutor(1, r -> {
						Thread thread = new Thread(r);
						thread.setDaemon(Boolean.TRUE);
						return thread;
					});
			threadPoolExecutor.scheduleAtFixedRate(this::readTime, 0L, 1L, TimeUnit.MILLISECONDS);
		}

		/**
		 * <h3 class="en-US">Read current local time milliseconds</h3>
		 * <h3 class="zh-CN">读取当前本地时间的毫秒数</h3>
		 *
		 * @return <span class="en-US">Current local time milliseconds</span>
		 * <span class="zh-CN">当前本地时间的毫秒数</span>
		 */
		public long currentTimeMillis() {
			return this.currentLocalTime.get();
		}

		/**
		 * <h3 class="en-US">Read current UTC time milliseconds</h3>
		 * <h3 class="zh-CN">读取当前UTC时间的毫秒数</h3>
		 *
		 * @return <span class="en-US">Current UTC time milliseconds</span>
		 * <span class="zh-CN">当前UTC时间的毫秒数</span>
		 */
		public long currentUTCTimeMillis() {
			return this.currentUTCTime.get();
		}

		/**
		 * <h3 class="en-US">Schedule method for read current local time and UTC time</h3>
		 * <h3 class="zh-CN">调度方法用于读取当前本地时间和UTC时间</h3>
		 */
		private void readTime() {
			long currentTime = System.currentTimeMillis();
			this.currentLocalTime.set(currentTime);
			this.currentUTCTime.set(currentTime - TimeZone.getDefault().getRawOffset());
		}
	}
}
