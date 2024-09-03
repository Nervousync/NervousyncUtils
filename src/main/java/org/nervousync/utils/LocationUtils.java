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

import org.nervousync.beans.location.GeoPoint;
import org.nervousync.exceptions.location.LocationConvertException;

/**
 * <h2 class="en-US">Geography Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Convert GeoPoint at WGS84(GPS)/GCJ02/BD09</ul>
 *     <ul>Calculate distance of two given geography point. (Unit: Kilometers)</ul>
 * </span>
 * <h2 class="zh-CN">地理位置信息工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>在不同坐标系间转换数据，支持的坐标系：WGS84(GPS)/GCJ02/BD09</ul>
 *     <ul>计算两个物理坐标之间的距离，单位：公里</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Dec 19, 2017 13:01:14 $
 */
public final class LocationUtils {
	/**
	 * <span class="en-US">Earth radius</span>
	 * <span class="zh-CN">地球半径</span>
	 */
	private static final double EARTH_R = 6378245.0;
	/**
	 * <span class="en-US">Square value of earth eccentricity</span>
	 * <span class="zh-CN">地球偏心率平方值</span>
	 */
	private static final double EARTH_EE = 0.00669342162296594323;

	/**
	 * <h3 class="en-US">Private constructor for LocationUtils</h3>
	 * <h3 class="zh-CN">地理位置信息工具集的私有构造方法</h3>
	 */
	private LocationUtils() {
	}

	/**
	 * <h3 class="en-US">Calculate distance of two given geography location. (Unit: Kilometers)</h3>
	 * <h3 class="zh-CN">计算两个物理坐标之间的距离，单位：公里</h3>
	 *
	 * @param beginPoint <span class="en-US">GroPoint instance of beginning geography location</span>
	 *                   <span class="zh-CN">起始位置坐标的GroPoint实例</span>
	 * @param endPoint   <span class="en-US">GroPoint instance of end geography location</span>
	 *                   <span class="zh-CN">终止位置坐标的GroPoint实例</span>
	 * @return <span class="en-US">Calculated distance value</span>
	 * <span class="zh-CN">计算完成的距离值</span>
	 * @throws LocationConvertException <span class="en-US">If convert GeoPoint instance to GPS location has error</span>
	 *                                  <span class="zh-CN">当转换GeoPoint为GPS坐标时出现错误</span>
	 */
	public static double calcDistance(final GeoPoint beginPoint, final GeoPoint endPoint)
			throws LocationConvertException {
		GeoPoint beginGPSPoint = anyToGPS(beginPoint);
		GeoPoint endGPSPoint = anyToGPS(endPoint);
		double tmpX = (endGPSPoint.getLongitude() - beginGPSPoint.getLongitude()) * Math.PI * EARTH_R
				* Math.cos(((beginGPSPoint.getLatitude() + endGPSPoint.getLatitude()) / 2) * Math.PI / 180) / 180;
		double tmpY = (endGPSPoint.getLatitude() - beginGPSPoint.getLatitude()) * Math.PI * EARTH_R / 180;
		return Math.hypot(tmpX, tmpY);

	}

	/**
	 * <h3 class="en-US">Convert given GeoPoint instance to GPS GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换给定的GeoPoint实例为GPS坐标GeoPoint实例</h3>
	 *
	 * @param currentPoint <span class="en-US">Given GroPoint instance</span>
	 *                     <span class="zh-CN">给定的坐标的GroPoint实例</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 * @throws LocationConvertException <span class="en-US">If convert GeoPoint instance to GPS location has error</span>
	 *                                  <span class="zh-CN">当转换GeoPoint为GPS坐标时出现错误</span>
	 */
	public static GeoPoint anyToGPS(final GeoPoint currentPoint) throws LocationConvertException {
		if (currentPoint == null) {
			throw new LocationConvertException(0x0000000C0001L, "Null_Point_Location_Error");
		}
		switch (currentPoint.getLocationType()) {
			case GPS:
				return currentPoint;
			case GCJ_02:
				return GCJ02ToGPS(currentPoint.getLongitude(), currentPoint.getLatitude());
			case BD_09:
				GeoPoint gcjPoint = BD09ToGCJ02(currentPoint.getLongitude(), currentPoint.getLatitude());
				return GCJ02ToGPS(gcjPoint.getLongitude(), gcjPoint.getLatitude());
			default:
				throw new LocationConvertException(0x0000000C0002L, "Not_Support_Type_Location_Error");
		}
	}

	/**
	 * <h3 class="en-US">Convert given GeoPoint instance to GCJ02 GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换给定的GeoPoint实例为GCJ02坐标GeoPoint实例</h3>
	 *
	 * @param currentPoint <span class="en-US">Given GroPoint instance</span>
	 *                     <span class="zh-CN">给定的坐标的GroPoint实例</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 * @throws LocationConvertException <span class="en-US">If convert GeoPoint instance to GPS location has error</span>
	 *                                  <span class="zh-CN">当转换GeoPoint为GPS坐标时出现错误</span>
	 */
	public static GeoPoint anyToGCJ02(final GeoPoint currentPoint) throws LocationConvertException {
		if (currentPoint == null) {
			throw new LocationConvertException(0x0000000C0001L, "Null_Point_Location_Error");
		}
		switch (currentPoint.getLocationType()) {
			case GPS:
				return GPSToGCJ02(currentPoint.getLongitude(), currentPoint.getLatitude());
			case GCJ_02:
				return currentPoint;
			case BD_09:
				return BD09ToGCJ02(currentPoint.getLongitude(), currentPoint.getLatitude());
			default:
				throw new LocationConvertException(0x0000000C0002L, "Not_Support_Type_Location_Error");
		}
	}

	/**
	 * <h3 class="en-US">Convert given GeoPoint instance to BD09 GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换给定的GeoPoint实例为BD09坐标GeoPoint实例</h3>
	 *
	 * @param currentPoint <span class="en-US">Given GroPoint instance</span>
	 *                     <span class="zh-CN">给定的坐标的GroPoint实例</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 * @throws LocationConvertException <span class="en-US">If convert GeoPoint instance to GPS location has error</span>
	 *                                  <span class="zh-CN">当转换GeoPoint为GPS坐标时出现错误</span>
	 */
	public static GeoPoint anyToBD09(final GeoPoint currentPoint) throws LocationConvertException {
		if (currentPoint == null) {
			throw new LocationConvertException(0x0000000C0001L, "Null_Point_Location_Error");
		}
		switch (currentPoint.getLocationType()) {
			case GPS:
				GeoPoint gcjPoint = GPSToGCJ02(currentPoint.getLongitude(), currentPoint.getLatitude());
				return GCJ02ToBD09(gcjPoint.getLongitude(), gcjPoint.getLatitude());
			case GCJ_02:
				return GCJ02ToBD09(currentPoint.getLongitude(), currentPoint.getLatitude());
			case BD_09:
				return currentPoint;
			default:
				throw new LocationConvertException(0x0000000C0002L, "Not_Support_Type_Location_Error");
		}
	}

	/**
	 * <h3 class="en-US">Convert GCJ02 GeoPoint instance to BD09 GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换GCJ02坐标的GeoPoint实例为BD09坐标GeoPoint实例</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 */
	private static GeoPoint GCJ02ToBD09(final double longitude, final double latitude) {
		double fixValue = Math.sqrt(Math.pow(longitude, 2) + Math.pow(latitude, 2)) + 0.00002 * Math.sin(latitude * Math.PI);
		double delta = Math.atan2(latitude, longitude) + 0.000003 * Math.cos(longitude * Math.PI);
		double bdLat = fixValue * Math.sin(delta) + 0.006;
		double bdLon = fixValue * Math.cos(delta) + 0.0065;
		return GeoPoint.bd09Point(bdLon, bdLat);
	}

	/**
	 * <h3 class="en-US">Convert BD09 GeoPoint instance to GCJ02 GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换BD09坐标的GeoPoint实例为GCJ02坐标GeoPoint实例</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 */
	private static GeoPoint BD09ToGCJ02(final double longitude, final double latitude) {
		double fixValue = Math.sqrt(Math.pow(longitude - 0.0065, 2) + Math.pow(latitude - 0.006, 2))
				- 0.00002 * Math.sin((latitude - 0.006) * Math.PI);
		double fixTemp = Math.atan2(latitude - 0.006, longitude - 0.0065)
				- 0.000003 * Math.cos((longitude - 0.0065) * Math.PI);
		double gcjLat = fixValue * Math.sin(fixTemp);
		double gcjLon = fixValue * Math.cos(fixTemp);
		return GeoPoint.gcj02Point(gcjLon, gcjLat);
	}

	/**
	 * <h3 class="en-US">Convert GCJ02 GeoPoint instance to GPS GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换GCJ02坐标的GeoPoint实例为GPS坐标GeoPoint实例</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 */
	private static GeoPoint GCJ02ToGPS(final double longitude, final double latitude) {
		if ((longitude < 72.004 || longitude > 137.8347) || (latitude < 0.8293 || latitude > 55.8271)) {
			return GeoPoint.gpsPoint(longitude, latitude);
		} else {
			GeoPoint deltaPoint = deltaPoint(longitude, latitude);
			return GeoPoint.gpsPoint(longitude - deltaPoint.getLongitude(),
					latitude - deltaPoint.getLatitude());
		}
	}

	/**
	 * <h3 class="en-US">Convert GPS GeoPoint instance to GCJ02 GeoPoint instance</h3>
	 * <h3 class="zh-CN">转换GPS坐标的GeoPoint实例为GCJ02坐标GeoPoint实例</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 */
	private static GeoPoint GPSToGCJ02(final double longitude, final double latitude) {
		if ((longitude < 72.004 || longitude > 137.8347) && (latitude < 0.8293 || latitude > 55.8271)) {
			return GeoPoint.gcj02Point(longitude, latitude);
		}
		GeoPoint deltaPoint = deltaPoint(longitude, latitude);
		return GeoPoint.gcj02Point(longitude + deltaPoint.getLongitude(),
				latitude + deltaPoint.getLatitude());
	}

	/**
	 * <h3 class="en-US">Calculate delta value of GeoPoint convert</h3>
	 * <h3 class="zh-CN">计算地理坐标的偏移量</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Converted GeoPoint instance</span>
	 * <span class="zh-CN">转换后的GeoPoint实例</span>
	 */
	private static GeoPoint deltaPoint(final double longitude, final double latitude) {
		double transformLatitude = latitude / 180.0 * Math.PI;
		double magic = 1 - EARTH_EE * Math.pow(Math.sin(transformLatitude), 2);
		double magicSqrt = Math.sqrt(magic);
		double fixedLatitude = ((transformLatitude(longitude - 105.0, latitude - 35.0) * 180.0)
				/ ((EARTH_R * (1 - EARTH_EE)) / (magic * magicSqrt) * Math.PI));
		double fixedLongitude = ((transformLongitude(longitude - 105.0, latitude - 35.0) * 180.0)
				/ (EARTH_R / magicSqrt * Math.cos(transformLatitude) * Math.PI));
		return GeoPoint.deltaPoint(fixedLongitude, fixedLatitude);
	}

	/**
	 * <h3 class="en-US">Calculate value of transformed latitude</h3>
	 * <h3 class="zh-CN">计算转换后的纬度值</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">transformed latitude value</span>
	 * <span class="zh-CN">转换后的纬度值</span>
	 */
	private static double transformLatitude(final double longitude, final double latitude) {
		double result = -100.0 + 2.0 * longitude + 3.0 * latitude + 0.2 * Math.pow(latitude, 2);
		result += 0.1 * longitude * latitude + 0.2 * Math.sqrt(Math.abs(longitude));
		result += calculate(longitude, latitude);
		result += (160.0 * Math.sin(latitude / 12.0 * Math.PI) + 320.0 * Math.sin(latitude * Math.PI / 30.0)) * 2.0 / 3.0;
		return result;
	}

	/**
	 * <h3 class="en-US">Calculate value of transformed longitude</h3>
	 * <h3 class="zh-CN">计算转换后的经度值</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">transformed longitude value</span>
	 * <span class="zh-CN">转换后的经度值</span>
	 */
	private static double transformLongitude(final double longitude, final double latitude) {
		double result = 300.0 + longitude + 2.0 * latitude + 0.1 * Math.pow(longitude, 2);
		result += 0.1 * longitude * latitude + 0.1 * Math.sqrt(Math.abs(longitude));
		result += calculate(longitude, longitude);
		result += (150.0 * Math.sin(longitude / 12.0 * Math.PI) + 300.0 * Math.sin(longitude * Math.PI / 30.0)) * 2.0 / 3.0;
		return result;
	}

	private static double calculate(final double value1, final double value2) {
		return ((20.0 * Math.sin(6.0 * value1 * Math.PI) + 20.0 * Math.sin(2.0 * value1 * Math.PI)) * 2.0 / 3.0)
				+ ((20.0 * Math.sin(value2 * Math.PI) + 40.0 * Math.sin(value2 / 3.0 * Math.PI)) * 2.0 / 3.0);
	}
}
