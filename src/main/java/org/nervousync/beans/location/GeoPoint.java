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
package org.nervousync.beans.location;

import java.io.Serializable;


/**
 * <h2 class="en-US">Geography point define</h2>
 * <h2 class="zh-CN">地理位置信息定义</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.1.1 $ $Date: Sep 09, 2022 13:03:40 $
 */
public final class GeoPoint implements Serializable {
	/**
	 * <span class="en-US">Serial version UID</span>
	 * <span class="zh-CN">序列化UID</span>
	 */
	private static final long serialVersionUID = -3501428042311016856L;
	/**
	 * <span class="en-US">Enumeration value of GeoPoint.LocationType</span>
	 * <span class="zh-CN">地理坐标类型枚举值</span>
	 *
	 * @see GeoPoint.LocationType
	 */
	private final LocationType locationType;
	/**
	 * <span class="en-US">Longitude value of GeoPoint</span>
	 * <span class="zh-CN">地理坐标经度值</span>
	 */
	private final double longitude;
	/**
	 * <span class="en-US">Latitude value of GeoPoint</span>
	 * <span class="zh-CN">地理坐标纬度值</span>
	 */
	private final double latitude;

	/**
	 * <h3 class="en-US">Constructor for GeoPoint</h3>
	 * <h3 class="zh-CN">GeoPoint默认构造方法</h3>
	 *
	 * @param locationType <span class="en-US">Enumeration value of GeoPoint.LocationType</span>
	 *                     <span class="zh-CN">地理坐标类型枚举值</span>
	 * @param longitude    <span class="en-US">Longitude value of GeoPoint</span>
	 *                     <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude     <span class="en-US">Latitude value of GeoPoint</span>
	 *                     <span class="zh-CN">地理坐标纬度值</span>
	 */
	private GeoPoint(final LocationType locationType, final double longitude, final double latitude) {
		this.locationType = locationType;
		this.longitude = longitude;
		this.latitude = latitude;
	}

	/**
	 * <h3 class="en-US">Static method for initialize GPS GeoPoint by given location (longitude, latitude)</h3>
	 * <h3 class="zh-CN">用于初始化GPS地理坐标的静态方法，使用给定的坐标（longitude，latitude）</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Initialized GeoPoint instance</span>
	 * <span class="en-US">初始化的GeoPoint实例对象</span>
	 */
	public static GeoPoint gpsPoint(final double longitude, final double latitude) {
		return new GeoPoint(LocationType.GPS, longitude, latitude);
	}

	/**
	 * <h3 class="en-US">Static method for initialize GCJ02 GeoPoint by given location (longitude, latitude)</h3>
	 * <h3 class="zh-CN">用于初始化GCJ02地理坐标的静态方法，使用给定的坐标（longitude，latitude）</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Initialized GeoPoint instance</span>
	 * <span class="en-US">初始化的GeoPoint实例对象</span>
	 */
	public static GeoPoint gcj02Point(final double longitude, final double latitude) {
		return new GeoPoint(LocationType.GCJ_02, longitude, latitude);
	}

	/**
	 * <h3 class="en-US">Static method for initialize BD09 GeoPoint by given location (longitude, latitude)</h3>
	 * <h3 class="zh-CN">用于初始化BD09地理坐标的静态方法，使用给定的坐标（longitude，latitude）</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Initialized GeoPoint instance</span>
	 * <span class="en-US">初始化的GeoPoint实例对象</span>
	 */
	public static GeoPoint bd09Point(final double longitude, final double latitude) {
		return new GeoPoint(LocationType.BD_09, longitude, latitude);
	}

	/**
	 * <h3 class="en-US">Static method for initialize Delta GeoPoint by given location (longitude, latitude)</h3>
	 * <h3 class="zh-CN">用于初始化Delta地理坐标的静态方法，使用给定的坐标（longitude，latitude）</h3>
	 *
	 * @param longitude <span class="en-US">Longitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标经度值</span>
	 * @param latitude  <span class="en-US">Latitude value of GeoPoint</span>
	 *                  <span class="zh-CN">地理坐标纬度值</span>
	 * @return <span class="en-US">Initialized GeoPoint instance</span>
	 * <span class="en-US">初始化的GeoPoint实例对象</span>
	 */
	public static GeoPoint deltaPoint(final double longitude, final double latitude) {
		return new GeoPoint(LocationType.DELTA, longitude, latitude);
	}

	/**
	 * <h3 class="en-US">Getter method for location type</h3>
	 * <h3 class="zh-CN">坐标类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of location type</span>
	 * <span class="zh-CN">坐标类型值</span>
	 */
	public LocationType getLocationType() {
		return locationType;
	}

	/**
	 * <h3 class="en-US">Getter method for location longitude</h3>
	 * <h3 class="zh-CN">坐标经度值的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of location longitude</span>
	 * <span class="zh-CN">坐标经度值</span>
	 */
	public double getLongitude() {
		return longitude;
	}

	/**
	 * <h3 class="en-US">Getter method for location latitude</h3>
	 * <h3 class="zh-CN">坐标纬度值的Getter方法</h3>
	 *
	 * @return <span class="en-US">Value of location latitude</span>
	 * <span class="zh-CN">坐标纬度值</span>
	 */
	public double getLatitude() {
		return latitude;
	}

	/**
	 * <h3 class="en-US">Override method for toString</h3>
	 * <p class="en-US">
	 * Join longitude and latitude using split character: ", ",
	 * longitude value is before the split character, latitude value is after the split character
	 * </p>
	 * <h3 class="zh-CN">覆写的toString方法</h3>
	 *
	 * @return <span class="en-US">Value of location latitude</span>
	 * <span class="zh-CN">坐标纬度值</span>
	 */
	@Override
	public String toString() {
		if (LocationType.GPS.equals(this.locationType)) {
			return this.latitude + "," + this.longitude;
		}
		return this.longitude + "," + this.latitude;
	}

	/**
	 * <h2 class="en-US">Enumeration defines for LocationType</h2>
	 * <h2 class="zh-CN">LocationType枚举类定义</h2>
	 */
	public enum LocationType {
		/**
		 * <span class="en-US">GPS/WGS84 Record</span>
		 * <span class="zh-CN">GPS/WGS84坐标</span>
		 */
		GPS,
		/**
		 * <span class="en-US">GCJ-02 Record</span>
		 * <span class="zh-CN">GCJ-02坐标</span>
		 */
		GCJ_02,
		/**
		 * <span class="en-US">BD-09 Record</span>
		 * <span class="zh-CN">GCJ02坐标</span>
		 */
		BD_09,
		/**
		 * <span class="en-US">DELTA Record, using for convert between the location types</span>
		 * <span class="zh-CN">DELTA坐标，用于不同坐标系间的数据转换</span>
		 */
		DELTA
	}
}
