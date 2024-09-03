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

import java.lang.reflect.Array;
import java.util.*;

/**
 * <h2 class="en-US">Collection Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 *     <ul>Check collection is empty</ul>
 *     <ul>Check collection contains target element</ul>
 *     <ul>Check two collection contains the same element</ul>
 *     <ul>Check collection contains unique element</ul>
 *     <ul>Convert object to array list</ul>
 *     <ul>Merge array to list</ul>
 *     <ul>Merge properties to map</ul>
 *     <ul>Find the first match element of collection</ul>
 * </span>
 * <h2 class="zh-CN">数据集合工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <ul>检查集合是否为空</ul>
 *     <ul>检查集合是否包含目标对象</ul>
 *     <ul>检查两个集合是否包含同一元素</ul>
 *     <ul>检查集合是否有唯一元素</ul>
 *     <ul>转换对象为列表</ul>
 *     <ul>合并数组到列表中</ul>
 *     <ul>合并属性信息实例到哈希表中</ul>
 *     <ul>从集合中寻找第一个符合要求的元素</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.2.0 $ $Date: Jan 13, 2010 16:27:49 $
 */
public final class CollectionUtils {
	/**
	 * <h3 class="en-US">Private constructor for CollectionUtils</h3>
	 * <h3 class="zh-CN">数据集合工具集的私有构造方法</h3>
	 */
	private CollectionUtils() {
	}

	/**
	 * <h3 class="en-US">Check given collection instance is empty</h3>
	 * <span class="en-US">
	 * Return <code>true</code> if the supplied Collection is <code>null</code>
	 * or empty. Otherwise, return <code>false</code>.
	 * </span>
	 * <h3 class="zh-CN">检查给定的集合实例对象是否为空</h3>
	 * <span class="zh-CN">当给定的集合实例对象为null或者集合为空返回<code>true</code>，否则返回<code>false</code></span>
	 *
	 * @param collection <span class="en-US">collection instance</span>
	 *                   <span class="zh-CN">集合实例对象</span>
	 * @return <span class="en-US">whether the given Collection is empty</span>
	 * <span class="zh-CN">给定的集合实例对象是否为空</span>
	 */
	public static boolean isEmpty(final Collection<?> collection) {
		return (collection == null || collection.isEmpty());
	}

	/**
	 * <h3 class="en-US">Check given collection instance is empty</h3>
	 * <span class="en-US">
	 * Return <code>true</code> if the supplied Collection is <code>null</code>
	 * or empty. Otherwise, return <code>false</code>.
	 * </span>
	 * <h3 class="zh-CN">检查给定的集合实例对象是否为空</h3>
	 * <span class="zh-CN">当给定的集合实例对象为null或者集合为空返回<code>true</code>，否则返回<code>false</code></span>
	 *
	 * @param objects <span class="en-US">array instance</span>
	 *                <span class="zh-CN">数组实例对象</span>
	 * @return <span class="en-US">whether the given Collection is empty</span>
	 * <span class="zh-CN">给定的集合实例对象是否为空</span>
	 */
	public static boolean isEmpty(final Object[] objects) {
		return (objects == null || objects.length == 0);
	}

	/**
	 * <h3 class="en-US">Check given map instance is empty</h3>
	 * <span class="en-US">
	 * Return <code>true</code> if the supplied Map is <code>null</code>
	 * or empty. Otherwise, return <code>false</code>.
	 * </span>
	 * <h3 class="zh-CN">检查给定的Map实例对象是否为空</h3>
	 * <span class="zh-CN">当给定的Map实例对象为null或者集合为空返回<code>true</code>，否则返回<code>false</code></span>
	 *
	 * @param map <span class="en-US">Map instance</span>
	 *            <span class="zh-CN">Map实例对象</span>
	 * @return <span class="en-US">whether the given map is empty</span>
	 * <span class="zh-CN">给定的Map实例对象是否为空</span>
	 */
	public static boolean isEmpty(final Map<?, ?> map) {
		return (map == null || map.isEmpty());
	}

	/**
	 * <h3 class="en-US">Append the given Object to the given array, returning a new array consisting of the input array contents plus the given Object.</h3>
	 * <h3 class="zh-CN">将给定的对象附加到给定的数组，返回一个由输入数组内容加上给定的对象组成的新数组。</h3>
	 *
	 * @param array <span class="en-US">the array to append to (can be <code>null</code>)</span>
	 *              <span class="zh-CN">要附加到的数组（可以为 <code>null</code>）</span>
	 * @param obj   <span class="en-US">the Object to append</span>
	 *              <span class="zh-CN">要附加的对象</span>
	 * @return <span class="en-US">the new array of the same component type; (never <code>null</code>)</span>
	 * <span class="zh-CN">相同组件类型的新数组；（永远不为<code>null</code>）</span>
	 */
	public static Object[] addObjectToArray(final Object[] array, final Object obj) {
		Class<?> compType = Object.class;
		if (array != null) {
			compType = array.getClass().getComponentType();
		} else if (obj != null) {
			compType = obj.getClass();
		}
		int newArrLength = (array != null ? array.length + 1 : 1);
		Object[] newArr = (Object[]) Array.newInstance(compType, newArrLength);
		if (array != null) {
			System.arraycopy(array, 0, newArr, 0, array.length);
		}
		newArr[newArr.length - 1] = obj;
		return newArr;
	}

	/**
	 * <h3 class="en-US">Convert the given array (which may be a primitive array) to an object array (if necessary of primitive wrapper objects).</h3>
	 * <span class="en-US">A <code>null</code> source value will be converted to an empty Object array.</span>
	 * <h3 class="zh-CN">将给定数组（可能是原始数组）转换为对象数组（如果需要原始包装对象）。</h3>
	 * <span class="zh-CN"><code>null</code> 源值将转换为空对象数组。</span>
	 *
	 * @param source <span class="en-US">the (potentially primitive) array</span>
	 *               <span class="zh-CN">可能为基础类型的实例对象（数组）</span>
	 * @return <span class="en-US">the corresponding object array (never <code>null</code>)</span>
	 * <span class="zh-CN">相应的对象数组（永远不为<code>null</code>）</span>
	 * @throws IllegalArgumentException <span class="en-US">if the parameter is not an array</span>
	 *                                  <span class="zh-CN">如果参数不是数组</span>
	 */
	public static Object[] toArray(final Object source) {
		if (source instanceof Object[]) {
			return (Object[]) source;
		}
		if (source == null) {
			return new Object[0];
		}
		if (!source.getClass().isArray()) {
			throw new IllegalArgumentException("Source is not an array: " + source);
		}
		int length = Array.getLength(source);
		if (length == 0) {
			return new Object[0];
		}
		Class<?> wrapperType = Array.get(source, 0).getClass();
		Object[] newArray = (Object[]) Array.newInstance(wrapperType, length);
		for (int i = 0; i < length; i++) {
			newArray[i] = Array.get(source, i);
		}
		return newArray;
	}

	/**
	 * <h3 class="en-US">Convert supplied object (or array) instance to a List</h3>
	 * <span class="en-US">
	 * Convert the supplied array into a List. A primitive array gets
	 * converted into a List of the appropriate wrapper type.
	 * <p>A <code>null</code> source value will be converted to an empty List.
	 * </span>
	 * <h3 class="zh-CN">转换支持的实例对象为列表</h3>
	 * <span class="zh-CN">转换支持的实例对象（数组）为列表。基础数据类型的数据转换为对应包装类对象列表。实例对象为null将返回一个空列表</span>
	 *
	 * @param source <span class="en-US">the (potentially primitive) array</span>
	 *               <span class="zh-CN">可能为基础类型的实例对象（数组）</span>
	 * @return <span class="en-US">the converted List result</span>
	 * <span class="zh-CN">转换后的列表结果</span>
	 */
	public static List<?> toList(final Object source) {
		if (source instanceof Collection) {
			return new ArrayList<>((Collection<?>) source);
		} else if (source instanceof Enumeration) {
			List<Object> list = new ArrayList<>();
			Enumeration<?> enumeration = (Enumeration<?>) source;
			while (enumeration.hasMoreElements()) {
				list.add(enumeration.nextElement());
			}
			return list;
		} else if (source instanceof Iterator) {
			List<Object> list = new ArrayList<>();
			Iterator<?> iterator = (Iterator<?>) source;
			while (iterator.hasNext()) {
				list.add(iterator.next());
			}
			return list;
		} else if (source instanceof Map) {
			return new ArrayList<>(((Map<?, ?>) source).entrySet());
		} else {
			return Arrays.asList(toArray(source));
		}
	}

	/**
	 * <h3 class="en-US">Merge the given array into the given Collection.</h3>
	 * <h3 class="zh-CN">合并给定的数组到给定的集合中</h3>
	 *
	 * @param array      <span class="en-US">the array to merge (maybe <code>null</code>)</span>
	 *                   <span class="zh-CN">要合并的数组（有可能为<code>null</code>）</span>
	 * @param collection <span class="en-US">the target Collection to merge the array into</span>
	 *                   <span class="zh-CN">将数组合并到的目标集合</span>
	 */
	public static void mergeArrayIntoCollection(final Object array, final Collection<Object> collection) {
		if (collection == null) {
			throw new IllegalArgumentException("Collection must not be null");
		}
		Collections.addAll(collection, toArray(array));
	}

	/**
	 * <h3 class="en-US">Merge the given Properties instance into the given Map.</h3>
	 * <span class="en-US">
	 * Merge the given Properties instance into the given Map,
	 * copying all properties (key-value pairs) over.
	 * Uses <code>Properties.propertyNames()</code> to even catch
	 * default properties linked into the original Properties instance.
	 * </span>
	 * <h3 class="zh-CN">合并给定的配置文件实例到给定的Map中</h3>
	 * <span class="en-US">合并给定的配置文件实例到给定的Map中，复制所有的配置键值对。</span>
	 *
	 * @param props <span class="en-US">the Properties instance to merge (maybe <code>null</code>)</span>
	 *              <span class="zh-CN">要合并的属性实例（可能为 null）</span>
	 * @param map   <span class="en-US">the target Map to merge the properties into</span>
	 *              <span class="zh-CN">将属性合并到的目标 Map</span>
	 */
	public static void mergePropertiesIntoMap(final Properties props, final Map<Object, Object> map) {
		if (map == null) {
			throw new IllegalArgumentException("Map must not be null");
		}
		if (props != null) {
			for (Enumeration<?> en = props.propertyNames(); en.hasMoreElements(); ) {
				String key = (String) en.nextElement();
				map.put(key, props.getProperty(key));
			}
		}
	}

	/**
	 * <h3 class="en-US">Check whether the given Iterator contains the given element.</h3>
	 * <h3 class="zh-CN">检查给定的迭代器是否包含给定的元素。</h3>
	 *
	 * @param iterator <span class="en-US">the Iterator to check</span>
	 *                 <span class="zh-CN">要检查的迭代器</span>
	 * @param element  <span class="en-US">the element to look for</span>
	 *                 <span class="zh-CN">要寻找的元素</span>
	 * @return <span class="en-US"><code>true</code> if found, <code>false</code> otherwise</span>
	 * <span class="zh-CN">如果找到返回<code>true</code>，否则返回<code>false</code></span>
	 */
	public static <T> boolean contains(final Iterator<T> iterator, final T element) {
		if (iterator != null) {
			while (iterator.hasNext()) {
				if (ObjectUtils.nullSafeEquals(iterator.next(), element)) {
					return Boolean.TRUE;
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Check whether the given Enumeration contains the given element.</h3>
	 * <h3 class="zh-CN">检查给定的枚举是否包含给定的元素。</h3>
	 *
	 * @param enumeration <span class="en-US">the Enumeration to check</span>
	 *                    <span class="zh-CN">要检查的枚举</span>
	 * @param element     <span class="en-US">the element to look for</span>
	 *                    <span class="zh-CN">要寻找的元素</span>
	 * @return <span class="en-US"><code>true</code> if found, <code>false</code> otherwise</span>
	 * <span class="zh-CN">如果找到返回<code>true</code>，否则返回<code>false</code></span>
	 */
	public static <T> boolean contains(final Enumeration<T> enumeration, final T element) {
		if (enumeration != null) {
			while (enumeration.hasMoreElements()) {
				if (ObjectUtils.nullSafeEquals(enumeration.nextElement(), element)) {
					return Boolean.TRUE;
				}
			}
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Check whether the given Collection contains the given element instance.</h3>
	 * <span class="en-US">
	 * Enforces the given instance to be present, rather than returning
	 * <code>true</code> for an equal element as well.
	 * </span>
	 * <h3 class="zh-CN">检查给定的集合是否包含给定的元素实例。</h3>
	 * <span class="zh-CN">强制给定实例存在，而不是对于相等的元素也返回 <code>true</code>。</span>
	 *
	 * @param collection <span class="en-US">the Collection to check</span>
	 *                   <span class="zh-CN">要检查的集合</span>
	 * @param element    <span class="en-US">the element to look for</span>
	 *                   <span class="zh-CN">要寻找的元素</span>
	 * @return <span class="en-US"><code>true</code> if found, <code>false</code> otherwise</span>
	 * <span class="zh-CN">如果找到返回<code>true</code>，否则返回<code>false</code></span>
	 */
	public static <T> boolean contains(final Collection<T> collection, final T element) {
		if (collection != null) {
			return collection.stream().anyMatch(candidate -> ObjectUtils.nullSafeEquals(candidate, element));
		}
		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Check whether the given Collections contains the same element instance.</h3>
	 * <h3 class="zh-CN">检查给定的集合是否包含相同的元素实例。</h3>
	 *
	 * @param source     <span class="en-US">the source Collection</span>
	 *                   <span class="zh-CN">源集合</span>
	 * @param candidates <span class="en-US">the candidates to search for</span>
	 *                   <span class="zh-CN">要搜索的候选元素</span>
	 * @return <span class="en-US"><code>true</code> if found, <code>false</code> otherwise</span>
	 * <span class="zh-CN">如果找到返回<code>true</code>，否则返回<code>false</code></span>
	 */
	public static <T> boolean containsAny(final Collection<T> source, final Collection<T> candidates) {
		if (isEmpty(source) || isEmpty(candidates)) {
			return false;
		}
		return candidates.stream().anyMatch(source::contains);
	}

	/**
	 * <h3 class="en-US">Checks whether the given set contains all candidate element instances.</h3>
	 * <h3 class="zh-CN">检查给定的集合是否包含所有的候选元素实例。</h3>
	 *
	 * @param source     <span class="en-US">the source Collection</span>
	 *                   <span class="zh-CN">源集合</span>
	 * @param candidates <span class="en-US">the candidates to search for</span>
	 *                   <span class="zh-CN">要搜索的候选元素</span>
	 * @return <span class="en-US"><code>true</code> if found, <code>false</code> otherwise</span>
	 * <span class="zh-CN">如果找到返回<code>true</code>，否则返回<code>false</code></span>
	 */
	public static <T> boolean containsAll(final Collection<T> source, final Collection<T> candidates) {
		if (isEmpty(source) || isEmpty(candidates)) {
			return Boolean.FALSE;
		}
		return source.containsAll(candidates);
	}

	/**
	 * <h3 class="en-US">Find the first element of the given Collections contains the same element instance.</h3>
	 * <h3 class="zh-CN">寻找给定的集合包含的第一个相同的元素实例。</h3>
	 *
	 * @param source     <span class="en-US">the source Collection</span>
	 *                   <span class="zh-CN">源集合</span>
	 * @param candidates <span class="en-US">the candidates to search for</span>
	 *                   <span class="zh-CN">要搜索的候选元素</span>
	 * @return <span class="en-US">the first present object, or <code>null</code> if not found</span>
	 * <span class="zh-CN">找到的第一个元素，如果未找到返回<code>null</code></span>
	 */
	public static <T> T findFirstMatch(final Collection<T> source, final Collection<T> candidates) {
		if (isEmpty(source) || isEmpty(candidates)) {
			return null;
		}
		return candidates.stream().filter(source::contains).findFirst().orElse(null);
	}

	/**
	 * <h3 class="en-US">Find a single value of the given type in the given Collection.</h3>
	 * <h3 class="zh-CN">在给定集合中查找给定类型的单个值。</h3>
	 *
	 * @param collection <span class="en-US">the Collection to search</span>
	 *                   <span class="zh-CN">要查询的集合</span>
	 * @param type       <span class="en-US">the type to look for</span>
	 *                   <span class="zh-CN">要寻找的类型</span>
	 * @return <span class="en-US">a value of the given type found if there is a clear match, or <code>null</code> if none or more than one such value found</span>
	 * <span class="zh-CN">如果存在明确匹配，则找到给定类型的值；如果未找到或找到多个此类值，则返回 null</code></span>
	 */
	public static <T> T findValueOfType(final Collection<T> collection, final Class<T> type) {
		if (isEmpty(collection) || type == null) {
			return null;
		}
		return collection.stream()
				.filter(type::isInstance)
				.findFirst()
				.orElse(null);
	}

	/**
	 * <h3 class="en-US">Find a single value of one of the given types in the given Collection</h3>
	 * <span class="en-US">
	 * searching the Collection for a value of the first type, then
	 * searching for a value of the second type, etc.
	 * </span>
	 * <h3 class="zh-CN">在给定集合中查找给定类型之一的单个值</h3>
	 * <span class="zh-CN">在 Collection 中搜索第一种类型的值，然后搜索第二种类型的值，依此类推。</span>
	 *
	 * @param collection <span class="en-US">the Collection to search</span>
	 *                   <span class="zh-CN">要查询的集合</span>
	 * @param types      <span class="en-US">the types to look for, in prioritized order</span>
	 *                   <span class="zh-CN">要查找的类型（按优先顺序）</span>
	 * @return <span class="en-US">a value of the given type found if there is a clear match, or <code>null</code> if none or more than one such value found</span>
	 * <span class="zh-CN">如果存在明确匹配，则找到给定类型的值；如果未找到或找到多个此类值，则返回 null</code></span>
	 */
	public static <T> T findValueOfTypes(final Collection<T> collection, final Class<T>[] types) {
		if (isEmpty(collection) || isEmpty(types)) {
			return null;
		}
		for (Class<T> type : types) {
			T value = findValueOfType(collection, type);
			if (value != null) {
				return value;
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Determine whether the given Collection only contains a single unique object.</h3>
	 * <h3 class="zh-CN">确定给定的集合是否仅包含单个唯一对象。</h3>
	 *
	 * @param collection <span class="en-US">the Collection to check</span>
	 *                   <span class="zh-CN">要检查的集合</span>
	 * @return <span class="en-US">
	 * <code>true</code> if the collection contains a single reference
	 * or multiple references to the same instance, <code>false</code> else
	 * </span>
	 * <span class="zh-CN">如果集合包含对同一实例的单个引用或多个引用，则为 <code>true</code>，否则为 <code>false</code></span>
	 */
	public static boolean hasUniqueObject(final Collection<?> collection) {
		if (isEmpty(collection)) {
			return Boolean.FALSE;
		}
		boolean hasCandidate = Boolean.FALSE;
		Object candidate = null;
		for (Object elem : collection) {
			if (!hasCandidate) {
				hasCandidate = Boolean.TRUE;
				candidate = elem;
			} else if (candidate != elem) {
				return Boolean.FALSE;
			}
		}
		return Boolean.TRUE;
	}
}
