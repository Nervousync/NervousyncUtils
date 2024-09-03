package org.nervousync.utils;

import com.google.zxing.*;
import com.google.zxing.client.j2se.BufferedImageLuminanceSource;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.common.HybridBinarizer;
import org.nervousync.beans.barcode.CodeOptions;
import org.nervousync.commons.Globals;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.util.Hashtable;
import java.util.Optional;

/**
 * <h2 class="en-US">Barcode Utilities</h2>
 * <span class="en-US">
 * <span>Current utilities implements features:</span>
 * <p>
 * One-dimensional barcode supports UPC-A, UPC-E, EAN-8, Code 39, Code 93 and other formats,
 * and two-dimensional barcode supports QR Code, Data Matrix, PDF 417, MaxiCode and other formats.
 * </p>
 *     <ul>Generate barcode information</ul>
 *     <ul>Parse barcode information in pictures</ul>
 * </span>
 * <h2 class="zh-CN">条码工具集</h2>
 * <span class="zh-CN">
 *     <span>此工具集实现以下功能:</span>
 *     <p>一维条码支持UPC-A，UPC-E，EAN-8，Code 39，Code 93等格式，二维条码支持QR Code，Data Matrix，PDF 417，MaxiCode等格式</p>
 *     <ul>生成条码信息</ul>
 *     <ul>解析图片中的条码信息</ul>
 * </span>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0.0 $ $Date: Nov 13, 2023 18:51:21 $
 */
public final class BarCodeUtils {

	/**
	 * <span class="en-US">Multilingual supported logger instance</span>
	 * <span class="zh-CN">多语言支持的日志对象</span>
	 */
	private static final LoggerUtils.Logger LOGGER = LoggerUtils.getLogger(BarCodeUtils.class);

	/**
	 * <h3 class="en-US">Generate barcode images based on given information</h3>
	 * <h3 class="zh-CN">根据给定的信息生成条码图片</h3>
	 *
	 * @param contents    <span class="en-US">barcode content</span>
	 *                    <span class="zh-CN">条码内容</span>
	 * @param codeOptions <span class="en-US">barcode options</span>
	 *                    <span class="zh-CN">条码选项</span>
	 * @param savePath    <span class="en-US">Generate image saving address</span>
	 *                    <span class="zh-CN">生成图片保存地址</span>
	 * @return <span class="en-US">Generate result</span>
	 * <span class="zh-CN">生成结果</span>
	 */
	public static boolean generate(final String contents, final CodeOptions codeOptions, final String savePath) {
		if (codeOptions == null || codeOptions.getCodeHeight() <= 0 || codeOptions.getCodeWidth() <= 0) {
			return Boolean.FALSE;
		}

		try {
			int index = savePath.lastIndexOf(Globals.DEFAULT_PAGE_SEPARATOR);
			String homePath = savePath.substring(0, index);
			FileUtils.makeDir(homePath);
			return BarCodeUtils.generate(contents, codeOptions, new FileOutputStream(savePath));
		} catch (FileNotFoundException e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}

		return Boolean.FALSE;
	}

	/**
	 * <h3 class="en-US">Generate barcode images based on given information</h3>
	 * <h3 class="zh-CN">根据给定的信息生成条码图片</h3>
	 *
	 * @param contents     <span class="en-US">barcode content</span>
	 *                     <span class="zh-CN">条码内容</span>
	 * @param codeOptions  <span class="en-US">barcode options</span>
	 *                     <span class="zh-CN">条码选项</span>
	 * @param outputStream <span class="en-US">Image information output stream</span>
	 *                     <span class="zh-CN">图片信息输出流</span>
	 * @return <span class="en-US">Generate result</span>
	 * <span class="zh-CN">生成结果</span>
	 */
	public static boolean generate(final String contents, final CodeOptions codeOptions,
	                               final OutputStream outputStream) {
		if (codeOptions == null || codeOptions.getCodeHeight() <= 0 || codeOptions.getCodeWidth() <= 0) {
			return Boolean.FALSE;
		}

		return Optional.ofNullable(BarCodeUtils.generate(contents, codeOptions))
				.map(bufferedImage -> {
					try {
						ImageIO.write(bufferedImage, codeOptions.getFileFormat(), outputStream);
						return Boolean.TRUE;
					} catch (IOException e) {
						return Boolean.FALSE;
					}
				})
				.orElse(Boolean.FALSE);
	}

	/**
	 * <h3 class="en-US">Generate barcode images based on given information</h3>
	 * <h3 class="zh-CN">根据给定的信息生成条码图片</h3>
	 *
	 * @param contents    <span class="en-US">barcode content</span>
	 *                    <span class="zh-CN">条码内容</span>
	 * @param codeOptions <span class="en-US">barcode options</span>
	 *                    <span class="zh-CN">条码选项</span>
	 * @return <span class="en-US">Generated BufferedImage instance object</span>
	 * <span class="zh-CN">生成的BufferedImage实例对象</span>
	 */
	public static BufferedImage generate(final String contents, final CodeOptions codeOptions) {
		if (codeOptions == null || codeOptions.getCodeHeight() <= 0 || codeOptions.getCodeWidth() <= 0) {
			return null;
		}

		try {
			Hashtable<EncodeHintType, Object> hints = new Hashtable<>();

			hints.put(EncodeHintType.ERROR_CORRECTION, codeOptions.getErrorLevel());
			hints.put(EncodeHintType.CHARACTER_SET, codeOptions.getEncoding());

			BitMatrix bitMatrix = new MultiFormatWriter().encode(contents, codeOptions.getCodeFormat(),
					codeOptions.getCodeWidth(), codeOptions.getCodeHeight(), hints);
			BufferedImage bufferedImage =
					new BufferedImage(codeOptions.getCodeWidth(), codeOptions.getCodeHeight(), BufferedImage.TYPE_INT_RGB);
			for (int x = 0; x < bitMatrix.getWidth(); x++) {
				for (int y = 0; y < bitMatrix.getHeight(); y++) {
					bufferedImage.setRGB(x, y,
							bitMatrix.get(x, y) ? codeOptions.getOnColor().getRGB() : codeOptions.getOffColor().getRGB());
				}
			}
			if (codeOptions.getMarkOptions() != null) {
				ImageUtils.markImage(bufferedImage, codeOptions.getMarkOptions());
			}
			return bufferedImage;
		} catch (Exception e) {
			if (LOGGER.isDebugEnabled()) {
				LOGGER.debug("Stack_Message_Error", e);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Parse the barcode information in the given image binary information</h3>
	 * <h3 class="zh-CN">解析给定的图片二进制信息中的条码信息</h3>
	 *
	 * @param imageBytes <span class="en-US">The binary data of the image</span>
	 *                   <span class="zh-CN">图片的二进制数据</span>
	 * @param encoding   <span class="en-US">Data information encoding set</span>
	 *                   <span class="zh-CN">数据信息编码集</span>
	 * @return <span class="en-US">Parsed data information, if an error occurs, <code>null</code> is returned</span>
	 * <span class="zh-CN">解析的数据信息，如果出错则返回<code>null</code></span>
	 */
	public static String parse(final byte[] imageBytes, final String encoding) {
		if (imageBytes != null && imageBytes.length > 0) {
			return BarCodeUtils.parse(new ByteArrayInputStream(imageBytes), encoding);
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Parse the barcode information in the given input stream</h3>
	 * <h3 class="zh-CN">解析给定的输入流中的条码信息</h3>
	 *
	 * @param inputStream <span class="en-US">Input stream instance object</span>
	 *                    <span class="zh-CN">输入流实例对象</span>
	 * @param encoding    <span class="en-US">Data information encoding set</span>
	 *                    <span class="zh-CN">数据信息编码集</span>
	 * @return <span class="en-US">Parsed data information, if an error occurs, <code>null</code> is returned</span>
	 * <span class="zh-CN">解析的数据信息，如果出错则返回<code>null</code></span>
	 */
	public static String parse(final InputStream inputStream, final String encoding) {
		if (inputStream != null) {
			try {
				return BarCodeUtils.parse(ImageIO.read(inputStream), encoding);
			} catch (IOException e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			} finally {
				IOUtils.closeStream(inputStream);
			}
		}
		return null;
	}

	/**
	 * <h3 class="en-US">Parse the barcode information in the given BufferedImage instance object</h3>
	 * <h3 class="zh-CN">解析给定的BufferedImage实例对象中的条码信息</h3>
	 *
	 * @param bufferedImage <span class="en-US">BufferedImage instance object</span>
	 *                      <span class="zh-CN">BufferedImage实例对象</span>
	 * @param encoding      <span class="en-US">Data information encoding set</span>
	 *                      <span class="zh-CN">数据信息编码集</span>
	 * @return <span class="en-US">Parsed data information, if an error occurs, <code>null</code> is returned</span>
	 * <span class="zh-CN">解析的数据信息，如果出错则返回<code>null</code></span>
	 */
	public static String parse(final BufferedImage bufferedImage, final String encoding) {
		String decodeResult = null;
		if (bufferedImage != null) {
			try {
				LuminanceSource luminanceSource = new BufferedImageLuminanceSource(bufferedImage);
				BinaryBitmap binaryBitmap = new BinaryBitmap(new HybridBinarizer(luminanceSource));

				Hashtable<DecodeHintType, Object> hints = new Hashtable<>();
				if (StringUtils.isEmpty(encoding)) {
					hints.put(DecodeHintType.CHARACTER_SET, Globals.DEFAULT_ENCODING);
				} else {
					hints.put(DecodeHintType.CHARACTER_SET, encoding);
				}

				Result result = new MultiFormatReader().decode(binaryBitmap, hints);
				decodeResult = result.getText();
			} catch (Exception e) {
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug("Stack_Message_Error", e);
				}
			}
		}
		return decodeResult;
	}
}
