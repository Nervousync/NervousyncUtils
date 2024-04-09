package org.nervousync.beans.barcode;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel;
import jakarta.annotation.Nonnull;
import org.nervousync.beans.image.MarkOptions;
import org.nervousync.builder.Builder;
import org.nervousync.commons.Globals;
import org.nervousync.exceptions.builder.BuilderException;
import org.nervousync.utils.FileUtils;
import org.nervousync.utils.StringUtils;

import java.awt.*;
import java.util.Arrays;

/**
 * <h2 class="en-US">Barcode/QR code generate options</h2>
 * <h2 class="zh-CN">条码/二维码生成选项</h2>
 *
 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
 * @version $Revision: 1.0 $ $Date: Jul 13, 2016 16:41:24 $
 */
public final class CodeOptions {

	/**
	 * <span class="en-US">Generate format type</span>
	 * <span class="zh-CN">生成格式类型</span>
	 */
	private final BarcodeFormat codeFormat;
	/**
	 * <span class="en-US">Width (Unit: pixel)</span>
	 * <span class="zh-CN">宽度（单位：像素）</span>
	 */
	private final int codeWidth;
	/**
	 * <span class="en-US">Height (Unit: pixel)</span>
	 * <span class="zh-CN">高度（单位：像素）</span>
	 */
	private final int codeHeight;
	/**
	 * <span class="en-US">File format</span>
	 * <span class="zh-CN">文件格式</span>
	 */
	private final String fileFormat;
	/**
	 * <span class="en-US">Content charset encoding</span>
	 * <span class="zh-CN">信息编码字符集</span>
	 */
	private final String encoding;
	/**
	 * <span class="en-US">Barcode/QR code color code</span>
	 * <span class="zh-CN">条码/二维码颜色代码</span>
	 */
	private final Color onColor;
	/**
	 * <span class="en-US">Background color code</span>
	 * <span class="zh-CN">背景颜色代码</span>
	 */
	private final Color offColor;
	/**
	 * <span class="en-US">Error correction level</span>
	 * <span class="zh-CN">容错等级</span>
	 */
	private final ErrorCorrectionLevel errorLevel;
	/**
	 * <span class="en-US">Mark options</span>
	 * <span class="zh-CN">水印选项</span>
	 */
	private final MarkOptions markOptions;

	/**
	 * <h3 class="en-US">Private constructor method for Barcode/QR code generate options</h3>
	 * <h3 class="zh-CN">条码/二维码生成选项的私有构造方法</h3>
	 *
	 * @param codeFormat  <span class="en-US">Generate format type</span>
	 *                    <span class="zh-CN">生成格式类型</span>
	 * @param codeWidth   <span class="en-US">Width (Unit: pixel)</span>
	 *                    <span class="zh-CN">宽度（单位：像素）</span>
	 * @param codeHeight  <span class="en-US">Height (Unit: pixel)</span>
	 *                    <span class="zh-CN">高度（单位：像素）</span>
	 * @param fileFormat  <span class="en-US">File format</span>
	 *                    <span class="zh-CN">文件格式</span>
	 * @param encoding    <span class="en-US">Content charset encoding</span>
	 *                    <span class="zh-CN">信息编码字符集</span>
	 * @param onColor     <span class="en-US">Barcode/QR code color code</span>
	 *                    <span class="zh-CN">条码/二维码颜色代码</span>
	 * @param offColor    <span class="en-US">Background color code</span>
	 *                    <span class="zh-CN">背景颜色代码</span>
	 * @param errorLevel  <span class="en-US">Error correction level</span>
	 *                    <span class="zh-CN">容错等级</span>
	 * @param markOptions <span class="en-US">Mark options</span>
	 *                    <span class="zh-CN">水印选项</span>
	 */
	private CodeOptions(@Nonnull final BarcodeFormat codeFormat, final int codeWidth, final int codeHeight,
	                    final String fileFormat, final String encoding,
	                    @Nonnull final Color onColor, @Nonnull final Color offColor,
	                    final ErrorCorrectionLevel errorLevel, final MarkOptions markOptions) {
		this.codeFormat = codeFormat;
		this.codeWidth = codeWidth;
		this.codeHeight = codeHeight;
		this.fileFormat = StringUtils.isEmpty(fileFormat) ? "PNG" : fileFormat;
		this.encoding = StringUtils.isEmpty(encoding) ? Globals.DEFAULT_ENCODING : encoding;
		this.onColor = onColor;
		this.offColor = offColor;
		this.errorLevel = errorLevel;
		this.markOptions = markOptions;
	}

	/**
	 * <h3 class="en-US">Getter method for generate format type</h3>
	 * <h3 class="zh-CN">生成格式类型的Getter方法</h3>
	 *
	 * @return <span class="en-US">Generate format type</span>
	 * <span class="zh-CN">生成格式类型</span>
	 */
	public BarcodeFormat getCodeFormat() {
		return this.codeFormat;
	}

	/**
	 * <h3 class="en-US">Getter method for width</h3>
	 * <h3 class="zh-CN">宽度的Getter方法</h3>
	 *
	 * @return <span class="en-US">Width (Unit: pixel)</span>
	 * <span class="zh-CN">宽度（单位：像素）</span>
	 */
	public int getCodeWidth() {
		return this.codeWidth;
	}

	/**
	 * <h3 class="en-US">Getter method for height</h3>
	 * <h3 class="zh-CN">高度的Getter方法</h3>
	 *
	 * @return <span class="en-US">Height (Unit: pixel)</span>
	 * <span class="zh-CN">高度（单位：像素）</span>
	 */
	public int getCodeHeight() {
		return this.codeHeight;
	}

	/**
	 * <h3 class="en-US">Getter method for file format</h3>
	 * <h3 class="zh-CN">文件格式的Getter方法</h3>
	 *
	 * @return <span class="en-US">File format</span>
	 * <span class="zh-CN">文件格式</span>
	 */
	public String getFileFormat() {
		return this.fileFormat;
	}

	/**
	 * <h3 class="en-US">Getter method for content charset encoding</h3>
	 * <h3 class="zh-CN">信息编码字符集的Getter方法</h3>
	 *
	 * @return <span class="en-US">Content charset encoding</span>
	 * <span class="zh-CN">信息编码字符集</span>
	 */
	public String getEncoding() {
		return this.encoding;
	}

	/**
	 * <h3 class="en-US">Getter method for Barcode/QR code color code</h3>
	 * <h3 class="zh-CN">条码/二维码颜色代码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Barcode/QR code color code</span>
	 * <span class="zh-CN">条码/二维码颜色代码</span>
	 */
	public Color getOnColor() {
		return this.onColor;
	}

	/**
	 * <h3 class="en-US">Getter method for background color code</h3>
	 * <h3 class="zh-CN">背景颜色代码的Getter方法</h3>
	 *
	 * @return <span class="en-US">Background color code</span>
	 * <span class="zh-CN">背景颜色代码</span>
	 */
	public Color getOffColor() {
		return this.offColor;
	}

	/**
	 * <h3 class="en-US">Getter method for error correction level</h3>
	 * <h3 class="zh-CN">容错等级的Getter方法</h3>
	 *
	 * @return <span class="en-US">Error correction level</span>
	 * <span class="zh-CN">容错等级</span>
	 */
	public ErrorCorrectionLevel getErrorLevel() {
		return this.errorLevel;
	}

	/**
	 * <h3 class="en-US">Getter method for mark options</h3>
	 * <h3 class="zh-CN">水印选项的Getter方法</h3>
	 *
	 * @return <span class="en-US">Mark options</span>
	 * <span class="zh-CN">水印选项</span>
	 */
	public MarkOptions getMarkOptions() {
		return this.markOptions;
	}

	/**
	 * <h3 class="en-US">Static method for initialize Barcode/QR code generate options builder</h3>
	 * <h3 class="zh-CN">初始化条码/二维码生成选项的构造器的静态方法</h3>
	 *
	 * @param codeFormat <span class="en-US">Generate format type</span>
	 *                   <span class="zh-CN">生成格式类型</span>
	 * @return <span class="en-US">Initialized Barcode/QR code generate options builder instance object</span>
	 * <span class="zh-CN">初始化的条码/二维码生成选项的构造器实例对象</span>
	 */
	public static OptionsBuilder newBuilder(@Nonnull final BarcodeFormat codeFormat) {
		return new OptionsBuilder(codeFormat);
	}

	/**
	 * <h2 class="en-US">Barcode/QR code generate options builder</h2>
	 * <h2 class="zh-CN">条码/二维码生成选项的构造器</h2>
	 *
	 * @author Steven Wee	<a href="mailto:wmkm0113@gmail.com">wmkm0113@gmail.com</a>
	 * @version $Revision: 1.0 $ $Date: Jul 13, 2016 17:08:12 $
	 */
	public static final class OptionsBuilder implements Builder<CodeOptions> {

		/**
		 * <span class="en-US">Generate format type</span>
		 * <span class="zh-CN">生成格式类型</span>
		 */
		private final BarcodeFormat codeFormat;
		/**
		 * <span class="en-US">Width (Unit: pixel)</span>
		 * <span class="zh-CN">宽度（单位：像素）</span>
		 */
		private int codeWidth = Globals.DEFAULT_VALUE_INT;
		/**
		 * <span class="en-US">Height (Unit: pixel)</span>
		 * <span class="zh-CN">高度（单位：像素）</span>
		 */
		private int codeHeight = Globals.DEFAULT_VALUE_INT;
		/**
		 * <span class="en-US">File format</span>
		 * <span class="zh-CN">文件格式</span>
		 */
		private String fileFormat = "PNG";
		/**
		 * <span class="en-US">Content charset encoding</span>
		 * <span class="zh-CN">信息编码字符集</span>
		 */
		private String encoding = Globals.DEFAULT_ENCODING;
		/**
		 * <span class="en-US">Barcode/QR code color code</span>
		 * <span class="zh-CN">条码/二维码颜色代码</span>
		 */
		private Color onColor = new Color(0, 0, 0);
		/**
		 * <span class="en-US">Background color code</span>
		 * <span class="zh-CN">背景颜色代码</span>
		 */
		private Color offColor = new Color(255, 255, 255);
		/**
		 * <span class="en-US">Error correction level</span>
		 * <span class="zh-CN">容错等级</span>
		 */
		private ErrorCorrectionLevel errorLevel = ErrorCorrectionLevel.L;
		/**
		 * <span class="en-US">Mark options</span>
		 * <span class="zh-CN">水印选项</span>
		 */
		private MarkOptions markOptions = null;

		/**
		 * <h3 class="en-US">Constructor method for Barcode/QR code generate options builder</h3>
		 * <h3 class="zh-CN">条码/二维码生成选项的构造器的构造方法</h3>
		 *
		 * @param codeFormat <span class="en-US">Generate format type</span>
		 *                   <span class="zh-CN">生成格式类型</span>
		 */
		OptionsBuilder(@Nonnull final BarcodeFormat codeFormat) {
			this.codeFormat = codeFormat;
		}

		/**
		 * <h3 class="en-US">Setting for image size</h3>
		 * <h3 class="zh-CN">设置图片尺寸</h3>
		 *
		 * @param codeWidth  <span class="en-US">Width (Unit: pixel)</span>
		 *                   <span class="zh-CN">宽度（单位：像素）</span>
		 * @param codeHeight <span class="en-US">Height (Unit: pixel)</span>
		 *                   <span class="zh-CN">高度（单位：像素）</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder codeSize(final int codeWidth, final int codeHeight) {
			if (codeWidth > Globals.INITIALIZE_INT_VALUE) {
				this.codeWidth = codeWidth;
			}
			if (codeHeight > Globals.INITIALIZE_INT_VALUE) {
				this.codeHeight = codeHeight;
			}
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for image format</h3>
		 * <h3 class="zh-CN">设置图片格式</h3>
		 *
		 * @param fileFormat <span class="en-US">File format</span>
		 *                   <span class="zh-CN">文件格式</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder format(final String fileFormat) {
			if (StringUtils.notBlank(fileFormat)) {
				this.fileFormat = fileFormat;
			}
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for content using charset encoding</h3>
		 * <h3 class="zh-CN">设置信息使用的字符集</h3>
		 *
		 * @param encoding <span class="en-US">Content charset encoding</span>
		 *                 <span class="zh-CN">信息编码字符集</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder useEncoding(final String encoding) {
			if (StringUtils.notBlank(encoding)) {
				this.encoding = encoding;
			}
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for Barcode/QR code color code</h3>
		 * <h3 class="zh-CN">设置条码/二维码颜色代码</h3>
		 *
		 * @param r <span class="en-US">Red color code</span>
		 *          <span class="zh-CN">红色代码值</span>
		 * @param g <span class="en-US">Green color code</span>
		 *          <span class="zh-CN">绿色代码值</span>
		 * @param b <span class="en-US">Blue color code</span>
		 *          <span class="zh-CN">蓝色代码值</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder codeColor(final int r, final int g, final int b) {
			if (this.checkRGB(r, g, b)) {
				this.onColor = new Color(r, g, b);
			}
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for background color code</h3>
		 * <h3 class="zh-CN">设置背景颜色代码</h3>
		 *
		 * @param r <span class="en-US">Red color code</span>
		 *          <span class="zh-CN">红色代码值</span>
		 * @param g <span class="en-US">Green color code</span>
		 *          <span class="zh-CN">绿色代码值</span>
		 * @param b <span class="en-US">Blue color code</span>
		 *          <span class="zh-CN">蓝色代码值</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder backgroundColor(final int r, final int g, final int b) {
			if (this.checkRGB(r, g, b)) {
				this.offColor = new Color(r, g, b);
			}
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for error correction level</h3>
		 * <h3 class="zh-CN">设置容错等级</h3>
		 *
		 * @param errorLevel <span class="en-US">Error correction level</span>
		 *                   <span class="zh-CN">容错等级</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder errorLevel(@Nonnull final ErrorCorrectionLevel errorLevel) {
			this.errorLevel = errorLevel;
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for image mark option</h3>
		 * <h3 class="zh-CN">设置图片水印</h3>
		 *
		 * @param markLocation <span class="en-US">Mark location. Instance of MarkOptions.MarkLocation</span>
		 *                     <span class="zh-CN">水印位置，MarkOptions.MarkLocation实例对象</span>
		 * @param markPath     <span class="en-US">Mark image path. Only using when markType is MarkType.ICON</span>
		 *                     <span class="zh-CN">水印图片地址，仅当markType值为MarkType.ICON时有效</span>
		 * @param transparency <span class="en-US">Transparent value of mark image. default is 1, valid value is between 0 and 1</span>
		 *                     <span class="zh-CN">水印图片的透明度，默认值为1，有效值在0到1之间</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder markIcon(final MarkOptions.MarkLocation markLocation, final String markPath,
		                               final float transparency) {
			this.markOptions = MarkOptions.markIcon(markLocation, markPath, transparency);
			return this;
		}

		/**
		 * <h3 class="en-US">Setting for text mark option</h3>
		 * <h3 class="zh-CN">设置文字水印</h3>
		 *
		 * @param markLocation <span class="en-US">Mark location. Instance of MarkOptions.MarkLocation</span>
		 *                     <span class="zh-CN">水印位置，MarkOptions.MarkLocation实例对象</span>
		 * @param markText     <span class="en-US">Mark text value. Only using when markType is MarkType.TEXT</span>
		 *                     <span class="zh-CN">水印文字，仅当markType值为MarkType.TEXT时有效</span>
		 * @param color        <span class="en-US">Mark text color settings.</span>
		 *                     <span class="zh-CN">水印文字的颜色值</span>
		 * @param fontName     <span class="en-US">Mark text font name settings.</span>
		 *                     <span class="zh-CN">水印文字的字体名</span>
		 * @param fontSize     <span class="en-US">Mark text font size settings.</span>
		 *                     <span class="zh-CN">水印文字的字号</span>
		 * @return <span class="en-US">Current builder instance object</span>
		 * <span class="zh-CN">当前构建器实例对象</span>
		 */
		public OptionsBuilder markText(final MarkOptions.MarkLocation markLocation, final String markText,
		                               final Color color, final String fontName, final int fontSize) {
			this.markOptions = MarkOptions.markText(markLocation, markText, color, fontName, fontSize);
			return this;
		}

		@Override
		public CodeOptions confirm() throws BuilderException {
			if (this.codeWidth <= Globals.INITIALIZE_INT_VALUE || this.codeHeight <= Globals.INITIALIZE_INT_VALUE) {
				throw new BuilderException(0x0000001D0001L);
			}
			if (this.markOptions != null && !FileUtils.canRead(this.markOptions.getMarkPath())) {
				throw new BuilderException(0x0000001D0002L);
			}
			return new CodeOptions(this.codeFormat, this.codeWidth, this.codeHeight,
					this.fileFormat, this.encoding, this.onColor, this.offColor, this.errorLevel, this.markOptions);
		}

		/**
		 * <h3 class="en-US">Checking for given color code value is valid</h3>
		 * <h3 class="zh-CN">检查给定的颜色代码值是否有效</h3>
		 *
		 * @param codes <span class="en-US">Color code value array</span>
		 *              <span class="zh-CN">颜色代码数组</span>
		 * @return <span class="en-US">Check result</span>
		 * <span class="zh-CN">检查结果</span>
		 */
		private boolean checkRGB(final int... codes) {
			return Arrays.stream(codes).allMatch(code -> (code >= 0 && code <= 255));
		}
	}
}
