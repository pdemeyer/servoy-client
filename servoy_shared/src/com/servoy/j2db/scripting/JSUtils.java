/*
 This file belongs to the Servoy development and deployment environment, Copyright (C) 1997-2010 Servoy BV

 This program is free software; you can redistribute it and/or modify it under
 the terms of the GNU Affero General Public License as published by the Free
 Software Foundation; either version 3 of the License, or (at your option) any
 later version.

 This program is distributed in the hope that it will be useful, but WITHOUT
 ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License along
 with this program; if not, see http://www.gnu.org/licenses or write to the Free
 Software Foundation,Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
*/
package com.servoy.j2db.scripting;


import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.StringTokenizer;

import org.mozilla.javascript.ScriptRuntime;

import com.servoy.j2db.IApplication;
import com.servoy.j2db.dataprocessing.FoundSet;
import com.servoy.j2db.dataprocessing.IRecordInternal;
import com.servoy.j2db.dataprocessing.JSDatabaseManager;
import com.servoy.j2db.dataprocessing.TagResolver;
import com.servoy.j2db.documentation.ServoyDocumented;
import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.Text;
import com.servoy.j2db.util.Utils;

/**
 * @author Jan Blok
 */
@ServoyDocumented(category = ServoyDocumented.RUNTIME, publicName = "Utils", scriptingName = "utils")
public class JSUtils
{
	private volatile IApplication application;

	public JSUtils(IApplication application)
	{
		this.application = application;
	}

	/**
	 * @see com.servoy.j2db.scripting.JSUtils#js_hasRecords(Object[])
	 */
	@Deprecated
	public boolean js_hasChildRecords(Object foundset)
	{
		return js_hasRecords(new Object[] { foundset });
	}

	/**
	 * Returns true if the (related)foundset exists and has records.
	 * Another use is, to pass a record and qualified relations string to test multiple relations/foundset at once  
	 *
	 * @sample
	 * //test the orders_to_orderitems foundset 
	 * if (%%elementName%%.hasRecords(orders_to_orderitems))
	 * {
	 * 	//do work on relatedFoundSet
	 * }
	 * //test the orders_to_orderitems.orderitems_to_products foundset to be reached from the current record 
	 * //if (%%elementName%%.hasRecords(foundset.getSelectedRecord(),'orders_to_orderitems.orderitems_to_products'))
	 * //{
	 * //	//do work on deeper relatedFoundSet
	 * //}
	 *
	 * @param foundset_or_record the foundset or record to be tested
	 * @param qualifiedRelationString optional the qualified relation string to reach a related foundset if a record is passes as first paramter
	 * @return true if exists 
	 */
	public boolean js_hasRecords(Object[] values)//needed for calcs
	{
		return JSDatabaseManager.hasRecords(values);
	}

	/**
	 * Returns a string containing the character for the unicode number.
	 *
	 * @sample 
	 * //returns a big dot
	 * var dot = utils.getUnicodeCharacter(9679);
	 *
	 * @param unicodeCharacterNumber the number indicating the unicode character
	 * 
	 * @return a string containing the unicode character 
	 */
	public String js_getUnicodeCharacter(int unicodeCharacterNumber)//no cast from int to char possible in javascript
	{
		return Character.toString((char)unicodeCharacterNumber);
	}

	/**
	 * Returns the text with % %tags%% replaced, based on provided record or foundset.
	 *
	 * @sample
	 * //Next line places a string in variable x, whereby the tag(% %TAG%%) is filled with the value of the database column 'company_name' of the selected record.
	 * var x = utils.stringReplaceTags("The companyName of the selected record is % %company_name%% ", foundset)
	 * //var otherExample = utils.stringReplaceTags("The amount of the related order line % %amount%% ", order_to_orderdetails);
	 * //var recordExample = utils.stringReplaceTags("The amount of the related order line % %amount%% ", order_to_orderdetails.getRecord(i);
	 *
	 * @param text the text tags to work with
	 * @param foundset_or_record the foundset or record to be used to fill in the tags
	 * @return the text with replaced tags
	 */
	public String js_stringReplaceTags(Object text, Object foundset_or_record)
	{
		if (text != null)
		{
			IRecordInternal record = null;
			if (foundset_or_record instanceof FoundSet)
			{
				record = ((FoundSet)foundset_or_record).getRecord(((FoundSet)foundset_or_record).getSelectedIndex());
			}
			else if (foundset_or_record instanceof IRecordInternal)
			{
				record = (IRecordInternal)foundset_or_record;
			}
			if (record != null)
			{
				return Text.processTags(TagResolver.formatObject(text, record.getParentFoundSet().getFoundSetManager().getApplication().getSettings()),
					TagResolver.createResolver(record));
			}
			return ""; //$NON-NLS-1$
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Returns true when Monday is the first day of the week for your current locale setting.
	 *
	 * @sample
	 * if(utils.isMondayFirstDayOfWeek())
	 * {
	 * //a date calculation
	 * }
	 * @return true if Monday is first day of the week in current locale
	 */
	public boolean js_isMondayFirstDayOfWeek()
	{
		return Calendar.getInstance().getFirstDayOfWeek() == Calendar.MONDAY;
	}

	/**
	 * Format a date object to a text representation or a parses a datestring to a date object.
	 *
	 * @sample
	 * var parsedDate = utils.dateFormat(datestring,'EEE, d MMM yyyy HH:mm:ss'); 
	 * 
	 * var formattedDateString = utils.dateFormat(dateobject,'EEE, d MMM yyyy HH:mm:ss');
	 *
	 * @param date the date as text or date object
	 * @param format the format to output or parse the to date
	 * @return the date as text or date object
	 */
	public Object js_dateFormat(Object date, Object format)
	{
		if (format != null)
		{
			if (date instanceof Date)
			{
				SimpleDateFormat sdf = new SimpleDateFormat(format.toString(), application.getLocale());
				return sdf.format((Date)date);
			}
			else if (date instanceof String)
			{
				SimpleDateFormat sdf = new SimpleDateFormat(format.toString(), application.getLocale());
				try
				{
					return sdf.parse((String)date);
				}
				catch (ParseException ex)
				{
					Debug.error("Date parsing error: " + date + ", format: " + format, ex); //$NON-NLS-1$//$NON-NLS-2$
					return null;
				}
			}
		}
		return ""; //$NON-NLS-1$
	}

	/** 
	 * Returns a datestamp from the timestamp (sets hours,minutes,seconds and milliseconds to 0).
	 * 
	 * @sample
	 * var date = utils.timestampToDate(application.getTimeStamp());
	 * 
	 * @param date object to be stripped from its time elements
	 * @return the stripped date object
	 */
	public Date js_timestampToDate(Object date)
	{
		if (date instanceof Date)
		{
			Calendar calendar = Calendar.getInstance();
			calendar.setTime((Date)date);
			Utils.applyMinTime(calendar);
			return calendar.getTime();
		}
		return null;
	}

	/**
	 * Returns the number of words, starting from the left.
	 *
	 * @sample 
	 * //returns 'this is a'
	 * var retval = utils.stringLeftWords('this is a test',3);
	 *
	 * @param text to process
	 * @param numberof_words to return
	 * @return the string with number of words form the left  
	 */
	public String js_stringLeftWords(Object text, Object numberof_words)
	{
		if (text != null && numberof_words instanceof Number)
		{
			try
			{
				int words = ((Number)numberof_words).intValue();
				StringBuffer sb = new StringBuffer();
				StringTokenizer st = new StringTokenizer(text.toString(), " "); //$NON-NLS-1$
				int i = 0;
				while (st.hasMoreTokens() && i < words)
				{
					String value = st.nextToken();
					sb.append(value);
					if (st.hasMoreTokens() && i < (words - 1))
					{
						sb.append(" "); //$NON-NLS-1$
					}
					i++;
				}
				return sb.toString();
			}
			catch (Exception ex)
			{
				return text.toString();
			}
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Returns a substring from the original string.
	 *
	 * @sample 
	 * //returns 'is a'
	 * var retval = utils.stringMiddleWords('this is a test',2,2);
	 *
	 * @param text to process 
	 * @param i_start start word index 
	 * @param numberof_words the word count to return
	 * @return the string with number of words form the left and  
	 */
	public String js_stringMiddleWords(Object text, Object i_start, Object numberof_words)
	{
		if (text != null && i_start instanceof Number && numberof_words instanceof Number)
		{
			try
			{
				int start = ((Number)i_start).intValue();
				int words = ((Number)numberof_words).intValue();
				StringBuffer sb = new StringBuffer();
				StringTokenizer st = new StringTokenizer(text.toString(), " "); //$NON-NLS-1$
				start = start - 1;
				int i = 0;
				while (st.hasMoreTokens())
				{
					String value = st.nextToken();
					if (i >= (start) && i < (start + words))
					{
						sb.append(value);
					}
					if (st.hasMoreTokens() && i >= (start) && i < (start + words) - 1)
					{
						sb.append(" "); //$NON-NLS-1$
					}
					i++;
				}
				return sb.toString();
			}
			catch (Exception ex)
			{
				return text.toString();
			}
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Returns the number of words, starting from the right.
	 *
	 * @sample 
	 * //returns 'is a test'
	 * var retval = utils.stringRightWords('this is a test',3);
	 *
	 * @param text to process
	 * @param numberof_words to return
	 * @return the string with number of words form the right  
	 */
	public String js_stringRightWords(Object text, Object numberof_words)
	{
		if (text != null && numberof_words instanceof Number)
		{
			try
			{
				int words = ((Number)numberof_words).intValue();
				StringBuffer sb = new StringBuffer();
				StringTokenizer st = new StringTokenizer(text.toString(), " "); //$NON-NLS-1$
				int i = 0;
				int countwords = st.countTokens();
				while (st.hasMoreTokens())
				{
					String value = st.nextToken();
					if (countwords - words <= i)
					{
						sb.append(value);
						if (st.hasMoreTokens())
						{
							sb.append(" "); //$NON-NLS-1$
						}
					}
					i++;
				}
				return sb.toString();
			}
			catch (Exception ex)
			{
				return text.toString();
			}
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Returns the number of times searchString appears in textString.
	 *
	 * @sample 
	 * //returns 2 as count
	 * var count = utils.stringPatternCount('this is a test','is');
	 *
	 * @param textString the text to process
	 * @param searchString the string to search
	 * @return the occurrenceCount that the search string is found in the text 
	 */
	public int js_stringPatternCount(Object textString, Object searchString)
	{
		if (textString != null && searchString != null)
		{
			if ("".equals(searchString)) return -1; //$NON-NLS-1$

			if (searchString instanceof Double)
			{
				searchString = ScriptRuntime.numberToString(((Double)searchString).doubleValue(), 10);
			}
			try
			{
				String text = textString.toString();
				String search = searchString.toString();
				int length = search.length();
				int i = 0;
				int index = text.indexOf(search);
				while (index != -1)
				{
					i++;
					index = text.indexOf(search, index + length);
				}
				return i;
			}
			catch (Exception ex)
			{
				return -1;
			}
		}
		else
		{
			return -1;
		}
	}

	/**
	 * Returns the position of the string to seach for, from a certain start position and occurrence.
	 *
	 * @sample 
	 * //returns 4 as position
	 * var pos = utils.stringPosition('This is a test','s',1,1)
	 *
	 * @param textString the text to process
	 * @param searchString the string to search
	 * @param i_start the start index to search from 
	 * @param i_occurrence the occurrence 
	 * 
	 * @return the position 
	 */
	public int js_stringPosition(Object textString, Object searchString, Object i_start, Object i_occurrence)
	{
		if (textString != null && searchString != null && i_start instanceof Number && i_occurrence instanceof Number)
		{
			if (searchString instanceof Double)
			{
				searchString = ScriptRuntime.numberToString(((Double)searchString).doubleValue(), 10);
			}

			try
			{
				int start = ((Number)i_start).intValue() - 1;
				if (start < 0) start = 0;

				int occurrence = ((Number)i_occurrence).intValue();
				if (occurrence == 0) occurrence = 1;

				String search = searchString.toString();
				String text = textString.toString();

				int length = search.length();
				if (text.length() <= start) return -1;

				if (occurrence < 0)
				{
					occurrence = occurrence * -1;
					int i = 0;
					int index = text.lastIndexOf(search, start);
					while (index != -1)
					{
						i++;
						if (occurrence == i)
						{
							return index + 1;
						}
						index = text.lastIndexOf(search, index);
					}

				}
				else
				{
					int i = 0;
					int index = text.indexOf(search, start);
					while (index != -1)
					{
						i++;
						if (occurrence == i)
						{
							return index + 1;
						}
						index = text.indexOf(search, index + length);
					}
				}
			}
			catch (Exception ex)
			{
				Debug.error("Error in utils.stringPosition", ex); //$NON-NLS-1$
			}
		}
		return -1;
	}

	/**
	 * Replaces a portion of a string with replacement text from a specfied index.
	 *
	 * @sample 
	 * //returns 'this was a test'
	 * var retval = utils.stringIndexReplace('this is a test',6,2,'was');
	 *
	 * @param textString the text to process
	 * @param i_start the start index to work from 
	 * @param i_size the size of the text to replace 
	 * @param replacement_text the replacement text
	 * @return the changed text string
	 */
	@SuppressWarnings("nls")
	public String js_stringIndexReplace(Object textString, Object i_start, Object i_size, Object replacement_text)
	{
		if (textString != null && i_start instanceof Number && i_size instanceof Number)
		{
			String text = textString.toString();
			try
			{
				if (replacement_text instanceof Double)
				{
					replacement_text = ScriptRuntime.numberToString(((Double)replacement_text).doubleValue(), 10);
				}

				int start = ((Number)i_start).intValue();
				int size = ((Number)i_size).intValue();
				start = start - 1;
				String left = text.substring(0, start);
				String right = text.substring(start + size, text.length());
				return left + String.valueOf(replacement_text) + right;
			}
			catch (Exception ex)
			{
				return text;
			}
		}
		else
		{
			return textString == null ? "" : String.valueOf(textString);
		}
	}

	/**
	 * Replaces a portion of a string with replacement text.
	 *
	 * @sample 
	 * //returns 'these are cow 1 and cow 2.'
	 * var retval = utils.stringReplace('these are test 1 and test 2.','test','cow');
	 *
	 * @param text the text to process
	 * @param search_text the string to search
	 * @param replacement_text the replacement text
	 * 
	 * @return the changed text string
	 */
	@SuppressWarnings("nls")
	public String js_stringReplace(Object text, Object search_text, Object replacement_text)
	{
		if (text != null && search_text != null)
		{
			if (replacement_text instanceof Double)
			{
				replacement_text = ScriptRuntime.numberToString(((Double)replacement_text).doubleValue(), 10);
			}
			return Utils.stringReplace(text.toString(), search_text.toString(), String.valueOf(replacement_text));
		}
		else
		{
			return text == null ? "" : String.valueOf(text);
		}
	}

	/**
	 * Returns a string with the requested number of characters, starting from the left.
	 *
	 * @sample 
	 * //returns 'this i'
	 * var retval = utils.stringLeft('this is a test',6);
	 *
	 * @param textString the text to process
	 * @param i_size the size of the text to return 
	 * @return the result text string
	 */
	public String js_stringLeft(Object textString, Object i_size)
	{
		if (textString != null && i_size instanceof Number)
		{
			String text = textString.toString();
			try
			{
				int pos = ((Number)i_size).intValue();
				return text.substring(0, pos);
			}
			catch (Exception ex)
			{
				return text;
			}
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Returns a substring from the original string.
	 *
	 * @sample 
	 * //returns 'his'
	 * var retval = utils.stringMiddle('this is a test',2,3);
	 *
	 * @param textString the text to process
	 * @param i_start the start index to work from 
	 * @param i_size the size of the text to return 
	 * @return the result text string
	 */
	public String js_stringMiddle(Object textString, Object i_start, Object i_size)
	{
		if (textString != null && i_start instanceof Number && i_size instanceof Number)
		{
			String text = textString.toString();
			int start = ((Number)i_start).intValue();
			int length = ((Number)i_size).intValue();
			try
			{
				start = start - 1;//Filemaker starts counting at 1>>Java at 0
				return text.substring((start), (start + length));
			}
			catch (Exception ex)
			{
				return text.substring((start), text.length());
			}
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Returns a string with the requested number of characters, starting from the right.
	 *
	 * @sample 
	 * //returns 'a test'
	 * var retval = utils.stringLeft('this is a test',6);
	 *
	 * @param textString the text to process
	 * @param i_size the size of the text to return 
	 * @return the result text string
	 */
	public String js_stringRight(Object textString, Object i_size)
	{
		if (textString != null && i_size instanceof Number)
		{
			String text = textString.toString();
			try
			{
				int pos = ((Number)i_size).intValue();
				return text.substring(text.length() - pos, text.length());
			}
			catch (Exception ex)
			{
				return text;
			}
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Filters characters out of from a string and leaves digits, returns the number.
	 *
	 * @sample 
	 * //returns '65567'
	 * var retval = utils.stringToNumber('fg65gf567'); 
	 *
	 * @param textString the text to process
	 * @return the resulting number
	 */
	public double js_stringToNumber(Object textString)
	{
		if (textString instanceof Number) return ((Number)textString).doubleValue();
		if (textString != null)
		{
			int flag = 0;
			StringBuffer sb = new StringBuffer();
			char[] array = textString.toString().toCharArray();
			for (char element : array)
			{
				Character c = new Character(element);
				String cc = c.toString();
				if (Character.isDigit(element))
				{
					sb.append(element);
				}
				else if (cc != null && cc.equals(".") && flag == 0) //$NON-NLS-1$
				{
					sb.append(element);
					flag = 1;
				}
			}
			String textt = sb.toString();
			try
			{
				return Utils.getAsDouble(textt);
			}
			catch (Exception ex)
			{
				return 0;
			}
		}
		else
		{
			return 0;
		}
	}

	/**
	 * Returns the md5 hash (encoded as base64) for specified text.
	 *
	 * NOTE: MD5 (Message-Digest Algorythm 5) is a hash function with a 128-bit hash value, for more info see: http://en.wikipedia.org/wiki/MD5 
	 * @sample var hashed_password = utils.stringMD5HashBase64(user_password)
	 *
	 * @param textString the text to process
	 * @return the resulting hashString
	 */
	public String js_stringMD5HashBase64(Object textString)
	{
		if (textString != null)
		{
			return Utils.calculateMD5HashBase64(textString.toString());
		}
		else
		{
			return null;
		}
	}

	/**
	 * Returns the md5 hash (encoded as base16) for specified text.
	 * 
	 * NOTE: MD5 (Message-Digest Algorythm 5) is a hash function with a 128-bit hash value, for more info see: http://en.wikipedia.org/wiki/MD5 
	 * @sample var hashed_password = utils.stringMD5HashBase16(user_password)
	 *
	 * @param textString the text to process
	 * @return the resulting hashString
	 */
	public String js_stringMD5HashBase16(Object textString)
	{
		if (textString != null)
		{
			return Utils.calculateMD5HashBase16(textString.toString());
		}
		else
		{
			return null;
		}
	}

	/**
	 * Returns the string without leading or trailing spaces.
	 *
	 * @sample 
	 * //returns 'text'
	 * var retval = utils.stringTrim('   text   ');
	 *
	 * @param textString the text to process
	 * @return the resulting trimmed string
	 */
	public String js_stringTrim(Object textString)
	{
		if (textString != null)
		{
			if (textString instanceof Double)
			{
				textString = ScriptRuntime.numberToString(((Double)textString).doubleValue(), 10);
			}

			return textString.toString().trim();
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Format a number to specification (or to have a defined fraction).
	 *
	 * @sample
	 * var textalNumber = utils.numberFormat(16.749, 2); //returns 16.75
	 * var textalNumber2 = utils.numberFormat(100006.749, '#,###.00'); //returns 100,006.75
	 *
	 * @param number the number to format 
	 * @param digitsOrFormat the format or digits 
	 * @return the resulting number in text
	 */
	public String js_numberFormat(Object number, Object digitsOrFormat)
	{
		if (number != null)
		{
			if (digitsOrFormat instanceof Number)
			{
				int digits = ((Number)digitsOrFormat).intValue();
				double val = Utils.getAsDouble(number);
				double d = 1 / Math.pow(10, digits + 2);
				val += d;
				return Utils.formatNumber(application.getLocale(), val, digits);
			}
			else if (digitsOrFormat instanceof String)
			{
				NumberFormat df = NumberFormat.getNumberInstance(application.getLocale());
				((DecimalFormat)df).applyPattern((String)digitsOrFormat);
				return df.format(Utils.getAsDouble(number));
			}
			return number.toString();
		}
		else
		{
			return ""; //$NON-NLS-1$
		}
	}

	/**
	 * Formats a string according to format specifiers and arguments.
	 *
	 * @sample
	 * // the  format specifier has the syntax: %[argument_index$][flags][width][.precision]conversion
	 * // argument index is 1$, 2$ ...
	 * // flags is a set of characters that modify the output format
	 * // typical values: '+'(The result will always include a sign), ','(The result will include locale-specific grouping separators)
	 * // width is a non-negative decimal integer indicating the minimum number of characters to be written to the output
	 * // precision is a non-negative decimal integer usually used to restrict the number of characters
	 * // conversion is a character indicating how the argument should be formatted
	 * // typical conversion values: b(boolean), s(string), c(character), d(decimal integer), f(floating number), t(prefix for date and time)
	 * // Date/Time Conversions (used after 't' prefix): 
	 * 		// 'H' 	Hour of the day for the 24-hour clock, formatted as two digits with a leading zero as necessary i.e. 00 - 23. 
	 * 		// 'I' 	Hour for the 12-hour clock, formatted as two digits with a leading zero as necessary, i.e. 01 - 12. 
	 * 		// 'k' 	Hour of the day for the 24-hour clock, i.e. 0 - 23. 
	 * 		// 'l' 	Hour for the 12-hour clock, i.e. 1 - 12. 
	 * 		// 'M' 	Minute within the hour formatted as two digits with a leading zero as necessary, i.e. 00 - 59. 
	 * 		// 'S' 	Seconds within the minute, formatted as two digits with a leading zero as necessary, i.e. 00 - 60 ("60" is a special value required to support leap seconds).
	 * 		// 'L' 	Millisecond within the second formatted as three digits with leading zeros as necessary, i.e. 000 - 999.
	 * 		// 'p' 	Locale-specific morning or afternoon marker in lower case, e.g."am" or "pm". Use of the conversion prefix 'T' forces this output to upper case. 
	 * 		// 'z' 	RFC 822 style numeric time zone offset from GMT, e.g. -0800.
	 * 		// 'Z' 	A string representing the abbreviation for the time zone.
	 * 		// 'B' 	Locale-specific full month name, e.g. "January", "February".
	 * 		// 'b' 	Locale-specific abbreviated month name, e.g. "Jan", "Feb". 
	 * 		// 'h' 	Same as 'b'. 
	 * 		// 'A' 	Locale-specific full name of the day of the week, e.g. "Sunday", "Monday" 
	 * 		// 'a' 	Locale-specific short name of the day of the week, e.g. "Sun", "Mon" 
	 * 		// 'C' 	Four-digit year divided by 100, formatted as two digits with leading zero as necessary, i.e. 00 - 99 
	 * 		// 'Y' 	Year, formatted as at least four digits with leading zeros as necessary, e.g. 0092 equals 92 CE for the Gregorian calendar. 
	 * 		// 'y' 	Last two digits of the year, formatted with leading zeros as necessary, i.e. 00 - 99.
	 * 		// 'j' 	Day of year, formatted as three digits with leading zeros as necessary, e.g. 001 - 366 for the Gregorian calendar. 
	 * 		// 'm' 	Month, formatted as two digits with leading zeros as necessary, i.e. 01 - 13. 
	 * 		// 'd' 	Day of month, formatted as two digits with leading zeros as necessary, i.e. 01 - 31 
	 * 		// 'e' 	Day of month, formatted as two digits, i.e. 1 - 31.
	 * 
	 * 		// common compositions for date/time conversion
	 * 		// 'R' 	Time formatted for the 24-hour clock as "%tH:%tM" 
	 * 		// 'T' 	Time formatted for the 24-hour clock as "%tH:%tM:%tS". 
	 * 		// 'r' 	Time formatted for the 12-hour clock as "%tI:%tM:%tS %Tp". The location of the morning or afternoon marker ('%Tp') may be locale-dependent. 
	 * 		// 'D' 	Date formatted as "%tm/%td/%ty". 
	 * 		// 'F' 	ISO 8601 complete date formatted as "%tY-%tm-%td". 
	 * 		// 'c' 	Date and time formatted as "%ta %tb %td %tT %tZ %tY", e.g. "Sun Jul 20 16:17:00 EDT 1969".
	 * 
	 * utils.stringFormat('%s Birthday: %2$tm %2$te,%2$tY',new Array('My',new Date(2009,0,1))) // returns My Birthday: 01 1,2009
	 * utils.stringFormat('The time is: %1$tH:%1$tM:%1$tS',new Array(new Date(2009,0,1,12,0,0))) // returns The time is: 12:00:00
	 * utils.stringFormat('My %s: %2$.0f, my float: %2$.2f',new Array('integer',10)) // returns My integer: 10, my float: 10.00
	 * utils.stringFormat('Today is: %1$tc',new Array(new Date())) // returns current date/time as:  Today is: Fri Feb 20 14:15:54 EET 2009
	 * utils.stringFormat('Today is: %tF',new Array(new Date())) // returns current date as: Today is: 2009-02-20
	 *
	 * @param text_to_format the text to format
	 * @param parameters_array the array with parameters
	 * @return the formatted text
	 */
	public String js_stringFormat(String text_to_format, Object parameters_array)
	{
		if (text_to_format == null) return null;
		if (parameters_array instanceof Object[]) return String.format(text_to_format, (Object[])parameters_array);
		else return text_to_format;
	}

	/**
	 * Returns the number of words in the text string.
	 *
	 * @sample 
	 * //returns '4' as result
	 * var retval = utils.stringWordCount('this is a test');
	 *
	 * @param textString the text to process
	 * @return the word count
	 */
	public int js_stringWordCount(Object textString)
	{
		if (textString != null)
		{
			try
			{
				StringTokenizer st = new StringTokenizer(textString.toString(), " \n\r\t"); //$NON-NLS-1$
				return st.countTokens();
			}
			catch (Exception ex)
			{
				return -1;
			}
		}
		else
		{
			return -1;
		}
	}

	/**
	 * Returns the escaped markup text (HTML/XML).
	 *
	 * @sample var escapedText = utils.stringEscapeMarkup('<html><body>escape me</body></html>')
	 *
	 * @param textString the text to process
	 * @param escapeSpaces optional boolean indicating to escape spaces
	 * @param convertToHtmlUnicodeEscapes optional boolean indicating to use unicode escapes
	 * @return the escaped text
	 */
	public String js_stringEscapeMarkup(Object[] vargs)
	{
		String val = ((vargs.length >= 1 && vargs[0] != null) ? vargs[0].toString() : null);
		CharSequence retval = null;
		if (vargs.length == 1)
		{
			retval = Utils.escapeMarkup(val);
		}
		else if (vargs.length == 2)
		{
			retval = Utils.escapeMarkup(val, Utils.getAsBoolean(vargs[1]));
		}
		else if (vargs.length >= 3)
		{
			retval = Utils.escapeMarkup(val, Utils.getAsBoolean(vargs[1]), Utils.getAsBoolean(vargs[2]));
		}
		return (retval != null ? retval.toString() : null);
	}

	/**
	 * Returns all words starting with capital chars.
	 *
	 * @sample 
	 * //returns 'This Is A Test'
	 * var retval = utils.stringInitCap('This is A test');
	 *
	 * @param text the text to process
	 * 
	 * @return the changed text
	 */
	public String js_stringInitCap(Object text)
	{
		return Utils.stringInitCap(text);
	}

	@Override
	public String toString()
	{
		return "JavaScript Utils"; //$NON-NLS-1$
	}

	public void destroy()
	{
		this.application = null;
	}
}
