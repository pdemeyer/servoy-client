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
package com.servoy.j2db.documentation;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;
import org.dom4j.io.OutputFormat;
import org.dom4j.io.XMLWriter;

import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.keyword.Ident;
import com.servoy.j2db.util.keyword.RhinoKeywords;
import com.servoy.j2db.util.keyword.SQLKeywords;

/**
 * Takes care of the reserved keywords part of the documentation. Manages 
 * several lists of reserved keywords for different categories.
 * 
 * @author gerzse
 */
public class ReservedKeywordsManager implements IAggregatedDocumentation
{
	public static final String CATEGORY_RHINO = "rhino"; //$NON-NLS-1$
	public static final String CATEGORY_SERVOY_SCRIPTING = "servoy_scripting"; //$NON-NLS-1$
	public static final String CATEGORY_SERVOY_DATAPROVIDERS = "servoy_dataproviders"; //$NON-NLS-1$

	private static final String TAG_KEYWORDS = "reservedKeywords"; //$NON-NLS-1$

	private final Map<String, ReservedKeywordsList> kwByCategory = new HashMap<String, ReservedKeywordsList>();

	public void addKeyword(String category, String keyword)
	{
		ReservedKeywordsList kwList;
		if (kwByCategory.containsKey(category))
		{
			kwList = kwByCategory.get(category);
		}
		else
		{
			kwList = new ReservedKeywordsList(category);
			kwByCategory.put(category, kwList);
		}
		kwList.addKeyword(keyword);
	}


	public Element getAggregatedElement(boolean pretty)
	{
		Element root = DocumentHelper.createElement(TAG_KEYWORDS);
		for (String key : kwByCategory.keySet())
		{
			ReservedKeywordsList kwList = kwByCategory.get(key);
			root.add(kwList.toXML());
		}
		return root;
	}

	public Element toXML(String filename, boolean pretty)
	{
		Document document = DocumentHelper.createDocument();
		document.addComment("This file is automatically generated. Don't bother editing it, because your changes will probably be lost at the next build."); //$NON-NLS-1$

		Element root = getAggregatedElement(pretty);
		document.add(root);

		OutputFormat outformat = OutputFormat.createPrettyPrint();
		outformat.setEncoding("UTF-8"); //$NON-NLS-1$

		try
		{
			XMLWriter writer = new XMLWriter(new PrintWriter(new File(filename)), outformat);
			writer.write(document);
			writer.flush();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}

		return root;
	}

	public static ReservedKeywordsManager fromXML(Element root)
	{
		if (!root.getName().equals(TAG_KEYWORDS))
		{
			Debug.error("Please provide an <" + TAG_KEYWORDS + "> element for extracting lists of keywords."); //$NON-NLS-1$//$NON-NLS-2$
			return null;
		}
		ReservedKeywordsManager kwManager = new ReservedKeywordsManager();

		Iterator<Element> kwIter = root.elementIterator();
		while (kwIter.hasNext())
		{
			Element kw = kwIter.next();
			ReservedKeywordsList kwList = ReservedKeywordsList.fromXML(kw);
			kwManager.kwByCategory.put(kwList.getCategory(), kwList);
		}

		return kwManager;
	}

	public static ReservedKeywordsManager buildForServoy()
	{
		ReservedKeywordsManager result = new ReservedKeywordsManager();
		for (String s : RhinoKeywords.keywords)
			result.addKeyword(CATEGORY_RHINO, s);

		for (String s : Ident.keywords)
			result.addKeyword(CATEGORY_SERVOY_DATAPROVIDERS, s);
		for (String s : SQLKeywords.keywords)
			result.addKeyword(CATEGORY_SERVOY_DATAPROVIDERS, s);
		return result;
	}
}
