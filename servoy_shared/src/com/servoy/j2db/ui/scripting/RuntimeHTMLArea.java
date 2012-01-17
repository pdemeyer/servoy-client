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

package com.servoy.j2db.ui.scripting;

import java.io.IOException;
import java.net.URL;

import javax.swing.JEditorPane;

import com.servoy.j2db.IApplication;
import com.servoy.j2db.ui.IFieldComponent;
import com.servoy.j2db.ui.IStylePropertyChangesRecorder;
import com.servoy.j2db.ui.runtime.IRuntimeComponent;
import com.servoy.j2db.ui.runtime.IRuntimeHtmlArea;
import com.servoy.j2db.util.Debug;

/**
 * Scriptable HTML area component.
 * 
 * @author lvostinar
 * @since 6.0
 */
public class RuntimeHTMLArea extends AbstractRuntimeTextEditor<IFieldComponent, JEditorPane> implements IRuntimeHtmlArea
{
	public RuntimeHTMLArea(IStylePropertyChangesRecorder jsChangeRecorder, IApplication application)
	{
		super(jsChangeRecorder, application);
	}

	@Override
	public void setURL(String url)
	{
		if (textComponent != null)
		{
			try
			{
				(textComponent).setPage(url);
			}
			catch (IOException e)
			{
				Debug.error(e);
			}
		}
	}

	@Override
	public String getURL()
	{
		if (textComponent != null)
		{
			URL url = (textComponent).getPage();
			if (url != null)
			{
				return url.toString();
			}
		}
		return null;
	}

	public String getElementType()
	{
		return IRuntimeComponent.HTML_AREA;
	}
}
