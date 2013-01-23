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

import javax.swing.text.JTextComponent;

import com.servoy.j2db.IApplication;
import com.servoy.j2db.ui.IFieldComponent;
import com.servoy.j2db.ui.IStylePropertyChangesRecorder;
import com.servoy.j2db.ui.runtime.IRuntimeComponent;
import com.servoy.j2db.ui.runtime.IRuntimeTextArea;
import com.servoy.j2db.util.Utils;

/**
 * Scriptable text area.
 * 
 * @author lvostinar
 * @since 6.0
 */
public class RuntimeTextArea extends AbstractRuntimeTextComponent<IFieldComponent, JTextComponent> implements IRuntimeTextArea
{
	public RuntimeTextArea(IStylePropertyChangesRecorder jsChangeRecorder, IApplication application)
	{
		super(jsChangeRecorder, application);
	}

	public String getElementType()
	{
		return IRuntimeComponent.TEXT_AREA;
	}

	public String getPlaceholderText()
	{
		return getComponent().getPlaceholderText();
	}

	public void setPlaceholderText(String placeholder)
	{
		if (!Utils.safeEquals(placeholder, getPlaceholderText()))
		{
			getComponent().setPlaceholderText(placeholder);
			getChangesRecorder().setChanged();
		}
	}
}
