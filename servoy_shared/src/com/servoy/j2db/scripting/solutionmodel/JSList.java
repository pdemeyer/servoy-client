/*
 This file belongs to the Servoy development and deployment environment, Copyright (C) 1997-2012 Servoy BV

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

package com.servoy.j2db.scripting.solutionmodel;

import org.mozilla.javascript.annotations.JSFunction;

import com.servoy.base.scripting.solutionhelper.BaseSHList;
import com.servoy.base.scripting.solutionhelper.IBaseSHFormList;
import com.servoy.base.scripting.solutionhelper.IBaseSMFormInternal;
import com.servoy.j2db.documentation.ServoyDocumented;
import com.servoy.j2db.scripting.IJavaScriptType;

/**
 * This class is the representation of a mobile list component/form. 
 * 
 * @author acostescu
 */
@ServoyDocumented(category = ServoyDocumented.RUNTIME)
public class JSList extends BaseSHList implements IJavaScriptType, ISHList, IBaseSHFormList
{
	public JSList(IBaseSMFormInternal listForm)
	{
		super(listForm, listForm);
	}

	/**
	 * Returns the list's form.
	 * @return the list's form.
	 * @sample
	 * newFormList.getForm().dataprovider = formList.getForm().dataprovider;
	 */
	@JSFunction
	public JSForm getForm()
	{
		return (JSForm)getContainer();
	}

}
