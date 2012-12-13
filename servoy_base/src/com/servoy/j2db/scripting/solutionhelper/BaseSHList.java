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

package com.servoy.j2db.scripting.solutionhelper;

import com.servoy.j2db.scripting.api.solutionmodel.IBaseSMButton;
import com.servoy.j2db.scripting.api.solutionmodel.IBaseSMField;
import com.servoy.j2db.scripting.api.solutionmodel.IBaseSMForm;
import com.servoy.j2db.scripting.api.solutionmodel.IBaseSMGraphicalComponent;
import com.servoy.j2db.scripting.api.solutionmodel.IBaseSMMethod;

/**
 * @author acostescu
 */
public class BaseSHList implements IBaseSHList
{

	protected final IBaseSMForm form;
	protected final BaseSolutionHelper solutionHelper;
	private IBaseSMButton textAndActionAndIconButton;
	private IBaseSMGraphicalComponent subtextComponent;
	private IBaseSMField countComponent;
	private IBaseSMField iconComponent;

	public BaseSHList(IBaseSMForm listForm, BaseSolutionHelper solutionHelper)
	{
		this.form = listForm;
		this.solutionHelper = solutionHelper;
	}

	public IBaseSMForm getListForm()
	{
		return form;
	}

	public String getDataSource()
	{
		return form.getDataSource();
	}

	public void setDataSource(String dataSource)
	{
		form.setDataSource(dataSource);
	}

	public String getCountDataProviderID()
	{
		return countComponent != null ? countComponent.getDataProviderID() : null;
	}

	public void setCountDataProviderID(String countDataProviderID)
	{
		createCountComponentIfNeeded();
		countComponent.setDataProviderID(countDataProviderID);
	}

	public String getText()
	{
		return textAndActionAndIconButton != null ? textAndActionAndIconButton.getText() : null;
	}

	public void setText(String text)
	{
		createTextAndActionAndIconButtonIfNeeded();
		textAndActionAndIconButton.setText(text);
	}

	public String getTextDataProviderID()
	{
		return textAndActionAndIconButton != null ? textAndActionAndIconButton.getDataProviderID() : null;
	}

	public void setTextDataProviderID(String textDataPRoviderID)
	{
		createTextAndActionAndIconButtonIfNeeded();
		textAndActionAndIconButton.setDataProviderID(textDataPRoviderID);
	}

	public void setOnAction(IBaseSMMethod method)
	{
		createTextAndActionAndIconButtonIfNeeded();
		textAndActionAndIconButton.setOnAction(method);
	}

	public IBaseSMMethod getOnAction()
	{
		return textAndActionAndIconButton != null ? textAndActionAndIconButton.getOnAction() : null;
	}

	public String getSubtext()
	{
		return subtextComponent != null ? subtextComponent.getText() : null;
	}

	public void setSubtext(String subtext)
	{
		createSubtextComponentIfNeeded();
		subtextComponent.setText(subtext);
	}

	public String getSubtextDataProviderID()
	{
		return subtextComponent != null ? subtextComponent.getDataProviderID() : null;
	}

	public void setSubtextDataProviderID(String subtextDataProviderID)
	{
		createSubtextComponentIfNeeded();
		subtextComponent.setDataProviderID(subtextDataProviderID);
	}

	public String getDataIconType()
	{
		return textAndActionAndIconButton != null ? solutionHelper.getIconType(textAndActionAndIconButton) : null;
	}

	public void setDataIconType(String iconType)
	{
		createTextAndActionAndIconButtonIfNeeded();
		solutionHelper.setIconType(textAndActionAndIconButton, iconType);
	}

	public String getDataIconDataProviderID()
	{
		return iconComponent != null ? iconComponent.getDataProviderID() : null;
	}

	public void setDataIconDataProviderID(String dataIconDataProviderID)
	{
		createIconComponentIfNeeded();
		iconComponent.setDataProviderID(dataIconDataProviderID);
	}

	private void createTextAndActionAndIconButtonIfNeeded()
	{
		if (textAndActionAndIconButton == null)
		{
			textAndActionAndIconButton = form.newButton(null, 0, 0, 0, 0, null);
			solutionHelper.getMobileProperties(textAndActionAndIconButton).setPropertyValue(IMobileProperties.LIST_ITEM_BUTTON, Boolean.TRUE);
		}
	}

	private void createSubtextComponentIfNeeded()
	{
		if (subtextComponent == null)
		{
			subtextComponent = form.newLabel(null, 0, 0, 0, 0);
			solutionHelper.getMobileProperties(subtextComponent).setPropertyValue(IMobileProperties.LIST_ITEM_SUBTEXT, Boolean.TRUE);
		}
	}

	private void createCountComponentIfNeeded()
	{
		if (countComponent == null)
		{
			countComponent = form.newField(null, IBaseSMField.TEXT_FIELD, 0, 0, 0, 0);
			solutionHelper.getMobileProperties(countComponent).setPropertyValue(IMobileProperties.LIST_ITEM_COUNT, Boolean.TRUE);
		}
	}

	private void createIconComponentIfNeeded()
	{
		if (iconComponent == null)
		{
			iconComponent = form.newField(null, IBaseSMField.TEXT_FIELD, 0, 0, 0, 0);
			solutionHelper.getMobileProperties(iconComponent).setPropertyValue(IMobileProperties.LIST_ITEM_IMAGE, Boolean.TRUE);
		}
	}

}
