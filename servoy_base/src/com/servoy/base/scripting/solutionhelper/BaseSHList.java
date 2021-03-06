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

package com.servoy.base.scripting.solutionhelper;

import com.servoy.base.persistence.IMobileProperties;
import com.servoy.base.solutionmodel.IBaseSMButton;
import com.servoy.base.solutionmodel.IBaseSMComponent;
import com.servoy.base.solutionmodel.IBaseSMField;
import com.servoy.base.solutionmodel.IBaseSMGraphicalComponent;
import com.servoy.base.solutionmodel.IBaseSMLabel;
import com.servoy.base.solutionmodel.IBaseSMListContainer;
import com.servoy.base.solutionmodel.IBaseSMMethod;

/**
 * @author acostescu
 */
public class BaseSHList implements IBaseSHList
{
	protected final IBaseSMListContainer container;
	protected final IBaseSMFormInternal contextForm;
	private IBaseSMButton textAndActionAndIconButton;
	private IBaseSMGraphicalComponent subtextComponent;
	private IBaseSMField countComponent;
	private IBaseSMField iconComponent;

	public BaseSHList(IBaseSMListContainer container, IBaseSMFormInternal contextForm)
	{
		this.container = container;
		this.contextForm = contextForm;

		// check for existing relevant components
		IBaseSMComponent[] components = (container instanceof IBaseSMFormInternal) ? ((IBaseSMFormInternal)container).getComponentsInternal(true, null)
			: container.getComponents();
		for (IBaseSMComponent c : components)
		{
			if (c instanceof IBaseSMButton && Boolean.TRUE.equals(contextForm.getMobilePropertyValue(c, IMobileProperties.LIST_ITEM_BUTTON)))
			{
				textAndActionAndIconButton = (IBaseSMButton)c;
			}
			else if (c instanceof IBaseSMGraphicalComponent && Boolean.TRUE.equals(contextForm.getMobilePropertyValue(c, IMobileProperties.LIST_ITEM_SUBTEXT)))
			{
				subtextComponent = (IBaseSMGraphicalComponent)c;
			}
			else if (c instanceof IBaseSMField)
			{
				if (Boolean.TRUE.equals(contextForm.getMobilePropertyValue(c, IMobileProperties.LIST_ITEM_COUNT))) countComponent = (IBaseSMField)c;
				else if (Boolean.TRUE.equals(contextForm.getMobilePropertyValue(c, IMobileProperties.LIST_ITEM_IMAGE))) iconComponent = (IBaseSMField)c;
			}
		}
	}

	protected IBaseSMListContainer getContainer()
	{
		return container;
	}

	public String getCountDataProviderID()
	{
		return countComponent != null ? countComponent.getDataProviderID() : null;
	}

	public void setCountDataProviderID(String countDataProviderID)
	{
		getOrCreateCountComponent().setDataProviderID(countDataProviderID);
	}

	public String getText()
	{
		return textAndActionAndIconButton != null ? textAndActionAndIconButton.getText() : null;
	}

	public void setText(String text)
	{
		getOrCreateTextAndActionAndIconButton().setText(text);
	}

	public String getTextDataProviderID()
	{
		return textAndActionAndIconButton != null ? textAndActionAndIconButton.getDataProviderID() : null;
	}

	public void setTextDataProviderID(String textDataPRoviderID)
	{
		getOrCreateTextAndActionAndIconButton().setDataProviderID(textDataPRoviderID);
	}

	public void setOnAction(IBaseSMMethod method)
	{
		getOrCreateTextAndActionAndIconButton().setOnAction(method);
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
		getOrCreateSubtextComponent().setText(subtext);
	}

	public String getSubtextDataProviderID()
	{
		return subtextComponent != null ? subtextComponent.getDataProviderID() : null;
	}

	public void setSubtextDataProviderID(String subtextDataProviderID)
	{
		getOrCreateSubtextComponent().setDataProviderID(subtextDataProviderID);
	}

	public String getDataIconType()
	{
		return textAndActionAndIconButton != null ? contextForm.getMobilePropertyValue(textAndActionAndIconButton, IMobileProperties.DATA_ICON) : null;
	}

	public void setDataIconType(String iconType)
	{
		contextForm.setMobilePropertyValue(getOrCreateTextAndActionAndIconButton(), IMobileProperties.DATA_ICON, iconType);
	}

	public String getDataIconDataProviderID()
	{
		return iconComponent != null ? iconComponent.getDataProviderID() : null;
	}

	public void setDataIconDataProviderID(String dataIconDataProviderID)
	{
		getOrCreateIconComponent().setDataProviderID(dataIconDataProviderID);
	}

	protected IBaseSMButton getOrCreateTextAndActionAndIconButton()
	{
		if (textAndActionAndIconButton == null)
		{
			textAndActionAndIconButton = createTextAndActionAndIconButton();
		}
		return textAndActionAndIconButton;
	}

	protected IBaseSMButton createTextAndActionAndIconButton()
	{
		IBaseSMButton button = container.newButton(null, 0, 0, 50, 30, null);
		contextForm.setMobilePropertyValue(button, IMobileProperties.LIST_ITEM_BUTTON, Boolean.TRUE);
		return button;
	}

	protected IBaseSMGraphicalComponent getOrCreateSubtextComponent()
	{
		if (subtextComponent == null)
		{
			subtextComponent = createSubtextComponent();
		}
		return subtextComponent;
	}

	protected IBaseSMGraphicalComponent createSubtextComponent()
	{
		IBaseSMLabel label = container.newLabel(null, 0, 0, 50, 30);
		contextForm.setMobilePropertyValue(label, IMobileProperties.LIST_ITEM_SUBTEXT, Boolean.TRUE);
		return label;
	}

	protected IBaseSMField getOrCreateCountComponent()
	{
		if (countComponent == null)
		{
			countComponent = createCountComponent();
		}
		return countComponent;
	}

	protected IBaseSMField createCountComponent()
	{
		IBaseSMField field = container.newField(null, IBaseSMField.TEXT_FIELD, 0, 0, 50, 30);
		contextForm.setMobilePropertyValue(field, IMobileProperties.LIST_ITEM_COUNT, Boolean.TRUE);
		return field;
	}

	protected IBaseSMField getOrCreateIconComponent()
	{
		if (iconComponent == null)
		{
			iconComponent = createIconComponent();
		}
		return iconComponent;
	}

	protected IBaseSMField createIconComponent()
	{
		IBaseSMField field = container.newField(null, IBaseSMField.TEXT_FIELD, 0, 0, 30, 30);
		contextForm.setMobilePropertyValue(field, IMobileProperties.LIST_ITEM_IMAGE, Boolean.TRUE);
		return field;
	}

	public String getListStyleClass()
	{
		return textAndActionAndIconButton != null ? textAndActionAndIconButton.getStyleClass() : null;
	}

	public void setListStyleClass(String styleClass)
	{
		getOrCreateTextAndActionAndIconButton().setStyleClass(styleClass);
	}

}
