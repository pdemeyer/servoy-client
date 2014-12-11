/*
 * Copyright (C) 2014 Servoy BV
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.servoy.j2db.server.ngclient.property.types;

import java.util.Collection;

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONWriter;
import org.sablo.specification.PropertyDescription;
import org.sablo.specification.property.IConvertedPropertyType;
import org.sablo.specification.property.IDataConverterContext;
import org.sablo.specification.property.types.TypesRegistry;
import org.sablo.websocket.utils.DataConversion;

import com.servoy.base.persistence.constants.IValueListConstants;
import com.servoy.j2db.FlattenedSolution;
import com.servoy.j2db.component.ComponentFormat;
import com.servoy.j2db.dataprocessing.CustomValueList;
import com.servoy.j2db.dataprocessing.DBValueList;
import com.servoy.j2db.dataprocessing.GlobalMethodValueList;
import com.servoy.j2db.dataprocessing.IValueList;
import com.servoy.j2db.dataprocessing.RelatedValueList;
import com.servoy.j2db.persistence.StaticContentSpecLoader;
import com.servoy.j2db.persistence.ValueList;
import com.servoy.j2db.server.ngclient.ColumnBasedValueList;
import com.servoy.j2db.server.ngclient.DataAdapterList;
import com.servoy.j2db.server.ngclient.FormElement;
import com.servoy.j2db.server.ngclient.INGApplication;
import com.servoy.j2db.server.ngclient.IWebFormUI;
import com.servoy.j2db.server.ngclient.WebFormComponent;
import com.servoy.j2db.server.ngclient.WebFormUI;
import com.servoy.j2db.server.ngclient.property.types.NGConversions.IFormElementToSabloComponent;
import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.UUID;
import com.servoy.j2db.util.Utils;

/**
 * Property type that handles valuelist typed properties.
 *
 * @author acostescu
 * @author jcompagner
 */
public class ValueListPropertyType implements IConvertedPropertyType<ValueListPropertySabloValue>,
	IFormElementToSabloComponent<Object, ValueListPropertySabloValue>, ISupportTemplateValue<Object>, IDataLinkedType<Object, ValueListPropertySabloValue>
{

	public static final ValueListPropertyType INSTANCE = new ValueListPropertyType();
	public static final String TYPE_NAME = "valuelist";

	private ValueListPropertyType()
	{
	}

	@Override
	public String getName()
	{
		return TYPE_NAME;
	}

	@Override
	public Object parseConfig(JSONObject json)
	{
		if (json != null && json.has("for"))
		{
			try
			{
				return json.getString("for");
			}
			catch (JSONException e)
			{
				Debug.error("JSONException", e);
			}
		}
		return "";
	}

	@Override
	public boolean valueInTemplate(Object object)
	{
		return false;
	}

	@Override
	public ValueListPropertySabloValue defaultValue()
	{
		return null;
	}

	@Override
	public ValueListPropertySabloValue fromJSON(Object newJSONValue, ValueListPropertySabloValue previousSabloValue, IDataConverterContext dataConverterContext)
	{
		// handle any valuelist specific websocket incomming traffic
		if (previousSabloValue != null && newJSONValue instanceof String)
		{
			// currently the only thing that can come from client is a filter request...
			previousSabloValue.filterValuelist((String)newJSONValue);
		}
		else Debug.error("Got a client update for valuelist property, but valuelist is null or value can't be interpreted: " + newJSONValue + ".");

		return previousSabloValue;
	}

	@Override
	public JSONWriter toJSON(JSONWriter writer, String key, ValueListPropertySabloValue sabloValue, DataConversion clientConversion,
		IDataConverterContext dataConverterContext) throws JSONException
	{
		if (sabloValue != null)
		{
			// TODO we should have type info here to send instead of null for real/display values
			sabloValue.toJSON(writer, key, clientConversion);
		}
		return writer;
	}

	@Override
	public ValueListPropertySabloValue toSabloComponentValue(Object formElementValue, PropertyDescription pd, FormElement formElement,
		WebFormComponent component, DataAdapterList dataAdapterList)
	{
		ValueList val = null;
		IValueList valueList = null;

		int valuelistID = Utils.getAsInteger(formElementValue);
		INGApplication application = dataAdapterList.getApplication();
		if (valuelistID > 0)
		{
			val = application.getFlattenedSolution().getValueList(valuelistID);
		}
		else
		{
			UUID uuid = Utils.getAsUUID(formElementValue, false);
			if (uuid != null) val = (ValueList)application.getFlattenedSolution().searchPersist(uuid);
		}

		String dataproviderID = (pd.getConfig() != null ? (String)formElement.getPropertyValue((String)pd.getConfig()) : null);

		if (val != null)
		{
			switch (val.getValueListType())
			{
				case IValueListConstants.GLOBAL_METHOD_VALUES :
					valueList = new GlobalMethodValueList(application, val);
					break;
				case IValueListConstants.CUSTOM_VALUES :
					String format = null;
					if (dataproviderID != null)
					{
						Collection<PropertyDescription> properties = formElement.getWebComponentSpec().getProperties(TypesRegistry.getType("format"));
						for (PropertyDescription formatPd : properties)
						{
							// compare the config objects for Format and Valuelist properties these are both the "for" dataprovider id property
							if (pd.getConfig().equals(formatPd.getConfig()))
							{
								format = (String)formElement.getPropertyValue(formatPd.getName());
								break;
							}
						}
					}
					ComponentFormat fieldFormat = ComponentFormat.getComponentFormat(format, dataproviderID,
						application.getFlattenedSolution().getDataproviderLookup(application.getFoundSetManager(), formElement.getForm()), application);
					valueList = new CustomValueList(application, val, val.getCustomValues(),
						(val.getAddEmptyValue() == IValueListConstants.EMPTY_VALUE_ALWAYS), fieldFormat.dpType, fieldFormat.parsedFormat);
					break;
				default :
					valueList = val.getDatabaseValuesType() == IValueListConstants.RELATED_VALUES ? new RelatedValueList(application, val) : new DBValueList(
						application, val);
			}
		}
		else
		{
			if (formElement.getTypeName().equals("servoydefault-typeahead"))
			{
				String dp = (String)formElement.getPropertyValue(StaticContentSpecLoader.PROPERTY_DATAPROVIDERID.getPropertyName());
				IWebFormUI formUI = component.findParent(WebFormUI.class);
				if (dp != null && formUI.getController().getTable() != null && formUI.getController().getTable().getColumnType(dp) != 0)
				{
					valueList = new ColumnBasedValueList(application, formElement.getForm().getServerName(), formElement.getForm().getTableName(),
						(String)formElement.getPropertyValue(StaticContentSpecLoader.PROPERTY_DATAPROVIDERID.getPropertyName()));
				}
			}
		}

		return valueList != null ? new ValueListPropertySabloValue(valueList, dataAdapterList, dataproviderID) : null;
	}

	@Override
	public TargetDataLinks getDataLinks(Object formElementValue, PropertyDescription pd, FlattenedSolution flattenedSolution, FormElement formElement)
	{
		return TargetDataLinks.LINKED_TO_ALL;
	}

}
