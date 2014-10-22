/*
 This file belongs to the Servoy development and deployment environment, Copyright (C) 1997-2014 Servoy BV

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

package com.servoy.j2db.server.ngclient.property.types;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONWriter;
import org.mozilla.javascript.NativeArray;
import org.mozilla.javascript.NativeJavaArray;
import org.mozilla.javascript.Scriptable;
import org.sablo.BaseWebObject;
import org.sablo.specification.PropertyDescription;
import org.sablo.specification.property.ChangeAwareList;
import org.sablo.specification.property.CustomJSONArrayType;
import org.sablo.specification.property.DataConverterContext;
import org.sablo.websocket.utils.DataConversion;
import org.sablo.websocket.utils.JSONUtils;

import com.servoy.j2db.FlattenedSolution;
import com.servoy.j2db.server.ngclient.FormElement;
import com.servoy.j2db.server.ngclient.IServoyDataConverterContext;
import com.servoy.j2db.server.ngclient.WebFormComponent;
import com.servoy.j2db.server.ngclient.component.RhinoMapOrArrayWrapper;
import com.servoy.j2db.server.ngclient.property.types.NGConversions.IDesignToFormElement;
import com.servoy.j2db.server.ngclient.property.types.NGConversions.IFormElementToSabloComponent;
import com.servoy.j2db.server.ngclient.property.types.NGConversions.IFormElementToTemplateJSON;
import com.servoy.j2db.server.ngclient.property.types.NGConversions.IRhinoToSabloComponent;
import com.servoy.j2db.server.ngclient.property.types.NGConversions.ISabloComponentToRhino;
import com.servoy.j2db.util.Debug;

/**
 * A JSON array type that is Servoy NG client aware as well.
 * So it adds all conversions from {@link NGConversions}.
 *
 * @author acostescu
 */
public class NGCustomJSONArrayType<SabloT, SabloWT> extends CustomJSONArrayType<SabloT, SabloWT> implements IDesignToFormElement<JSONArray, Object[], Object>,
	IFormElementToTemplateJSON<Object[], Object>, IFormElementToSabloComponent<Object[], Object>, ISabloComponentToRhino<Object>,
	IRhinoToSabloComponent<Object>, ISupportTemplateValue<List<Object>>
{

	public NGCustomJSONArrayType(PropertyDescription definition)
	{
		super(definition);
	}

	@Override
	public Object[] toFormElementValue(JSONArray designValue, PropertyDescription pd, FlattenedSolution flattenedSolution, FormElement formElement,
		PropertyPath propertyPath)
	{
		if (designValue != null)
		{
			Object[] formElementValues = new Object[designValue.length()];
			for (int i = designValue.length() - 1; i >= 0; i--)
			{
				try
				{
					propertyPath.add(i);
					formElementValues[i] = NGConversions.INSTANCE.convertDesignToFormElementValue(designValue.get(i), getCustomJSONTypeDefinition(),
						flattenedSolution, formElement, propertyPath);
				}
				catch (JSONException e)
				{
					Debug.error(e);
					formElementValues[i] = null;
				}
				finally
				{
					propertyPath.backOneLevel();
				}
			}
			return formElementValues;
		}
		return null;
	}

	@Override
	public JSONWriter toTemplateJSONValue(JSONWriter writer, String key, Object[] formElementValue, PropertyDescription pd, DataConversion conversionMarkers,
		IServoyDataConverterContext servoyDataConverterContext) throws JSONException
	{
		JSONUtils.addKeyIfPresent(writer, key);
		if (conversionMarkers != null) conversionMarkers.convert(CustomJSONArrayType.TYPE_NAME); // so that the client knows it must use the custom client side JS for what JSON it gets

		if (formElementValue != null)
		{
			writer.object().key(CONTENT_VERSION).value(1).key(VALUE).array();
			DataConversion arrayConversionMarkers = new DataConversion();

			for (int i = 0; i < formElementValue.length; i++)
			{
				arrayConversionMarkers.pushNode(String.valueOf(i));
				NGConversions.INSTANCE.convertFormElementToTemplateJSONValue(writer, null, formElementValue[i], getCustomJSONTypeDefinition(),
					arrayConversionMarkers, servoyDataConverterContext);
				arrayConversionMarkers.popNode();
			}
			writer.endArray();
			if (arrayConversionMarkers.getConversions().size() > 0)
			{
				writer.key("conversions").object();
				JSONUtils.writeConversions(writer, arrayConversionMarkers.getConversions());
				writer.endObject();
			}
			writer.endObject();
		}
		else
		{
			writer.value(JSONObject.NULL);
		}
		return writer;
	}

	@Override
	public Object toSabloComponentValue(Object[] formElementValue, PropertyDescription pd, FormElement formElement, WebFormComponent component)
	{
		if (formElementValue != null)
		{
			List<SabloT> list = new ArrayList<>(formElementValue.length);
			for (Object element : formElementValue)
			{
				list.add((SabloT)NGConversions.INSTANCE.convertFormElementToSabloComponentValue(element, getCustomJSONTypeDefinition(), formElement, component));
			}
			return list;
		}
		return null;
	}

	@Override
	public Object toSabloComponentValue(final Object rhinoValue, Object previousComponentValue, PropertyDescription pd, final BaseWebObject componentOrService)
	{
		if (rhinoValue == null || rhinoValue == Scriptable.NOT_FOUND) return null;

		final ChangeAwareList<SabloT, SabloWT> previousSpecialArray = (ChangeAwareList<SabloT, SabloWT>)previousComponentValue;
		if (rhinoValue instanceof RhinoMapOrArrayWrapper)
		{
			return ((RhinoMapOrArrayWrapper)rhinoValue).getWrappedValue();
		}
		else if (previousSpecialArray != null && previousSpecialArray.getBaseList() instanceof IRhinoNativeProxy &&
			((IRhinoNativeProxy)previousSpecialArray.getBaseList()).getBaseRhinoScriptable() == rhinoValue)
		{
			return previousComponentValue; // this can get called a lot when a native Rhino wrapper list and proxy are in use; don't create new values each time
			// something is accessed in the wrapper+converter+proxy list cause that messes up references
		}
		else
		{
			// if it's some kind of array

			List<SabloT> rhinoArray = null;

			if (rhinoValue instanceof NativeArray)
			{
				rhinoArray = new RhinoNativeArrayWrapperList<SabloT, SabloWT>((NativeArray)rhinoValue, getCustomJSONTypeDefinition(), previousSpecialArray,
					componentOrService);
			}
			else if (rhinoValue instanceof NativeJavaArray)
			{
				// rhinoValue.unwrap() will be a java static array []
				rhinoArray = new RhinoNativeArrayWrapperList<SabloT, SabloWT>(Arrays.asList(((NativeJavaArray)rhinoValue).unwrap()),
					getCustomJSONTypeDefinition(), previousSpecialArray, componentOrService, (Scriptable)rhinoValue);
			}

			if (rhinoArray != null)
			{
				ChangeAwareList<SabloT, SabloWT> cal = wrap(rhinoArray, (ChangeAwareList<SabloT, SabloWT>)previousComponentValue, new DataConverterContext(pd,
					componentOrService));
				cal.markAllChanged();
				return cal;

				// if we really want to remove the extra-conversion list above and convert all to a new list we could do it by executing the code below after a toJSON is called (so after a request finishes,
				// we consider that in the next request the user will only use property reference again taken from service/component, so the new converted list, not anymore the array that was created in JS directly,
				// but this still won't work if the user really holds on to that old/initial reference and changes it...); actually if the initial value is used, it will not be change-aware anyway...
//				int i = 0;
//				for (Object rv : rhinoArray)
//				{
//					convertedArray.add(NGConversions.INSTANCE.convertRhinoToSabloComponentValue(rv,
//						(previousSpecialArray != null && previousSpecialArray.size() > i) ? previousSpecialArray.get(i) : null, getCustomJSONTypeDefinition(),
//						componentOrService));
//					i++;
//				}
			}
		}
		return previousComponentValue; // or should we return null or throw exception here? incompatible thing was assigned
	}

	@Override
	public boolean isValueAvailableInRhino(Object webComponentValue, PropertyDescription pd, BaseWebObject componentOrService)
	{
		return true;
	}

	@Override
	public Object toRhinoValue(Object webComponentValue, PropertyDescription pd, BaseWebObject componentOrService, Scriptable startScriptable)
	{
		return webComponentValue == null ? null : new RhinoMapOrArrayWrapper(webComponentValue, componentOrService, pd, startScriptable);
	}

	@Override
	public boolean valueInTemplate(List<Object> values)
	{
		if (values != null && values.size() > 0)
		{
			PropertyDescription desc = getCustomJSONTypeDefinition();

			if (desc.getType() instanceof ISupportTemplateValue)
			{
				ISupportTemplateValue<Object> type = (ISupportTemplateValue<Object>)desc.getType();
				for (Object object : values)
				{
					if (!type.valueInTemplate(object))
					{
						return false;
					}
				}
			}
		}
		return true;
	}

}