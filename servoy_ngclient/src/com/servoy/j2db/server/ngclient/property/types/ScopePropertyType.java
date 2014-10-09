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

import org.json.JSONException;
import org.json.JSONObject;
import org.json.JSONWriter;
import org.mozilla.javascript.Scriptable;
import org.sablo.specification.property.IConvertedPropertyType;
import org.sablo.specification.property.IDataConverterContext;
import org.sablo.websocket.utils.DataConversion;

import com.servoy.j2db.server.ngclient.component.RuntimeWebComponent;

/**
 * @author lvostinar
 *
 */
public class ScopePropertyType implements IConvertedPropertyType<Scriptable>
{
	public static final ScopePropertyType INSTANCE = new ScopePropertyType();
	public static final String TYPE_NAME = "scope";

	private ScopePropertyType()
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
		return json;
	}

	@Override
	public RuntimeWebComponent defaultValue()
	{
		return null;
	}

	@Override
	public RuntimeWebComponent fromJSON(Object newJSONValue, Scriptable previousSabloValue, IDataConverterContext dataConverterContext)
	{
		//only user server side
		return null;
	}

	@Override
	public JSONWriter toJSON(JSONWriter writer, String key, Scriptable sabloValue, DataConversion clientConversion) throws JSONException
	{
		if (key != null)
		{
			writer.key(key);
		}
		// just write something, this type should be used server side
		writer.value(sabloValue.getClassName());
		return writer;
	}
}