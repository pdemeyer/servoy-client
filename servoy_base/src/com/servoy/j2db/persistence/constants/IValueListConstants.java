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

package com.servoy.j2db.persistence.constants;

/**
 * Constants used in valuelists.
 * @author acostescu
 */
public interface IValueListConstants
{

	public static final int CUSTOM_VALUES = 0;
	public static final int DATABASE_VALUES = 1;

	//type of database Values
	public static final int TABLE_VALUES = 2;
	public static final int RELATED_VALUES = 3;

	public static final int GLOBAL_METHOD_VALUES = 4;

	public static final int EMPTY_VALUE_ALWAYS = 0;
	public static final int EMPTY_VALUE_NEVER = 1;
	public static final int EMPTY_VALUE_ONCREATION_ONLY = 2; //TODO:not impl yet

}
