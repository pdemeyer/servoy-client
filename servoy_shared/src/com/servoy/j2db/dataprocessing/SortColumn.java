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
package com.servoy.j2db.dataprocessing;


import com.servoy.j2db.persistence.ColumnWrapper;
import com.servoy.j2db.persistence.IColumn;
import com.servoy.j2db.persistence.Relation;

/**
 * Wrapper class to indicate sort on columns
 * @author jblok
 */
public class SortColumn extends ColumnWrapper
{
	public static final int ASCENDING = 0;
	public static final int DESCENDING = 1;

	private int sortOrder;

	public SortColumn(IColumn c)
	{
		super(c);
	}

	public SortColumn(IColumn c, int sortOrder)
	{
		super(c);
		this.sortOrder = sortOrder;
	}

	public SortColumn(IColumn c, Relation[] relations)
	{
		super(c, relations);
	}

	public SortColumn(ColumnWrapper c)
	{
		super(c.getColumn(), c.getRelations());
	}

	public int getSortOrder()
	{
		return sortOrder;
	}

	public void setSortOrder(int o)
	{
		sortOrder = o;
	}

	public boolean equalsIgnoreSortorder(Object obj)
	{
		if (this == obj) return true;
		if (obj == null) return false;
		if (getClass() != obj.getClass()) return false;
		return equalColumnWrapper((SortColumn)obj);
	}

	@Override
	public int hashCode()
	{
		return super.hashCode() + (sortOrder * 6);
	}

	@Override
	public boolean equals(Object obj)
	{
		return equalsIgnoreSortorder(obj) && (sortOrder == ((SortColumn)obj).sortOrder);
	}

	@Override
	public String toString()
	{
		return super.toString() + (sortOrder == ASCENDING ? " asc" : " desc"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}