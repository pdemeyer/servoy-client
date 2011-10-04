/*
 This file belongs to the Servoy development and deployment environment, Copyright (C) 1997-2011 Servoy BV

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

package com.servoy.j2db.querybuilder.impl;

import java.util.Iterator;

import org.mozilla.javascript.annotations.JSFunction;

import com.servoy.j2db.persistence.RepositoryException;
import com.servoy.j2db.querybuilder.IQueryBuilderColumn;
import com.servoy.j2db.querybuilder.IQueryBuilderResult;
import com.servoy.j2db.querybuilder.internal.IQueryBuilderColumnInternal;
import com.servoy.j2db.scripting.annotations.JSReadonlyProperty;

/**
 * @author rgansevles
 *
 */
public class QueryBuilderResult implements IQueryBuilderResult
{
	private final QueryBuilder parent;

	/**
	 * @param queryBuilder
	 */
	QueryBuilderResult(QueryBuilder parent)
	{
		this.parent = parent;
	}

	@JSReadonlyProperty
	public QueryBuilder getParent()
	{
		return parent;
	}

	@JSFunction
	public QueryBuilderResult addPk() throws RepositoryException
	{
		Iterator<String> rowIdentColumnNames = getParent().getTable().getRowIdentColumnNames();
		while (rowIdentColumnNames.hasNext())
		{
			add(rowIdentColumnNames.next());
		}
		return this;
	}

	@JSFunction
	public QueryBuilderResult add(String columnName) throws RepositoryException
	{
		return add(parent.getColumn(columnName));
	}

	public QueryBuilderResult js_add(QueryBuilderColumn column) throws RepositoryException
	{
		return add(column);
	}

	public QueryBuilderResult add(IQueryBuilderColumn column) throws RepositoryException
	{
		parent.getQuery().addColumn(((IQueryBuilderColumnInternal)column).getQueryColumn());
		return this;
	}

}
