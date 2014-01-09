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

package com.servoy.j2db.dataprocessing;

import java.util.Comparator;

/**
 * @author lvostinar
 * 
 * A buffered dataset that also holds row index information.
 * 
 */
public class BufferedDataSetWithIndex implements IDataSetWithIndex
{
	private int rowIndex = -1;
	private final IDataSet dataset;

	public BufferedDataSetWithIndex(IDataSet dataset)
	{
		this(dataset, -1);
	}

	public BufferedDataSetWithIndex(IDataSet dataset, int rowIndex)
	{
		this.dataset = dataset;
		this.rowIndex = rowIndex;
	}


	public int getRowIndex()
	{
		return rowIndex;
	}

	public void setRowIndex(int rowIndex)
	{
		this.rowIndex = rowIndex;
	}

	@Override
	public int getRowCount()
	{
		return dataset.getRowCount();
	}

	@Override
	public Object[] getRow(int row)
	{
		return dataset.getRow(row);
	}

	@Override
	public void removeRow(int index)
	{
		dataset.removeRow(index);
	}

	@Override
	public void setRow(int index, Object[] array)
	{
		dataset.setRow(index, array);
	}

	@Override
	public void addRow(Object[] array)
	{
		dataset.addRow(array);
	}

	@Override
	public int getColumnCount()
	{
		return dataset.getColumnCount();
	}

	@Override
	public String[] getColumnNames()
	{
		return dataset.getColumnNames();
	}

	@Override
	public int[] getColumnTypes()
	{
		return dataset.getColumnTypes();
	}

	@Override
	public boolean hadMoreRows()
	{
		return dataset.hadMoreRows();
	}

	@Override
	public void clearHadMoreRows()
	{
		dataset.clearHadMoreRows();
	}

	@Override
	public void addRow(int index, Object[] new_record_value)
	{
		dataset.addRow(index, new_record_value);
	}

	@Override
	public void sort(int column, boolean ascending)
	{
		dataset.sort(column, ascending);
	}

	@Override
	public void sort(Comparator<Object[]> rowComparator)
	{
		dataset.sort(rowComparator);
	}

	@Override
	public boolean addColumn(int columnIndex, String columnName, int columnType)
	{
		return dataset.addColumn(columnIndex, columnName, columnType);
	}

	@Override
	public boolean removeColumn(int columnIndex)
	{
		return dataset.removeColumn(columnIndex);
	}

	@Override
	public void setColumnName(int columnIndex, String columnName)
	{
		dataset.setColumnName(columnIndex, columnName);
	}

	@Override
	public IDataSet clone()
	{
		return new BufferedDataSetWithIndex(dataset.clone(), rowIndex);
	}
}
