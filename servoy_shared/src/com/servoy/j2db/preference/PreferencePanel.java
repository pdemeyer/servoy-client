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
package com.servoy.j2db.preference;


import java.awt.LayoutManager;

import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeListener;

/**
 * @author Johan Compagner
 */
public abstract class PreferencePanel extends JPanel
{
	//user actions
	public static final int NO_USER_ACTION_REQUIRED = 0;
	public static final int APPLICATION_RESTART_NEEDED = 1;
	public static final int SOLUTION_RELOAD_NEEDED = 2;

	public PreferencePanel()
	{
		super();
		setBorder(new EmptyBorder(10, 10, 10, 10));
	}

	public PreferencePanel(LayoutManager m)
	{
		super(m);
		setBorder(new EmptyBorder(10, 10, 10, 10));
	}

	/**
	 * Called by the Preference Dialog when the cancel button is pressed
	 */
	public abstract boolean handleCancel();

	/**
	 * Called by the Preference Dialog when the OK button is pressed.
	 */
	public abstract boolean handleOK();

	/**
	 * Should return the tabname that must be displayed as the tab title.
	 */
	public abstract String getTabName();

	/**
	 * Should return one of the final user actions.
	 */
	public abstract void addChangeListener(ChangeListener l);

	/**
	 * Should return one of the final user actions.
	 */
	public abstract int getRequiredUserAction();
}
