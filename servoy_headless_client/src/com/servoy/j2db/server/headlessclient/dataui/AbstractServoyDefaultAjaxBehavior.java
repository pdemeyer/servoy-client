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
package com.servoy.j2db.server.headlessclient.dataui;


import org.apache.wicket.Component;
import org.apache.wicket.ajax.AbstractDefaultAjaxBehavior;

import com.servoy.j2db.server.headlessclient.IDesignModeListener;
import com.servoy.j2db.server.headlessclient.WebClientSession;

/**
 * A base {@link AbstractDefaultAjaxBehavior} that calls onAjaxError() in the browser when a failure happens.
 * It is only enabled when the webclient is in ajax mode and the design mode boolean is false.
 * 
 * @author jcompagner
 * 
 */
public abstract class AbstractServoyDefaultAjaxBehavior extends AbstractDefaultAjaxBehavior implements IDesignModeListener
{

	private boolean designMode;

	public AbstractServoyDefaultAjaxBehavior()
	{
		super();
	}

	/**
	 * @see org.apache.wicket.ajax.AbstractDefaultAjaxBehavior#getFailureScript()
	 */
	@Override
	protected CharSequence getFailureScript()
	{
		return "onAjaxError();"; //$NON-NLS-1$
	}

	/**
	 * @see org.apache.wicket.ajax.AbstractDefaultAjaxBehavior#getPreconditionScript()
	 */
	@Override
	protected CharSequence getPreconditionScript()
	{
		return "onAjaxCall();" + super.getPreconditionScript(); //$NON-NLS-1$
	}

	/**
	 * @see org.apache.wicket.behavior.AbstractBehavior#isEnabled(org.apache.wicket.Component)
	 */
	@Override
	public boolean isEnabled(Component component)
	{
		return WebClientSession.get().useAjax() && super.isEnabled(component) && !designMode;
	}

	/**
	 * @see com.servoy.j2db.server.headlessclient.IDesignModeListener#setDesignMode(boolean)
	 */
	public void setDesignMode(boolean designMode)
	{
		this.designMode = designMode;
	}

}