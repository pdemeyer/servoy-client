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
package com.servoy.j2db.scripting;


import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map;
import java.util.Map.Entry;

import org.eclipse.dltk.rhino.dbgp.LazyInitScope;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.NativeJavaArray;
import org.mozilla.javascript.Scriptable;

import com.servoy.j2db.IApplication;
import com.servoy.j2db.IBasicFormManager;
import com.servoy.j2db.IFormController;
import com.servoy.j2db.util.Debug;

/**
 * This class handles dynamic creation/compilation of a 'form' and methods when asked for<br>
 * Normally this is a prototype of the top level scope (== solution scope)
 * 
 * @author jblok
 */
public class CreationalPrototype extends DefaultScope implements LazyInitScope
{
	private volatile IApplication application;

	public CreationalPrototype(Scriptable parent, IApplication application)
	{
		super(parent);
		this.application = application;
		setLocked(true);
	}

	@Override
	public void destroy()
	{
		super.destroy();
		application = null;
	}

	/**
	 * @see org.mozilla.javascript.ScriptableObject#getDefaultValue(java.lang.Class)
	 */
	@Override
	public Object getDefaultValue(Class typeHint)
	{
		StringBuffer sb = new StringBuffer();
		sb.append("CreationalPrototype["); //$NON-NLS-1$

		Object[] objects = getIds();
		for (Object element : objects)
		{
			sb.append(element);
			sb.append(","); //$NON-NLS-1$
		}
		if (objects.length > 0) sb.setCharAt(sb.length() - 1, ']');
		else sb.append("]"); //$NON-NLS-1$
		return sb.toString();
	}

	/**
	 * @see com.servoy.j2db.scripting.DefaultScope#getIds()
	 */
	@Override
	public Object[] getIds()
	{
		ArrayList<String> al = new ArrayList<String>();
		al.add("allnames"); //$NON-NLS-1$
		al.add("length"); //$NON-NLS-1$
		IBasicFormManager fm = application.getFormManager();
		Iterator<String> it = fm.getPossibleFormNames();
		while (it.hasNext())
		{
			al.add(it.next());
		}
		return al.toArray();
	}

	/**
	 * @see org.eclipse.dltk.rhino.dbgp.LazyInitScope#getInitializedIds()
	 */
	public Object[] getInitializedIds()
	{
		ArrayList<String> al = new ArrayList<String>();
		al.add("allnames"); //$NON-NLS-1$
		al.add("length"); //$NON-NLS-1$
		IBasicFormManager fm = application.getFormManager();
		if (fm == null) return new Object[0];
		Iterator<String> it = fm.getPossibleFormNames();
		while (it.hasNext())
		{
			String form = it.next();
			Object o = super.get(form, this);
			if (o != null && o != Scriptable.NOT_FOUND)
			{
				if (o instanceof FormScope)
				{
					IFormController fp = ((FormScope)o).getFormController();
					if (!fp.isShowingData()) continue;
				}
				al.add(form);
			}
		}
		return al.toArray();
	}

	@Override
	public Object get(java.lang.String name, Scriptable start)
	{
		if ("allnames".equals(name)) //$NON-NLS-1$
		{
			ArrayList<String> al = new ArrayList<String>();
			IBasicFormManager fm = application.getFormManager();
			if (fm == null) throw new IllegalStateException(
				"Trying to access forms after client was shut down? This JS code was probably running decoupled from client shut down but at the same time."); // should never happen during normal operation; see case 251716 
			Iterator<String> it = fm.getPossibleFormNames();
			while (it.hasNext())
			{
				al.add(it.next());
			}
			Context.enter();
			try
			{
				return new NativeJavaArray(this, al.toArray());
			}
			finally
			{
				Context.exit();
			}
		}
		Object o = super.get(name, start);
		if ((o == null || o == Scriptable.NOT_FOUND))
		{
			IBasicFormManager fm = application.getFormManager();
			if (fm == null) throw new IllegalStateException(
				"Trying to access forms after client was shut down? This JS code was probably running decoupled from client shut down but at the same time."); // should never happen during normal operation; see case 251716 
			if (!fm.isPossibleForm(name))
			{
				return o;
			}
			Context.enter();
			try
			{
				Debug.trace("CreationalPrototype:get " + name + " scope " + start); //$NON-NLS-1$ //$NON-NLS-2$
				if (!application.isEventDispatchThread())
				{
					Debug.log("Form " + name + " is not created because it is CreationalPrototype.get(formname) is called outside of the event thread"); //$NON-NLS-1$ //$NON-NLS-2$
					return "<Form " + name + " not loaded yet>"; //$NON-NLS-1$ //$NON-NLS-2$
				}
				IFormController fp = fm.leaseFormPanel(name);
				if (fp != null)
				{
					fp.initForJSUsage(this);//This registers the object in this scopes, this must called before anything else! (to prevent repeative calls/lookups here)
					o = super.get(name, this);//re-get
				}
				if (o == null) o = Scriptable.NOT_FOUND;
			}
			finally
			{
				Context.exit();
			}
		}

		if (o instanceof FormScope)
		{
			IFormController fp = ((FormScope)o).getFormController();
			fp.setView(fp.getView());
			fp.executeOnLoadMethod();

			try
			{
				if (!fp.isShowingData())
				{
					if (fp.wantEmptyFoundSet())
					{
						if (fp.getFormModel() != null) fp.getFormModel().clear();
					}
					else
					{
						fp.loadAllRecordsImpl(true);
					}
				}
			}
			catch (Exception ex)
			{
				Debug.error(ex);
				application.handleException(application.getI18NMessage("servoy.formPanel.error.formData"), ex); //$NON-NLS-1$
			}
		}
		return o;
	}

	public void removeFormPanel(IFormController fp)
	{
		String name = fp.getName();
		Object o = allVars.remove(name);
		if (o != null)
		{
			Iterator<Entry<Integer, Object>> it = allIndex.entrySet().iterator();
			while (it.hasNext())
			{
				Map.Entry<Integer, Object> entry = it.next();
				if (entry.getValue() == o)
				{
					Integer key = entry.getKey();
					allIndex.remove(key);
					Integer nextKey = new Integer(key.intValue() + 1);
					o = allIndex.remove(nextKey);
					while (o != null)
					{
						allIndex.put(key, o);
						key = nextKey;
						nextKey = new Integer(key.intValue() + 1);
						o = allIndex.remove(nextKey);
					}
					break;
				}
			}
		}
	}
}
