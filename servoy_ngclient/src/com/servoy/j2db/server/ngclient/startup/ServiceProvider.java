package com.servoy.j2db.server.ngclient.startup;

import java.util.HashSet;
import java.util.Set;

import org.apache.tomcat.starter.IServiceProvider;

import com.servoy.j2db.server.ngclient.MediaResourcesServlet;
import com.servoy.j2db.server.ngclient.NGClientEndpoint;
import com.servoy.j2db.server.ngclient.TemplateGeneratorFilter;


public class ServiceProvider implements IServiceProvider
{
	@Override
	public void registerServices()
	{
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.tomcat.starter.IServiceProvider#getAnnotatedClasses(java.lang.String)
	 */
	@Override
	public Set<Class< ? >> getAnnotatedClasses(String context)
	{
		// ng client stuff are only reported for the root context in developer.
		if ("".equals(context))
		{
			HashSet<Class< ? >> set = new HashSet<Class< ? >>();
			set.add(MediaResourcesServlet.class);
			set.add(TemplateGeneratorFilter.class);
			set.add(NGClientEndpoint.class);
			return set;
		}
		return null;
	}
}
