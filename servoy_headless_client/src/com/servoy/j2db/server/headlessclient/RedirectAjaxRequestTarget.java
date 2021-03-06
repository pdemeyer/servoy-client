/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.servoy.j2db.server.headlessclient;

import org.apache.wicket.Application;
import org.apache.wicket.IRequestTarget;
import org.apache.wicket.Page;
import org.apache.wicket.RequestCycle;
import org.apache.wicket.protocol.http.WebResponse;

import com.servoy.j2db.server.headlessclient.MainPage.ShowUrlInfo;

/**
 * The empty AJAX request target does output an empty AJAX response.
 * 
 * @author Matej Knopp
 */
public final class RedirectAjaxRequestTarget implements IRequestTarget
{
	/** immutable hashcode. */
	private static final int HASH = 17 * 1542323;
	private final Class< ? extends Page> page;

	/** singleton instance. */
	/**
	 * Construct.
	 */
	public RedirectAjaxRequestTarget(Class< ? extends Page> page)
	{
		this.page = page;
	}

	/**
	 * @see org.apache.wicket.IRequestTarget#respond(org.apache.wicket.RequestCycle)
	 */
	public void respond(RequestCycle requestCycle)
	{
		WebResponse response = (WebResponse)requestCycle.getResponse();
		final String encoding = Application.get().getRequestCycleSettings().getResponseRequestEncoding();

		// Set content type based on markup type for page
		response.setCharacterEncoding(encoding);
		response.setContentType("text/xml; charset=" + encoding);

		// Make sure it is not cached by a client
		response.setDateHeader("Expires", System.currentTimeMillis());
		response.setHeader("Cache-Control", "no-cache, must-revalidate");
		response.setHeader("Pragma", "no-cache");

		CharSequence urlFor = RequestCycle.get().urlFor(page, null);
		response.write("<?xml version=\"1.0\" encoding=\"");
		response.write(encoding);
		response.write("\"?><ajax-response>");
		response.write("<evaluate");
		response.write(">");
		response.write("<![CDATA[");
		response.write(MainPage.getShowUrlScript(new ShowUrlInfo(urlFor.toString(), "_self", null, 0, true, false, true)));
		response.write("]]>");
		response.write("</evaluate>");
		response.write("</ajax-response>");
	}

	/**
	 * @see org.apache.wicket.IRequestTarget#detach(org.apache.wicket.RequestCycle)
	 */
	public void detach(RequestCycle requestCycle)
	{
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	@Override
	public boolean equals(Object obj)
	{
		if (obj instanceof RedirectAjaxRequestTarget)
		{
			return true;
		}
		return false;
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	@Override
	public int hashCode()
	{
		return HASH;
	}

	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		return "RedirectAjaxRequestTarget";
	}
}
