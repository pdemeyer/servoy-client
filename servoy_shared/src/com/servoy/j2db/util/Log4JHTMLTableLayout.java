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
package com.servoy.j2db.util;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Layout;
import org.apache.log4j.Level;
import org.apache.log4j.helpers.Transform;
import org.apache.log4j.spi.LocationInfo;
import org.apache.log4j.spi.LoggingEvent;
import org.mozilla.javascript.RhinoException;

public class Log4JHTMLTableLayout extends Layout
{
	// Print no location info by default
	private boolean locationInfo = false;

	private String dateTimeFormat = "HH:mm";

	private DateFormat dateFormat = new SimpleDateFormat(dateTimeFormat);

	public void setLocationInfo(boolean flag)
	{
		locationInfo = flag;
	}

	public boolean getLocationInfo()
	{
		return locationInfo;
	}

	public String getDateTimeFormat()
	{
		return dateTimeFormat;
	}

	public void setDateTimeFormat(String dateTimeFormat)
	{
		this.dateTimeFormat = dateTimeFormat;
		dateFormat = new SimpleDateFormat(dateTimeFormat);
	}

	@Override
	public boolean ignoresThrowable()
	{
		return false;
	}

	public void activateOptions()
	{
	}

	@Override
	public String getContentType()
	{
		return "text/html";
	}

	@SuppressWarnings("nls")
	@Override
	public String format(LoggingEvent event)
	{
		StringBuffer buffer = new StringBuffer();

		buffer.append(Layout.LINE_SEP + "<tr>" + Layout.LINE_SEP);

		buffer.append("<td nowrap>");
		buffer.append(dateFormat.format(new Date(event.timeStamp)));
		buffer.append("</td>" + Layout.LINE_SEP);

		buffer.append("<td title=\"" + event.getThreadName() + " thread\" nowrap>");
		buffer.append(Transform.escapeTags(event.getThreadName()));
		buffer.append("</td>" + Layout.LINE_SEP);

		buffer.append("<td title=\"Level\">");
		if (event.getLevel().equals(Level.DEBUG))
		{
			buffer.append("<font color=\"#339933\">");
			buffer.append(event.getLevel());
			buffer.append("</font>");
		}
		else if (event.getLevel().equals(Level.WARN))
		{
			buffer.append("<font color=\"#FC9206\"><strong>");
			buffer.append(event.getLevel());
			buffer.append("</strong></font>");
		}
		else if (event.getLevel().isGreaterOrEqual(Level.ERROR))
		{
			buffer.append("<font color=\"#993300\"><strong>");
			buffer.append(event.getLevel());
			buffer.append("</strong></font>");
		}
		else
		{
			buffer.append(event.getLevel());
		}
		buffer.append("</td>" + Layout.LINE_SEP);

		buffer.append("<td title=\"" + event.getLoggerName() + " category\">");
		buffer.append(Transform.escapeTags(event.getLoggerName()));
		buffer.append("</td>" + Layout.LINE_SEP);

		if (locationInfo)
		{
			LocationInfo locInfo = event.getLocationInformation();
			buffer.append("<td>");
			buffer.append(Transform.escapeTags(locInfo.getFileName()));
			buffer.append(':');
			buffer.append(locInfo.getLineNumber());
			buffer.append("</td>" + Layout.LINE_SEP);
		}

		buffer.append("<td title=\"Message\">");
		buffer.append(Transform.escapeTags(event.getRenderedMessage()));
		buffer.append("</td>" + Layout.LINE_SEP);

		Object clientid = event.getMDC("clientid");
		if (clientid == null) clientid = "&nbsp;";
		buffer.append("<td bgcolor=\"#EEEEEE\" style=\"font-size : xx-small;\" title=\"ClientId\">");
		buffer.append("<a href =\"/servoy-admin/clients/info/" + clientid + "\">" + clientid + "</a>");
		buffer.append("</td>");
		Object solutionName = event.getMDC("solution");
		if (solutionName == null) solutionName = "&nbsp;";
		buffer.append("<td bgcolor=\"#EEEEEE\" style=\"font-size : xx-small;\" title=\"Solution Name\">");
		buffer.append(solutionName);
		buffer.append("</td>");

		buffer.append("</tr>" + Layout.LINE_SEP);

		if (event.getNDC() != null)
		{
			buffer.append("<tr><td bgcolor=\"#EEEEEE\" style=\"font-size : xx-small;\" colspan=\"6\" title=\"Nested Diagnostic Context\">");
			buffer.append("NDC: " + Transform.escapeTags(event.getNDC()));
			buffer.append("</td></tr>" + Layout.LINE_SEP);
		}

		if (event.getThrowableInformation() != null)
		{
			if (event.getThrowableInformation().getThrowable() instanceof IOException || Level.WARN.isGreaterOrEqual(event.getLevel()))
			{
				buffer.append("<tr><td bgcolor=\"#FF9900\" style=\"color:White; font-size : xx-small;\" colspan=\"7\">");
				buffer.append("Exception, see log file for full details: ");
				buffer.append(event.getThrowableInformation().getThrowable().getMessage());
				buffer.append("</td></tr>" + Layout.LINE_SEP);
			}
			else if (event.getThrowableInformation().getThrowable() instanceof RhinoException)
			{
				StringWriter stringWriter = new StringWriter(1024);
				event.getThrowableInformation().getThrowable().printStackTrace(new PrintWriter(stringWriter));
				String[] s = stringWriter.getBuffer().toString().split("\n");
				if (s != null)
				{
					buffer.append("<tr><td bgcolor=\"#993300\" style=\"color:White; font-size : xx-small;\" colspan=\"7\">");
					appendThrowableAsHTML(s, buffer);
					buffer.append("</td></tr>" + Layout.LINE_SEP);
				}
			}
			else
			{
				String[] s = event.getThrowableStrRep();
				if (s != null)
				{
					buffer.append("<tr><td bgcolor=\"#993300\" style=\"color:White; font-size : xx-small;\" colspan=\"7\">");
					appendThrowableAsHTML(s, buffer);
					buffer.append("</td></tr>" + Layout.LINE_SEP);
				}
			}
		}
		return buffer.toString();
	}

	void appendThrowableAsHTML(String[] s, StringBuffer buffer)
	{
		if (s != null)
		{
			int len = s.length;
			if (len == 0) return;
			buffer.append(Transform.escapeTags(s[0]));
			buffer.append(Layout.LINE_SEP);
			for (int i = 1; i < len; i++)
			{
				buffer.append("<br>&nbsp;&nbsp;&nbsp;&nbsp;");
				buffer.append(Transform.escapeTags(s[i]));
				buffer.append(Layout.LINE_SEP);
			}
		}
	}

	@SuppressWarnings("nls")
	@Override
	public String getHeader()
	{
		StringBuffer buffer = new StringBuffer();
		buffer.append("<table cellspacing=\"0\" cellpadding=\"4\" border=\"1\" bordercolor=\"#224466\" width=\"100%\" style=\"font-family: arial,sans-serif; font-size: x-small;\">" +
			Layout.LINE_SEP);
		buffer.append("<tr style=\"background: #336699; color: #FFFFFF; text-align: left;\">" + Layout.LINE_SEP);
		buffer.append("<th>Time</th>" + Layout.LINE_SEP);
		buffer.append("<th>Thread</th>" + Layout.LINE_SEP);
		buffer.append("<th>Level</th>" + Layout.LINE_SEP);
		buffer.append("<th>Category</th>" + Layout.LINE_SEP);
		if (locationInfo)
		{
			buffer.append("<th>File:Line</th>" + Layout.LINE_SEP);
		}
		buffer.append("<th>Message</th>" + Layout.LINE_SEP);
		buffer.append("<th>ClientId</th>" + Layout.LINE_SEP);
		buffer.append("<th>Solution Name</th>" + Layout.LINE_SEP);
		buffer.append("</tr>" + Layout.LINE_SEP);
		return buffer.toString();
	}

	@Override
	public String getFooter()
	{
		return "</table>" + Layout.LINE_SEP;
	}

}