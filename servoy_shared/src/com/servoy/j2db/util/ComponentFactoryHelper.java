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

import java.awt.Color;
import java.awt.Font;
import java.awt.Insets;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.swing.BorderFactory;
import javax.swing.border.BevelBorder;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.EtchedBorder;
import javax.swing.border.LineBorder;
import javax.swing.border.MatteBorder;
import javax.swing.border.TitledBorder;

import com.servoy.j2db.J2DBGlobals;
import com.servoy.j2db.util.gui.SpecialMatteBorder;

/**
 * Helper class.
 * 
 * @author Jan Blok
 */
public class ComponentFactoryHelper
{
	public static String createBorderString(Object currentBorder)
	{
		String retval = null;
		if (currentBorder != null)
		{
			if (currentBorder instanceof CompoundBorder)
			{
				Border oborder = ((CompoundBorder)currentBorder).getOutsideBorder();
				Border iborder = ((CompoundBorder)currentBorder).getInsideBorder();
				retval = "CompoundBorder,"; //$NON-NLS-1$
				retval += ";" + createBorderString(oborder); //$NON-NLS-1$
				retval += ";" + createBorderString(iborder) + ";"; //$NON-NLS-1$ //$NON-NLS-2$
			}
			else if (currentBorder instanceof BevelBorder)
			{
				BevelBorder border = (BevelBorder)currentBorder;
				int type = border.getBevelType();
				retval = "BevelBorder," + type; //$NON-NLS-1$
				if (border.getHighlightInnerColor() != null || border.getHighlightOuterColor() != null || border.getShadowInnerColor() != null ||
					border.getShadowOuterColor() != null)
				{
					retval += "," + PersistHelper.createColorString(border.getHighlightOuterColor()); //$NON-NLS-1$
					retval += "," + PersistHelper.createColorString(border.getHighlightInnerColor()); //$NON-NLS-1$
					retval += "," + PersistHelper.createColorString(border.getShadowOuterColor()); //$NON-NLS-1$
					retval += "," + PersistHelper.createColorString(border.getShadowInnerColor()); //$NON-NLS-1$
				}
			}
			else if (currentBorder instanceof EtchedBorder)
			{
				EtchedBorder border = (EtchedBorder)currentBorder;
				int type = border.getEtchType();
				Color hi = border.getHighlightColor();
				Color sh = border.getShadowColor();
				retval = "EtchedBorder," + type + "," + PersistHelper.createColorString(hi) + "," + PersistHelper.createColorString(sh); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			}
			else if (currentBorder instanceof LineBorder)
			{
				LineBorder border = (LineBorder)currentBorder;
				int thick = border.getThickness();
				Color lineColor = border.getLineColor();
				retval = "LineBorder," + thick + "," + PersistHelper.createColorString(lineColor); //$NON-NLS-1$ //$NON-NLS-2$
			}
			else if (currentBorder instanceof TitledBorder)
			{
				TitledBorder border = (TitledBorder)currentBorder;
				String s = border.getTitle();
				s = Utils.stringReplace(s, ",", "|"); //escape //$NON-NLS-1$ //$NON-NLS-2$
				Font f = border.getTitleFont();
				Color c = border.getTitleColor();
				retval = "TitledBorder," + s; //$NON-NLS-1$

				int justification = border.getTitleJustification();
				int position = border.getTitlePosition();
				if (justification != 0 || position != 0 || f != null || c != null)
				{
					retval += "," + justification + "," + position; //$NON-NLS-1$ //$NON-NLS-2$
					if (f != null)
					{
						retval += "," + PersistHelper.createFontString(f); //$NON-NLS-1$
						if (c != null)
						{
							retval += "," + PersistHelper.createColorString(c); //$NON-NLS-1$
						}
					}
				}
			}
			else if (currentBorder instanceof SpecialMatteBorder)
			{
				SpecialMatteBorder border = (SpecialMatteBorder)currentBorder;
				retval = "SpecialMatteBorder," + border.getTop() + "," + border.getRight() + "," + border.getBottom() + "," + border.getLeft(); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
				retval += "," + PersistHelper.createColorString(border.getTopColor()); //$NON-NLS-1$
				retval += "," + PersistHelper.createColorString(border.getRightColor()); //$NON-NLS-1$
				retval += "," + PersistHelper.createColorString(border.getBottomColor()); //$NON-NLS-1$
				retval += "," + PersistHelper.createColorString(border.getLeftColor()); //$NON-NLS-1$
				retval += "," + border.getRoundingRadius(); //$NON-NLS-1$
				retval += "," + SpecialMatteBorder.createDashString(border.getDashPattern()); //$NON-NLS-1$
			}
			else if (currentBorder instanceof MatteBorder)
			{
				MatteBorder border = (MatteBorder)currentBorder;
				Insets i = border.getBorderInsets(null);
				Color lineColor = border.getMatteColor();
				retval = "MatteBorder," + i.top + "," + i.right + "," + i.bottom + "," + i.left + "," + PersistHelper.createColorString(lineColor); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$ //$NON-NLS-5$
			}
			else if (currentBorder instanceof EmptyBorder)
			{
				EmptyBorder border = (EmptyBorder)currentBorder;
				Insets i = border.getBorderInsets(null);
				retval = "EmptyBorder," + i.top + "," + i.right + "," + i.bottom + "," + i.left; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
			}
			else
			{
				retval = "<select>"; //$NON-NLS-1$
			}
		}
		return retval;
	}

	public static Border createBorder(String s)
	{
		return createBorder(s, false);
	}

	public static Border createBorder(String s, boolean design)
	{
		Border currentBorder = null;
		if (s != null)
		{
			StringTokenizer tk = new StringTokenizer(s, ","); //$NON-NLS-1$
			if (tk.hasMoreTokens())
			{
				try
				{
					String type = tk.nextToken();
					if (type.equals("CompoundBorder")) //$NON-NLS-1$
					{
						StringTokenizer tk2 = new StringTokenizer(s, ";"); //$NON-NLS-1$
						tk2.nextToken();//skip 'CompoundBorder,' token
						String s_oborder = tk2.nextToken();
						Border oborder = createBorder(s_oborder);
						String s_iborder = tk2.nextToken();
						Border iborder = createBorder(s_iborder);
						currentBorder = BorderFactory.createCompoundBorder(oborder, iborder);
					}
					else if (type.equals("EmptyBorder")) //$NON-NLS-1$
					{
						int top = Utils.getAsInteger(tk.nextToken());
						int right = Utils.getAsInteger(tk.nextToken());
						int bottom = Utils.getAsInteger(tk.nextToken());
						int left = Utils.getAsInteger(tk.nextToken());
						currentBorder = BorderFactory.createEmptyBorder(top, left, bottom, right);
					}
					else if (type.equals("BevelBorder")) //$NON-NLS-1$
					{
						int beveltype = Utils.getAsInteger(tk.nextToken());
						if (tk.hasMoreTokens())
						{
							Color highlightO = PersistHelper.createColor(tk.nextToken());
							Color highlightI = PersistHelper.createColor(tk.nextToken());
							Color shadowO = PersistHelper.createColor(tk.nextToken());
							Color shadowI = PersistHelper.createColor(tk.nextToken());

							currentBorder = BorderFactory.createBevelBorder(beveltype, highlightO, highlightI, shadowO, shadowI);
						}
						else
						{
							currentBorder = BorderFactory.createBevelBorder(beveltype);
						}
					}
					else if (type.equals("EtchedBorder")) //$NON-NLS-1$
					{
						int beveltype = Utils.getAsInteger(tk.nextToken());
						Color highlight = PersistHelper.createColor(tk.nextToken());
						Color shadow = PersistHelper.createColor(tk.nextToken());
						currentBorder = BorderFactory.createEtchedBorder(beveltype, highlight, shadow);
					}
					else if (type.equals("LineBorder")) //$NON-NLS-1$
					{
						int thick = Utils.getAsInteger(tk.nextToken());
						currentBorder = BorderFactory.createLineBorder(PersistHelper.createColor(tk.nextToken()), thick);
					}
					else if (type.equals("TitledBorder")) //$NON-NLS-1$
					{
						String title = tk.nextToken();
						title = Utils.stringReplace(title, "|", ",");//unescape //$NON-NLS-1$ //$NON-NLS-2$
						int justification = 0;
						int position = 0;
						Font font = null;
						Color color = null;
						if (tk.hasMoreTokens())
						{
							justification = Utils.getAsInteger(tk.nextToken());
							position = Utils.getAsInteger(tk.nextToken());
							if (tk.hasMoreTokens())
							{
								font = PersistHelper.createFont(tk.nextToken() + "," + tk.nextToken() + "," + tk.nextToken());//we know a font has 3 parameters ALSO separated with ',' //$NON-NLS-1$ //$NON-NLS-2$
								if (tk.hasMoreTokens())
								{
									color = PersistHelper.createColor(tk.nextToken());
								}
							}
						}

						if (design)
						{
							currentBorder = BorderFactory.createTitledBorder(title);
						}
						else
						{
							currentBorder = BorderFactory.createTitledBorder(J2DBGlobals.getServiceProvider().getI18NMessageIfPrefixed(title));
						}
						((TitledBorder)currentBorder).setTitleJustification(justification);
						((TitledBorder)currentBorder).setTitlePosition(position);
						if (font != null) ((TitledBorder)currentBorder).setTitleFont(font);
						if (color != null) ((TitledBorder)currentBorder).setTitleColor(color);

//						if (font == null)
//						{
//							currentBorder = BorderFactory.createTitledBorder(null,title,justification,position);
//						}
//						else
//						{
//							if (font != null && color != null)
//							{
//								currentBorder = BorderFactory.createTitledBorder(null,title,justification,position,font,color);
//							}
//							else
//							{
//								currentBorder = BorderFactory.createTitledBorder(null,title,justification,position,font);
//							}
//						}
					}
					else if (type.equals("MatteBorder")) //$NON-NLS-1$
					{
						int top = Utils.getAsInteger(tk.nextToken());
						int right = Utils.getAsInteger(tk.nextToken());
						int bottom = Utils.getAsInteger(tk.nextToken());
						int left = Utils.getAsInteger(tk.nextToken());
						Color color = Color.black;
						if (tk.hasMoreElements()) color = PersistHelper.createColor(tk.nextToken());
						currentBorder = BorderFactory.createMatteBorder(top, left, bottom, right, color);
					}
					else if (type.equals("SpecialMatteBorder")) //$NON-NLS-1$
					{
						float top = Utils.getAsFloat(tk.nextToken());
						float right = Utils.getAsFloat(tk.nextToken());
						float bottom = Utils.getAsFloat(tk.nextToken());
						float left = Utils.getAsFloat(tk.nextToken());
						Color topColor = PersistHelper.createColor(tk.nextToken());
						Color rightColor = PersistHelper.createColor(tk.nextToken());
						Color bottomColor = PersistHelper.createColor(tk.nextToken());
						Color leftColor = PersistHelper.createColor(tk.nextToken());
						currentBorder = new SpecialMatteBorder(top, left, bottom, right, topColor, leftColor, bottomColor, rightColor);
						if (tk.hasMoreTokens())
						{
							((SpecialMatteBorder)currentBorder).setRoundingRadius(Utils.getAsFloat(tk.nextToken()));
						}
						if (tk.hasMoreTokens())
						{
							((SpecialMatteBorder)currentBorder).setDashPattern(SpecialMatteBorder.createDash(tk.nextToken()));
						}
					}
					else
					{
						currentBorder = BorderFactory.createEtchedBorder();
					}
				}
				catch (Exception ex)
				{
					Debug.error(ex);
					return null;
				}
			}
			else
			{
				currentBorder = BorderFactory.createEtchedBorder();
			}
		}
		return currentBorder;
	}

	public static Insets createBorderCSSProperties(String s, Properties style)
	{
		if (s == null)
		{
			// no border specified
			return null;
		}
		else
		{
			StringTokenizer tk = new StringTokenizer(s, ","); //$NON-NLS-1$
			if (tk.hasMoreTokens())
			{
				try
				{
					String type = tk.nextToken();
					if (type.equals("CompoundBorder")) //$NON-NLS-1$
					{
						StringTokenizer tk2 = new StringTokenizer(s, ";"); //$NON-NLS-1$
						tk2.nextToken();//skip 'CompoundBorder,' token
						String s_oborder = tk2.nextToken();
						return createBorderCSSProperties(s_oborder, style);
					}
					else if (type.equals("EmptyBorder")) //$NON-NLS-1$
					{
						int top = Utils.getAsInteger(tk.nextToken());
						int right = Utils.getAsInteger(tk.nextToken());
						int bottom = Utils.getAsInteger(tk.nextToken());
						int left = Utils.getAsInteger(tk.nextToken());
						if (top != 0 && right != 0 && bottom != 0 && left != 0)
						{
							StringBuffer pad = new StringBuffer();
							pad.append(top);
							pad.append("px "); //$NON-NLS-1$
							pad.append(right);
							pad.append("px "); //$NON-NLS-1$
							pad.append(bottom);
							pad.append("px "); //$NON-NLS-1$
							pad.append(left);
							pad.append("px"); //$NON-NLS-1$
							style.setProperty("padding", pad.toString()); //$NON-NLS-1$
						}
						style.setProperty("border-style", "none"); //$NON-NLS-1$ //$NON-NLS-2$
						return new Insets(top, left, bottom, right);
					}
					else if (type.equals("BevelBorder") || type.equals("EtchedBorder")) //$NON-NLS-1$ //$NON-NLS-2$
					{
						int beveltype = Utils.getAsInteger(tk.nextToken());
						if (tk.hasMoreTokens())
						{
							Color highlightO = null;
							Color highlightI = null;
							Color shadowO = null;
							Color shadowI = null;
							if (type.equals("BevelBorder")) //$NON-NLS-1$
							{
								highlightO = PersistHelper.createColor(tk.nextToken());
								highlightI = PersistHelper.createColor(tk.nextToken());
								shadowO = PersistHelper.createColor(tk.nextToken());
								shadowI = PersistHelper.createColor(tk.nextToken());
							}
							else
							{
								highlightO = PersistHelper.createColor(tk.nextToken());
								highlightI = highlightO;
								shadowO = PersistHelper.createColor(tk.nextToken());
								shadowI = shadowO;
							}
							if (beveltype == BevelBorder.LOWERED)
							{
								if (PersistHelper.createColorString(shadowO) != null)
								{
									StringBuffer pad = new StringBuffer();
									pad.append(PersistHelper.createColorString(shadowO));
									pad.append(' ');
									pad.append(PersistHelper.createColorString(highlightI));
									pad.append(' ');
									pad.append(PersistHelper.createColorString(highlightO));
									pad.append(' ');
									pad.append(PersistHelper.createColorString(shadowI));
									style.setProperty("border-color", pad.toString()); //$NON-NLS-1$
								}
								if (type.equals("BevelBorder")) //$NON-NLS-1$
								{
									style.setProperty("border-style", "inset"); //$NON-NLS-1$ //$NON-NLS-2$
								}
								else
								{
									style.setProperty("border-style", "grooved"); //$NON-NLS-1$ //$NON-NLS-2$
								}
							}
							else
							{
								if (PersistHelper.createColorString(shadowO) != null)
								{
									StringBuffer pad = new StringBuffer();
									pad.append(PersistHelper.createColorString(highlightO));
									pad.append(' ');
									pad.append(PersistHelper.createColorString(shadowI));
									pad.append(' ');
									pad.append(PersistHelper.createColorString(shadowO));
									pad.append(' ');
									pad.append(PersistHelper.createColorString(highlightI));
									style.setProperty("border-color", pad.toString()); //$NON-NLS-1$
								}
								if (type.equals("BevelBorder")) //$NON-NLS-1$
								{
									style.setProperty("border-style", "outset"); //$NON-NLS-1$ //$NON-NLS-2$
								}
								else
								{
									style.setProperty("border-style", "grooved"); //$NON-NLS-1$ //$NON-NLS-2$
								}
							}
							return null;//TODO waht are the insets?
						}
						else
						{
							style.setProperty("border-style", (beveltype == BevelBorder.LOWERED ? "inset" : "outset")); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
							return null;//TODO waht are the insets?
						}
					}
					else if (type.equals("LineBorder")) //$NON-NLS-1$
					{
						int thick = Utils.getAsInteger(tk.nextToken());
						style.setProperty("border-style", "solid"); //$NON-NLS-1$ //$NON-NLS-2$
						style.setProperty("border-width", thick + "px"); //$NON-NLS-1$ //$NON-NLS-2$
						style.setProperty("border-color", tk.nextToken()); //$NON-NLS-1$
						return new Insets(thick, thick, thick, thick);
					}
					else if (type.equals("TitledBorder")) //$NON-NLS-1$
					{
						style.setProperty("border-style", "grooved"); //$NON-NLS-1$ //$NON-NLS-2$
						return null;//TODO waht are the insets?
					}
					else if (type.equals("MatteBorder")) //$NON-NLS-1$
					{
						int top = Utils.getAsInteger(tk.nextToken());
						int right = Utils.getAsInteger(tk.nextToken());
						int bottom = Utils.getAsInteger(tk.nextToken());
						int left = Utils.getAsInteger(tk.nextToken());
						Color c = Color.black;
						if (tk.hasMoreElements()) c = PersistHelper.createColor(tk.nextToken());
						style.setProperty("border-style", "solid"); //$NON-NLS-1$ //$NON-NLS-2$
						StringBuffer pad = new StringBuffer();
						pad.append(top);
						pad.append("px "); //$NON-NLS-1$
						pad.append(right);
						pad.append("px "); //$NON-NLS-1$
						pad.append(bottom);
						pad.append("px "); //$NON-NLS-1$
						pad.append(left);
						pad.append("px"); //$NON-NLS-1$
						style.setProperty("border-width", pad.toString()); //$NON-NLS-1$
						style.setProperty("border-color", PersistHelper.createColorString(c)); //$NON-NLS-1$
						return new Insets(top, left, bottom, right);
					}
					else if (type.equals("SpecialMatteBorder")) //$NON-NLS-1$
					{
						float top = Utils.getAsFloat(tk.nextToken());
						float right = Utils.getAsFloat(tk.nextToken());
						float bottom = Utils.getAsFloat(tk.nextToken());
						float left = Utils.getAsFloat(tk.nextToken());
						StringBuffer pad = new StringBuffer();
						pad.append(Math.round(top));
						pad.append("px "); //$NON-NLS-1$
						pad.append(Math.round(right));
						pad.append("px "); //$NON-NLS-1$
						pad.append(Math.round(bottom));
						pad.append("px "); //$NON-NLS-1$
						pad.append(Math.round(left));
						pad.append("px"); //$NON-NLS-1$
						style.setProperty("border-width", pad.toString()); //$NON-NLS-1$

						Color topColor = PersistHelper.createColor(tk.nextToken());
						Color rightColor = PersistHelper.createColor(tk.nextToken());
						Color bottomColor = PersistHelper.createColor(tk.nextToken());
						Color leftColor = PersistHelper.createColor(tk.nextToken());
						StringBuffer c = new StringBuffer();
						c.append(PersistHelper.createColorString(topColor));
						c.append(' ');
						c.append(PersistHelper.createColorString(rightColor));
						c.append(' ');
						c.append(PersistHelper.createColorString(bottomColor));
						c.append(' ');
						c.append(PersistHelper.createColorString(leftColor));
						style.setProperty("border-color", c.toString()); //$NON-NLS-1$

						style.setProperty("border-style", "solid"); //$NON-NLS-1$ //$NON-NLS-2$
						if (tk.hasMoreTokens())
						{
							//ignore rounded
							tk.nextToken();
						}
						if (tk.hasMoreTokens() && tk.nextToken().trim().length() != 0)
						{
							style.setProperty("border-style", "dashed"); //$NON-NLS-1$ //$NON-NLS-2$
						}
						return new Insets(Math.round(top), Math.round(left), Math.round(bottom), Math.round(right));
					}
					else
					{
						return null;
					}
				}
				catch (Exception ex)
				{
					Debug.error(ex);
					return null;
				}
			}
			else
			{
				return null;
			}
		}
	}
}
