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
package com.servoy.j2db.ui.runtime;

import org.mozilla.javascript.annotations.JSFunction;

/**
 * Interface for components with scrolling support.
 * 
 * @author rgansevles
 * 
 *  @since 6.1
 *
 */
public interface HasRuntimeScroll
{
	/**
	 * Returns the x scroll location of specified element - only for an element where height of element is less than the height of element content.
	 * 
	 * NOTE: getScrollX() can be used with getScrollY() to set the scroll location of an element using the setScroll function. For Example:
	 * 
	 * //returns the X and Y scroll coordinates
	 * var x = forms.company.elements.portal50.getScrollX();
	 * var y = forms.company.elements.portal50.getScrollY();
	 * 
	 * //sets the new scroll location
	 * forms.company.elements.portal50.setScroll(x+10,y+10);
	 *
	 * @sample
	 * var x = %%prefix%%%%elementName%%.getScrollX();
	 * 
	 * @return The x scroll location in pixels.
	 */
	@JSFunction
	public int getScrollX();

	/**
	 * Returns the y scroll location of specified element - only for an element where height of element is less than the height of element content.
	 * 
	 * NOTE: getScrollY() can be used with getScrollX() to set the scroll location of an element using the setScroll function. For Example:
	 * 
	 * //returns the X and Y scroll coordinates
	 * var x = forms.company.elements.portal50.getScrollX();
	 * var y = forms.company.elements.portal50.getScrollY();
	 * 
	 * //sets the new scroll location
	 * forms.company.elements.portal50.setScroll(x+10,y+10);
	 *
	 * @sample
	 * var y = %%prefix%%%%elementName%%.getScrollY();
	 * 
	 * @return The y scroll location in pixels.
	 */
	@JSFunction
	public int getScrollY();

	/**
	 * Sets the scroll location of an element. It takes as input the X (horizontal) and Y (vertical) coordinates - starting from the TOP LEFT side of the screen - only for an element where the height of the element is greater than the height of element content
	 * 
	 * NOTE: getScrollX() can be used with getScrollY() to return the current scroll location of an element; then use the X and Y coordinates with the setScroll function to set a new scroll location. For Example:
	 * 
	 * //returns the X and Y coordinates
	 * var x = forms.company.elements.portal50.getScrollX();
	 * var y = forms.company.elements.portal50.getScrollY();
	 * 
	 * //sets the new location
	 * forms.company.elements.portal50.setScroll(x+10,y+10);
	 *
	 * @sample
	 * %%prefix%%%%elementName%%.setScroll(200,200);
	 *
	 * @param x the X coordinate of the portal scroll location in pixels
	 * @param y the Y coordinate of the portal scroll location in pixels
	 */
	@JSFunction
	public void setScroll(int x, int y);
}
