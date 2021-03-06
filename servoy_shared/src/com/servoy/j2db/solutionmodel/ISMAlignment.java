/*
 This file belongs to the Servoy development and deployment environment, Copyright (C) 1997-2012 Servoy BV

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

package com.servoy.j2db.solutionmodel;

import javax.swing.SwingConstants;

import com.servoy.base.persistence.constants.IContentSpecConstantsBase;
import com.servoy.j2db.persistence.TabPanel;

/**
 * Constants used for alignment property.
 * 
 * @since 7.0
 * @author acostescu
 */
public interface ISMAlignment
{

	/**
	 * Constant used for setting horizontal and vertical alignment. DEFAULT value makes the alignment behave as if it was not changed before.
	 * 
	 * @sample
	 * var hLabel = myJSForm.getLabel('label_name');
	 * if (hLabel.horizontalAlignment == SM_ALIGNMENT.LEFT) hLabel.horizontalAlignment = SM_ALIGNMENT.DEFAULT;
	 */
	public static final int DEFAULT = IContentSpecConstantsBase.MINUS_ONE.intValue();

	/**
	 * Constant used for setting horizontal and vertical alignment
	 * for components. If used for horizontal alignment,
	 * then the text of the component will be horizontally centered.
	 * Similarly, if used for vertical alignment, then the text
	 * of the component will be vertically centered.
	 * 
	 * @sample
	 * var hCenteredLabel = form.newLabel('CENTER', 10, 40, 300, 20);
	 * hCenteredLabel.horizontalAlignment = SM_ALIGNMENT.CENTER;
	 * var vCenterAlignedLabel = form.newLabel('CENTER', 460, 10, 50, 300);
	 * vCenterAlignedLabel.verticalAlignment = SM_ALIGNMENT.CENTER
	 */
	public static final int CENTER = SwingConstants.CENTER;

	/**
	 * Constant used for setting vertical alignment for components.
	 * It makes the text inside the component be top aligned vertically.
	 * 
	 * @sample
	 * var topAlignedLabel = form.newLabel('TOP', 400, 10, 50, 300);
	 * topAlignedLabel.verticalAlignment = SM_ALIGNMENT.TOP;
	 */
	public static final int TOP = SwingConstants.TOP;

	/**
	 * Constant used for setting horizontal alignment for components.
	 * It makes the text inside the component be left aligned horizontally.
	 * 
	 * @sample
	 * var leftAlignedLabel = form.newLabel('LEFT', 10, 10, 300, 20);
	 * leftAlignedLabel.horizontalAlignment = SM_ALIGNMENT.LEFT;
	 */
	public static final int LEFT = SwingConstants.LEFT;

	/**
	 * Constant used for setting vertical alignment for components.
	 * It makes the text inside the component be bottom aligned vertically.
	 * 
	 * @sample
	 * var bottomAlignedLabel = form.newLabel('BOTTOM', 520, 10, 50, 300);
	 * bottomAlignedLabel.verticalAlignment = SM_ALIGNMENT.BOTTOM;
	 */
	public static final int BOTTOM = SwingConstants.BOTTOM;

	/**
	 * Constant used for setting horizontal alignment for components.
	 * It makes the text inside the component be right aligned vertically.
	 * 
	 * @sample
	 * var rightAlignedLabel = form.newLabel('RIGHT', 10, 70, 300, 20);
	 * rightAlignedLabel.horizontalAlignment = SM_ALIGNMENT.RIGHT;
	 */
	public static final int RIGHT = SwingConstants.RIGHT;

	/**
	 * Constant used for creating horizontal split pane from tab panel, by setting its tabOrientation.
	 * 
	 * @sample
	 * var splitPane = myForm.newTabPanel('splitPane', 10, 10, 620, 460);
	 * splitPane.tabOrientation = SM_ALIGNMENT.SPLIT_HORIZONTAL;
	 * 
	 * @deprecated please use {@link com.servoy.j2db.solutionmodel.ISMTabPanel#SPLIT_HORIZONTAL} instead.
	 */
	@Deprecated
	public static final int SPLIT_HORIZONTAL = TabPanel.SPLIT_HORIZONTAL;

	/**
	 * Constant used for creating vertical split pane from tab panel, by setting its tabOrientation.
	 * 
	 * @sample
	 * var splitPane = myForm.newTabPanel('splitPane', 10, 10, 620, 460);
	 * splitPane.tabOrientation = SM_ALIGNMENT.SPLIT_VERTICAL;
	 * 
	 * @deprecated please use {@link com.servoy.j2db.solutionmodel.ISMTabPanel#SPLIT_VERTICAL} instead.
	 */
	@Deprecated
	public static final int SPLIT_VERTICAL = TabPanel.SPLIT_VERTICAL;

	/**
	 * Constant used for creating accordion panel from tab panel, by setting its tabOrientation.
	 * 
	 * @sample
	 * var accordion = myForm.newTabPanel('accordion', 10, 10, 620, 460);
	 * accordion.tabOrientation = SM_ALIGNMENT.ACCORDION_PANEL;
	 * 
	 * @deprecated please use {@link com.servoy.j2db.solutionmodel.ISMTabPanel#ACCORDION_PANEL} instead.
	 */
	@Deprecated
	public static final int ACCORDION_PANEL = TabPanel.ACCORDION_PANEL;

}
