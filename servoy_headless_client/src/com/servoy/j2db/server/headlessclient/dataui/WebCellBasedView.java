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

import java.awt.Color;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Insets;
import java.awt.Point;
import java.awt.Rectangle;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.StringTokenizer;

import javax.swing.BorderFactory;
import javax.swing.border.Border;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.text.html.CSS;

import org.apache.wicket.AttributeModifier;
import org.apache.wicket.Component;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.Page;
import org.apache.wicket.RequestCycle;
import org.apache.wicket.ResourceReference;
import org.apache.wicket.Response;
import org.apache.wicket.Session;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.IAjaxCallDecorator;
import org.apache.wicket.ajax.calldecorator.AjaxPostprocessingCallDecorator;
import org.apache.wicket.behavior.IBehavior;
import org.apache.wicket.behavior.IIgnoreDisabledComponentBehavior;
import org.apache.wicket.behavior.SimpleAttributeModifier;
import org.apache.wicket.markup.ComponentTag;
import org.apache.wicket.markup.MarkupElement;
import org.apache.wicket.markup.MarkupStream;
import org.apache.wicket.markup.WicketTag;
import org.apache.wicket.markup.html.IHeaderResponse;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.internal.HtmlHeaderContainer;
import org.apache.wicket.markup.html.list.ListItem;
import org.apache.wicket.markup.html.list.ListView;
import org.apache.wicket.markup.html.navigation.paging.PagingNavigator;
import org.apache.wicket.markup.resolver.IComponentResolver;
import org.apache.wicket.model.IModel;
import org.apache.wicket.model.Model;
import org.apache.wicket.protocol.http.request.WebClientInfo;
import org.apache.wicket.request.ClientInfo;
import org.apache.wicket.response.StringResponse;
import org.apache.wicket.util.string.AppendingStringBuffer;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.Undefined;

import com.servoy.j2db.FormController;
import com.servoy.j2db.FormManager;
import com.servoy.j2db.IApplication;
import com.servoy.j2db.IForm;
import com.servoy.j2db.IMainContainer;
import com.servoy.j2db.IScriptExecuter;
import com.servoy.j2db.IView;
import com.servoy.j2db.MediaURLStreamHandler;
import com.servoy.j2db.component.ComponentFactory;
import com.servoy.j2db.dataprocessing.DBValueList;
import com.servoy.j2db.dataprocessing.DataAdapterList;
import com.servoy.j2db.dataprocessing.FindState;
import com.servoy.j2db.dataprocessing.FoundSet;
import com.servoy.j2db.dataprocessing.FoundSetListWrapper;
import com.servoy.j2db.dataprocessing.FoundSetManager;
import com.servoy.j2db.dataprocessing.IDataAdapter;
import com.servoy.j2db.dataprocessing.IDisplay;
import com.servoy.j2db.dataprocessing.IDisplayData;
import com.servoy.j2db.dataprocessing.IDisplayRelatedData;
import com.servoy.j2db.dataprocessing.IFoundSetInternal;
import com.servoy.j2db.dataprocessing.IRecordInternal;
import com.servoy.j2db.dataprocessing.ISwingFoundSet;
import com.servoy.j2db.dataprocessing.IValueList;
import com.servoy.j2db.dataprocessing.Record;
import com.servoy.j2db.dataprocessing.Row;
import com.servoy.j2db.dataprocessing.SortColumn;
import com.servoy.j2db.dataui.IServoyAwareBean;
import com.servoy.j2db.dnd.DRAGNDROP;
import com.servoy.j2db.dnd.JSDNDEvent;
import com.servoy.j2db.persistence.AbstractBase;
import com.servoy.j2db.persistence.BaseComponent;
import com.servoy.j2db.persistence.Bean;
import com.servoy.j2db.persistence.Field;
import com.servoy.j2db.persistence.Form;
import com.servoy.j2db.persistence.GraphicalComponent;
import com.servoy.j2db.persistence.IDataProviderLookup;
import com.servoy.j2db.persistence.IFormElement;
import com.servoy.j2db.persistence.IPersist;
import com.servoy.j2db.persistence.IRepository;
import com.servoy.j2db.persistence.ISupportAnchors;
import com.servoy.j2db.persistence.ISupportBounds;
import com.servoy.j2db.persistence.ISupportName;
import com.servoy.j2db.persistence.ISupportScrollbars;
import com.servoy.j2db.persistence.ISupportTabSeq;
import com.servoy.j2db.persistence.Part;
import com.servoy.j2db.persistence.Portal;
import com.servoy.j2db.persistence.PositionComparator;
import com.servoy.j2db.persistence.Relation;
import com.servoy.j2db.persistence.RepositoryException;
import com.servoy.j2db.persistence.TabSeqComparator;
import com.servoy.j2db.persistence.Table;
import com.servoy.j2db.persistence.ValueList;
import com.servoy.j2db.scripting.IScriptable;
import com.servoy.j2db.scripting.IScriptableProvider;
import com.servoy.j2db.scripting.JSEvent.EventType;
import com.servoy.j2db.server.headlessclient.MainPage;
import com.servoy.j2db.server.headlessclient.PageContributor;
import com.servoy.j2db.server.headlessclient.TabIndexHelper;
import com.servoy.j2db.server.headlessclient.WebForm;
import com.servoy.j2db.server.headlessclient.dataui.TemplateGenerator.TextualStyle;
import com.servoy.j2db.server.headlessclient.dnd.DraggableBehavior;
import com.servoy.j2db.ui.DataRendererOnRenderWrapper;
import com.servoy.j2db.ui.IComponent;
import com.servoy.j2db.ui.IDataRenderer;
import com.servoy.j2db.ui.IFieldComponent;
import com.servoy.j2db.ui.ILabel;
import com.servoy.j2db.ui.IPortalComponent;
import com.servoy.j2db.ui.IProviderStylePropertyChanges;
import com.servoy.j2db.ui.IScriptRenderMethods;
import com.servoy.j2db.ui.IStylePropertyChanges;
import com.servoy.j2db.ui.IStylePropertyChangesRecorder;
import com.servoy.j2db.ui.ISupportOnRenderCallback;
import com.servoy.j2db.ui.ISupportRowStyling;
import com.servoy.j2db.ui.ISupportValueList;
import com.servoy.j2db.ui.ISupportWebBounds;
import com.servoy.j2db.ui.PropertyCopy;
import com.servoy.j2db.ui.RenderableWrapper;
import com.servoy.j2db.ui.runtime.HasRuntimeReadOnly;
import com.servoy.j2db.ui.runtime.IRuntimeComponent;
import com.servoy.j2db.ui.scripting.RuntimePortal;
import com.servoy.j2db.util.ComponentFactoryHelper;
import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.IAnchorConstants;
import com.servoy.j2db.util.IStyleRule;
import com.servoy.j2db.util.IStyleSheet;
import com.servoy.j2db.util.ISupplyFocusChildren;
import com.servoy.j2db.util.OrientationApplier;
import com.servoy.j2db.util.Pair;
import com.servoy.j2db.util.PersistHelper;
import com.servoy.j2db.util.ScopesUtils;
import com.servoy.j2db.util.SortedList;
import com.servoy.j2db.util.Utils;

/**
 * This class is normally used to show a portal or tableview
 * 
 * @author jblok
 */
public class WebCellBasedView extends WebMarkupContainer implements IView, IPortalComponent, IDataRenderer, IProviderStylePropertyChanges, TableModelListener,
	ListSelectionListener, ISupportWebBounds, ISupportWebTabSeq, ISupportRowStyling
{
//	private static final int SCROLLBAR_SIZE = 17;
	private static final long serialVersionUID = 1L;

	public final ResourceReference R_ARROW_OFF = new ResourceReference(IApplication.class, "images/arrow_off.png"); //$NON-NLS-1$
	public final ResourceReference R_ARROW_DOWN = new ResourceReference(IApplication.class, "images/arrow_down.png"); //$NON-NLS-1$
	public final ResourceReference R_ARROW_UP = new ResourceReference(IApplication.class, "images/arrow_up.png"); //$NON-NLS-1$

	private final LinkedHashMap<IPersist, Component> elementToColumnIdentifierComponent = new LinkedHashMap<IPersist, Component>(); // IPersist -> column identifier components - used by JavaScript
	private final HashMap<IPersist, Integer> elementTabIndexes = new HashMap<IPersist, Integer>();
	private final LinkedHashMap<Component, IPersist> cellToElement = new LinkedHashMap<Component, IPersist>(); // each cell component -> IPersist (on the form)
	private final Map<IPersist, Component> elementToColumnHeader = new HashMap<IPersist, Component>(); // links each column identifier component
	private final Map<IRuntimeComponent, Map<String, String>> runtimeComponentStyleAttributes = new HashMap<IRuntimeComponent, Map<String, String>>();
	// to a column header component (if such a component exists)

	private String relationName;
	private List<SortColumn> defaultSort = null;

	private SortableCellViewHeaders headers;
	private final WebMarkupContainer tableContainerBody;
	private final WebCellBasedViewListView table;
	private final IModel<FoundSetListWrapper> data = new Model<FoundSetListWrapper>();
	private PagingNavigator pagingNavigator;
	boolean showPageNavigator = true;
	private DataAdapterList dal;

	private final Map<String, Boolean> initialSortColumnNames = new HashMap<String, Boolean>();
	private final Map<String, Boolean> initialSortedColumns = new HashMap<String, Boolean>();

	private final boolean addHeaders;

	private int tabIndex;

	private final IApplication application;
	private final AbstractBase cellview;
	protected final FormController fc;
	private final int startY, endY, sizeHint, formDesignHeight;
	private int maxHeight;
	private int bodyHeightHint = -1;
	private int bodyWidthHint = -1;

	private final boolean useAJAX, useAnchors;
	private Component resizedComponent; // the component that has been resized because of a column resize

	private final ISupportOnRenderCallback dataRendererOnRenderWrapper;
	private IStyleSheet styleSheet;
	private IStyleRule oddStyle, evenStyle, selectedStyle, headerStyle;

	private ServoyTableResizeBehavior tableResizeBehavior;
	private boolean bodySizeHintSetFromClient;
	private Label loadingInfo; // used to show loading info when rendering is postponed waiting for size info response from browser\
	private String lastRenderedPath;
	private boolean isAnchored;
	private final RuntimePortal scriptable;

	private boolean isScrollMode;
	private ScrollBehavior scrollBehavior;
	private int maxRowsPerPage;
	private boolean isKeepLoadedRowsInScrollMode;

	private int viewType;

	private boolean isLeftToRightOrientation;
	private Dimension formBodySize;

	private boolean isListViewMode;

	/***
	 * This class is used to rerender the odd/even/selected style (with css transparency fallback color) upon creation of the table  (table is created via an ajax call).
	 * <p>
	 * It was introduced because renderering IRuntimeComponent does not support duplicate rules needed for fallback colors, it adds the javascript rowselectionscript to be executed 
	 * just after all the rows components is rendered.
	 * @author Ovidiu
	 *
	 */
	private final class OddEvenSelectedBehavior extends AbstractServoyDefaultAjaxBehavior implements IIgnoreDisabledComponentBehavior
	{
		@Override
		public void renderHead(IHeaderResponse response)
		{
			String rowSelScritpt = getRowSelectionScript(true);
			if (rowSelScritpt != null)
			{
				response.renderOnDomReadyJavascript(rowSelScritpt);
			}
		}

		@Override
		protected void respond(AjaxRequestTarget target)
		{
			//no implementation . This behavior only needs to add javascript to the head section
		}

	}


	/**
	 * @author jcompagner
	 *
	 */
	private final class ServoyTableResizeBehavior extends AbstractServoyDefaultAjaxBehavior implements IIgnoreDisabledComponentBehavior
	{
		private final int resizeStartY;
		private final int resizeEndY;
		private final AbstractBase resizeCellview;
		private boolean responded = false;

		/**
		 * @param startY
		 * @param endY
		 * @param cellview
		 */
		private ServoyTableResizeBehavior(int startY, int endY, AbstractBase cellview)
		{
			this.resizeStartY = startY;
			this.resizeEndY = endY;
			this.resizeCellview = cellview;
		}

		@SuppressWarnings("nls")
		@Override
		public void renderHead(IHeaderResponse response)
		{
			super.renderHead(response);
			String cellViewId = WebCellBasedView.this.getMarkupId();

			StringBuilder sb = new StringBuilder();

			if (useAnchors)
			{
				sb.append("if(typeof(tablesPreferredHeight) != \"undefined\")\n").append("{\n"); //$NON-NLS-1$ //$NON-NLS-2$
				sb.append("tablesPreferredHeight['").append(cellViewId).append("'] = new Array();\n"); //$NON-NLS-1$ //$NON-NLS-2$
				sb.append("tablesPreferredHeight['").append(cellViewId).append("']['height'] = ").append(bodyHeightHint).append(";\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				sb.append("tablesPreferredHeight['").append(cellViewId).append("']['width'] = ").append(bodyWidthHint).append(";\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				sb.append("tablesPreferredHeight['").append(cellViewId).append("']['callback'] = '").append(getCallbackUrl()).append("';\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				sb.append("}\n"); //$NON-NLS-1$
			}
			else if (!responded) // this flag guards against the possibility of endless loop that keeps replacing whole table view generated by following JS code + code in "respond(...)" that alters bodyHeightHint
			{
				sb.append("var preferredSize = getPreferredTableSize('").append(cellViewId); //$NON-NLS-1$ //$NON-NLS-2$
				sb.append("');\n"); //$NON-NLS-1$ 
				sb.append("if(preferredSize && preferredSize[1] != ").append(bodyHeightHint).append(") wicketAjaxGet('").append(getCallbackUrl()).append( //$NON-NLS-1$ //$NON-NLS-2$
					"&bodyWidth=' + preferredSize[0] + '&bodyHeight=' + preferredSize[1]);\n"); //$NON-NLS-1$ 
			}
			response.renderOnLoadJavascript(sb.toString());
			responded = false;
		}

		@Override
		protected void respond(AjaxRequestTarget target)
		{
			responded = true;

			int newBodyWidthHint = Integer.parseInt(getComponent().getRequest().getParameter("bodyWidth")); //$NON-NLS-1$ 
			int newBodyHeightHint = Integer.parseInt(getComponent().getRequest().getParameter("bodyHeight")); //$NON-NLS-1$ 

			if (isScrollMode() && needsMoreThanOnePage(newBodyHeightHint).getLeft().booleanValue())
			{
				newBodyWidthHint -= 17; // extract the vertical scrollbar width
			}

			if (newBodyWidthHint != bodyWidthHint || newBodyHeightHint != bodyHeightHint || !bodySizeHintSetFromClient)
			{
				bodyWidthHint = newBodyWidthHint;
				bodyHeightHint = newBodyHeightHint;
				bodySizeHintSetFromClient = true;

				distributeExtraSpace();

				IWebFormContainer tabPanel = findParent(IWebFormContainer.class);
				if (tabPanel instanceof WebTabPanel)
				{
					int bodyDesignHeight = resizeEndY - resizeStartY;
					int otherPartsHeight = (resizeCellview instanceof Portal) ? 0 : formDesignHeight - bodyDesignHeight;
					((WebTabPanel)tabPanel).setTabSize(new Dimension(bodyWidthHint, bodyHeightHint + otherPartsHeight));
				}
				WebCellBasedView.this.setVisibilityAllowed(true);
				WebCellBasedView.this.getStylePropertyChanges().setChanged();
				WebEventExecutor.generateResponse(target, getComponent().getPage());
			}
		}
	}


	public static class CellContainer extends WebMarkupContainer
	{
		private final Component childComp;

		public CellContainer(Component childComp)
		{
			super(childComp.getId() + '_');
			this.childComp = childComp;
		}

		public static Component getContentsForCell(Component child)
		{
			if (child instanceof CellContainer)
			{
				Iterator< ? extends Component> it = ((CellContainer)child).iterator();
				if (it.hasNext())
				{
					return it.next();
				}
				Debug.log("Strange - CellContainer with no child..."); //$NON-NLS-1$
			}
			return child;
		}

		@Override
		protected void onBeforeRender()
		{
			if (childComp instanceof IComponent)
			{
				Color childCompBG = ((IComponent)childComp).getBackground();
				super.onBeforeRender();
				Color newChildBG = ((IComponent)childComp).getBackground();
				if (!Utils.equalObjects(childCompBG, newChildBG))
				{
					String sNewChildBG = newChildBG != null ? PersistHelper.createColorString(newChildBG) : ""; //$NON-NLS-1$
					add(new StyleAppendingModifier(new Model<String>("background-color: " + sNewChildBG))); //$NON-NLS-1$
				}
			}
			else
			{
				super.onBeforeRender();
			}
		}
	}

	interface ItemAdd
	{
		void add(IPersist element, Component comp);
	}

	/*
	 * (Persist, ColumnIdentifierComponent) used to compare based on X position; if ColumnIdentifierComponent X position is not available, the persist position
	 * is used
	 */
	private static class PersistColumnIdentifierComponent implements Comparable<PersistColumnIdentifierComponent>
	{
		private final IPersist persist;
		private final IComponent component;

		public PersistColumnIdentifierComponent(IPersist persist, IComponent component)
		{
			this.persist = persist;
			this.component = component;
		}

		public IPersist getPersist()
		{
			return persist;
		}

		public IComponent getComponent()
		{
			return component;
		}

		public int compareTo(PersistColumnIdentifierComponent pc)
		{
			if (pc == null) return -1;
			IComponent c = pc.getComponent();

			Point componentLocation = component.getLocation();
			if (componentLocation == null)
			{
				componentLocation = ((ISupportBounds)persist).getLocation();
			}

			Point cLocation = c.getLocation();
			if (cLocation == null)
			{
				cLocation = ((ISupportBounds)pc.getPersist()).getLocation();
			}

			return PositionComparator.comparePoint(true, componentLocation, cLocation);
		}
	}

	private class WebCellBasedViewListView extends ServoyListView<IRecordInternal>
	{
		private final AbstractBase listCellview;
		private final IDataProviderLookup dataProviderLookup;
		private final IScriptExecuter el;
		private final int listStartY, listEndY;
		private final Form form;

		public WebCellBasedViewListView(String id, IModel<FoundSetListWrapper> model, int rowsPerPage, AbstractBase cellview,
			IDataProviderLookup dataProviderLookup, IScriptExecuter el, int startY, int endY, Form form)
		{
			super(id, model, rowsPerPage);
			this.listCellview = cellview;
			this.dataProviderLookup = dataProviderLookup;
			this.el = el;
			this.listStartY = startY;
			this.listEndY = endY;
			this.form = form;
		}

		@Override
		protected void onBeforeRender()
		{
			getViewSize();
			final int firstIndex = getStartIndex();
			for (int i = 0; i < getViewSize(); i++)
			{
				// Get index
				final int index = firstIndex + i;
				getList().get(index);
				updateListItem(index);
			}
			updateHeaders();

			super.onBeforeRender();

			//set focus on correct (cell) component now; cells should be created at this point
			if (focusRequestingColIdentComponent != null)
			{
				Component cell = getCellToFocus(focusRequestingColIdentComponent);

				if (cell != null && RequestCycle.get().getRequestTarget() instanceof AjaxRequestTarget)
				{
					((AjaxRequestTarget)RequestCycle.get().getRequestTarget()).focusComponent(cell);
				}
				else
				{
					Debug.log("couldn't set focus to " + focusRequestingColIdentComponent); //$NON-NLS-1$
				}
				focusRequestingColIdentComponent = null;
			}

			permitRemovedCellComponentsToBeCollected();
		}

		/**
		 * Create a new ListItem for list item at index.
		 * 
		 * @param index
		 * @return ListItem
		 */
		@Override
		protected ListItem<IRecordInternal> newItem(final int index)
		{
			if (WebCellBasedView.this.addHeaders)
			{
				return new ReorderableListItem(index, getListItemModel(getModel(), index));
			}
			else
			{
				return new WebCellBasedViewListItem(index, getListItemModel(getModel(), index));
			}
		}

		private void permitRemovedCellComponentsToBeCollected()
		{
			// cellToElement hash table remembers the IPersist instance for each cell that was created;
			// when a cell is no longer used (it's list item is removed), the cell must be deleted from the
			// hash table as well in order to avoid memory leaks
			List<Component> validChildren = new ArrayList<Component>();

			int firstIndex = getStartIndex();
			int index;
			for (int i = 0; i < getViewSize(); i++)
			{
				index = firstIndex + i;
				ListItem<IRecordInternal> item = (ListItem<IRecordInternal>)get(Integer.toString(index));
				if (item != null)
				{
					Iterator< ? extends Component> children = item.iterator();
					while (children.hasNext())
					{
						Component child = CellContainer.getContentsForCell(children.next());
						validChildren.add(child);
					}
				}
			}

			Iterator<Component> hashedCells = cellToElement.keySet().iterator();
			while (hashedCells.hasNext())
			{
				if (!validChildren.contains(hashedCells.next()))
				{
					hashedCells.remove(); // the cell is no longer used...
				}
			}
		}

		private void updateListItem(int index)
		{
			ListItem<IRecordInternal> item = (ListItem<IRecordInternal>)get(Integer.toString(index));
			if (item != null)
			{
				// update it's model to reflect the correct record (records may have been added/deleted)
				// and the model may no longer be correct (points to a record with another index)
				item.setModel(getListItemModel(getModel(), index));

				// re-apply all changes to the list item and it's child components
				setUpItem(item, false);
			}
		}

		@Override
		protected void populateItem(ListItem<IRecordInternal> listItem)
		{
			setUpItem(listItem, true);
		}

		private boolean isRecordSelected(IRecordInternal rec)
		{
			IFoundSetInternal parentFoundSet = rec.getParentFoundSet();
			if (parentFoundSet instanceof FoundSet)
			{
				FoundSet fs = (FoundSet)parentFoundSet;
				return Arrays.binarySearch(fs.getSelectedIndexes(), fs.getRecordIndex(rec)) >= 0;
			}

			return parentFoundSet.getRecordIndex(rec) == parentFoundSet.getSelectedIndex();
		}

		private void setUpItem(final ListItem<IRecordInternal> listItem, boolean createComponents)
		{
			if (!createComponents)
			{
				// this list item has been set up once before - reset previous behaviors  
				List<IBehavior> allBehaviors = listItem.getBehaviors();
				for (int i = 0; i < allBehaviors.size(); i++)
				{
					listItem.remove(allBehaviors.get(i));
				}
			}

			final IRecordInternal rec = listItem.getModelObject();
			boolean selected = isRecordSelected(rec);

			Object color = null, fgColor = null, styleFont = null, styleBorder = null;

			if (!isListViewMode())
			{
				color = WebCellBasedView.this.getListItemBgColor(listItem, selected, false);
				if (color instanceof Undefined) color = null;
				fgColor = WebCellBasedView.this.getListItemFgColor(listItem, selected, false);
				if (fgColor instanceof Undefined) fgColor = null;
				styleFont = WebCellBasedView.this.getListItemFont(listItem, selected);
				if (styleFont instanceof Undefined) styleFont = null;
				styleBorder = WebCellBasedView.this.getListItemBorder(listItem, selected);
			}

			if (color == null && fgColor == null && styleFont == null && styleBorder == null)
			{
				listItem.add(new AttributeModifier("class", new Model<String>((listItem.getIndex() % 2) == 0 ? "even" : "odd"))); //$NON-NLS-1$//$NON-NLS-2$ //$NON-NLS-3$
			}

			final int visibleRowIndex = listItem.getIndex() % getRowsPerPage();
			final WebMarkupContainer listItemContainer = listItem instanceof WebCellBasedViewListItem ? ((WebCellBasedViewListItem)listItem).getListContainer()
				: listItem;

			if (createComponents)
			{
				final Object compColor = color;
				final Object compFgColor = fgColor;
				final Object compFont = styleFont;
				final Object compBorder = styleBorder;
				createComponents(application, form, listCellview, dataProviderLookup, el, listStartY, listEndY, new ItemAdd()
				{
					public void add(IPersist element, final Component comp)
					{
						Component listItemChild = comp;
						if (!isListViewMode())
						{
							Component component = elementToColumnIdentifierComponent.values().iterator().next();
							if (component instanceof IComponent && comp instanceof IScriptableProvider)
							{
								IScriptable so = ((IScriptableProvider)comp).getScriptObject();
								if (so instanceof IRuntimeComponent)
								{
									IRuntimeComponent ic = (IRuntimeComponent)so;
									ic.setSize(ic.getWidth(), ((IComponent)component).getSize().height);
									ic.setLocation(ic.getLocationX(), visibleRowIndex * ic.getHeight());
								}
							}

							if (element instanceof ISupportName)
							{
								String elementName = ((ISupportName)element).getName();
								if ((elementName != null) && (elementName.trim().length() > 0) || WebCellBasedView.this.addHeaders)
								{
									// this column's cells can be made invisible (and <td> tag is the one that has to change)
									// so we will link this <td> to a wicket component
									listItemChild = new CellContainer(comp);
									listItemChild.setOutputMarkupPlaceholderTag(true);
									((MarkupContainer)listItemChild).add(comp);
								}
							}
						}
						else
						{
							// if anchoring add wrapper to the listItemChild
							if (!(cellview instanceof Portal) &&
								useAnchors &&
								(((element instanceof Field) && WebAnchoringHelper.needsWrapperDivForAnchoring((Field)element)) || (element instanceof Bean) || ((element instanceof GraphicalComponent) && ComponentFactory.isButton((GraphicalComponent)element))))
							{
								listItemChild = WebAnchoringHelper.getWrapperComponent(comp, (IFormElement)element, listStartY, formBodySize,
									isLeftToRightOrientation);
							}
						}
						updateRuntimeComponentStyleAttributes(comp);
						cellToElement.put(comp, element);
						listItemContainer.add(listItemChild);
						setUpComponent(comp, rec, compColor, compFgColor, compFont, compBorder, visibleRowIndex);
					}
				});
			}
			else
			{
				// we only need to set up again all components in the list item (refresh them)
				Iterator< ? extends Component> children = listItemContainer.iterator();
				while (children.hasNext())
				{
					Component child = CellContainer.getContentsForCell(children.next());
					// re-initialize :) it - apply js_ user changes applied on the column identifier component
					// and other initializations...
					initializeComponent(child, listCellview, cellToElement.get(child));

					//we keep track of the current runtime component style attributes for later use when row Selection occurs 
					//if new row selection -> put the old runtime style on the previously selected row
					updateRuntimeComponentStyleAttributes(child);
					setUpComponent(child, rec, color, fgColor, styleFont, styleBorder, visibleRowIndex);
				}
			}

			//listItem.add(new SimpleAttributeModifier("onfocus", "Wicket.Log.info('ONFOCUS')"));
			enableChildrenInContainer(this, isEnabled());
		}

		private void updateRuntimeComponentStyleAttributes(Component child)
		{
			if (child instanceof IScriptableProvider)
			{
				IScriptable s = ((IScriptableProvider)child).getScriptObject();
				if (s instanceof IRuntimeComponent)
				{
					IRuntimeComponent rtComp = (IRuntimeComponent)s;
					Map<String, String> rtCompStyle = runtimeComponentStyleAttributes.get(rtComp);
					if (rtCompStyle == null)
					{
						rtCompStyle = new HashMap<String, String>();
						runtimeComponentStyleAttributes.put(rtComp, rtCompStyle);
					}
					rtCompStyle.put(RenderableWrapper.PROPERTY_BGCOLOR, rtComp.getBgcolor());
					rtCompStyle.put(RenderableWrapper.PROPERTY_FGCOLOR, rtComp.getFgcolor());
					rtCompStyle.put(RenderableWrapper.PROPERTY_FONT, rtComp.getFont());
					rtCompStyle.put(RenderableWrapper.PROPERTY_BORDER, rtComp.getBorder());
				}
			}
		}

		private void setUpComponent(Component comp, IRecordInternal record, Object compColor, Object fgColor, Object compFont, Object compBorder,
			int visibleRowIndex)
		{
			// set correct tab index
			if (tabIndex < 0)
			{
				TabIndexHelper.setUpTabIndexAttributeModifier(comp, tabIndex);
			}
			else
			{
				if (elementTabIndexes.size() > 0)
				{
					Integer idx = elementTabIndexes.get(cellToElement.get(comp));
					if (idx == null)
					{
						TabIndexHelper.setUpTabIndexAttributeModifier(comp, ISupportWebTabSeq.SKIP);
					}
					else
					{
						TabIndexHelper.setUpTabIndexAttributeModifier(comp, tabIndex + 1 + visibleRowIndex * elementTabIndexes.size() + idx.intValue());
					}
				}
				else
				{
					TabIndexHelper.setUpTabIndexAttributeModifier(comp, tabIndex + 1);
				}
			}

			if (compColor != null)
			{
				setParentBGcolor(comp, compColor);
			}

			WebCellBasedView.this.applyStyleOnComponent(comp, compColor, fgColor, compFont, compBorder);

			if (scriptable.isReadOnly() && validationEnabled && comp instanceof IScriptableProvider &&
				((IScriptableProvider)comp).getScriptObject() instanceof HasRuntimeReadOnly) // if in find mode, the field should not be readonly
			{
				((HasRuntimeReadOnly)((IScriptableProvider)comp).getScriptObject()).setReadOnly(true);
			}

			if (!isEnabled() && comp instanceof IComponent)
			{
				((IComponent)comp).setComponentEnabled(false);
			}
			if (comp instanceof IDisplayRelatedData && record != null)
			{
				((IDisplayRelatedData)comp).setRecord(record, true);
			}

			MarkupContainer parent = comp.getParent();
			if (parent instanceof CellContainer)
			{
				// apply properties that need to be applied to <td> tag instead
				parent.setVisible(comp.isVisible());
			}

			if (compBorder != null)
			{
				IPersist elem = WebCellBasedView.this.cellToElement.get(comp);
				Object colId = WebCellBasedView.this.elementToColumnIdentifierComponent.get(elem);
				final int idx = WebCellBasedView.this.visibleColummIdentifierComponents.indexOf(colId);

				final int[] borderWidth = new int[] { 0, 0 };

				Border cb = ComponentFactoryHelper.createBorder((String)compBorder);
				if (cb != null)
				{
					int defaultLeftPadding;
					int defaultRightPadding;

					switch (elem.getTypeID())
					{
						case IRepository.FIELDS :
							Insets fieldMargin = null;
							if (comp instanceof IFieldComponent)
							{
								fieldMargin = ((IFieldComponent)comp).getMargin();
							}
							defaultLeftPadding = fieldMargin != null ? fieldMargin.left : TemplateGenerator.DEFAULT_FIELD_PADDING.left;
							defaultRightPadding = fieldMargin != null ? fieldMargin.right : TemplateGenerator.DEFAULT_FIELD_PADDING.right;
							break;
						case IRepository.GRAPHICALCOMPONENTS :
							Insets gcMargin = null;
							if (elem instanceof GraphicalComponent)
							{
								gcMargin = ((GraphicalComponent)elem).getMargin();
							}
							defaultLeftPadding = gcMargin != null ? gcMargin.left : TemplateGenerator.DEFAULT_LABEL_PADDING.left;
							defaultRightPadding = gcMargin != null ? gcMargin.right : TemplateGenerator.DEFAULT_LABEL_PADDING.right;
							break;
						default :
							defaultLeftPadding = 0;
							defaultRightPadding = 0;
					}

					Insets borderInsets = ComponentFactoryHelper.getBorderInsetsForNoComponent(cb);
					borderWidth[0] = borderInsets.left + defaultLeftPadding;
					borderWidth[1] = borderInsets.right + defaultRightPadding;
				}
			}
		}


		@Override
		protected IModel<IRecordInternal> getListItemModel(final IModel< ? extends List<IRecordInternal>> listViewModel, final int index)
		{
			List<IRecordInternal> list = listViewModel.getObject();
			if (list != null)
			{
				IRecordInternal r = list.get(index);
				if (r instanceof FindState)
				{
					return new FindStateItemModel(r);
				}
				if (r != null)
				{
					return new FoundsetRecordItemModel(this, r, index);
				}
			}
			return null;
		}

		public ListItem<IRecordInternal> getOrCreateListItem(int index)
		{
			// if there are missing list items in the top of the view, create them now
			if (size() > 1 && index < ((ListItem<IRecordInternal>)get(0)).getIndex())
			{
				int firstIdx = ((ListItem<IRecordInternal>)get(0)).getIndex();

				ArrayList<ListItem<IRecordInternal>> els = new ArrayList<ListItem<IRecordInternal>>();
				for (int i = 0; i < size(); i++)
					els.add((ListItem<IRecordInternal>)get(i));

				removeAll();

				ListItem<IRecordInternal> newItem;
				for (int i = index; i < firstIdx; i++)
				{
					newItem = newItem(i);
					add(newItem);
					onBeginPopulateItem(newItem);
					populateItem(newItem);
				}
				for (ListItem<IRecordInternal> l : els)
					add(l);
			}

			ListItem<IRecordInternal> listItem = index < size() ? (ListItem<IRecordInternal>)get(index) : null;
			if (listItem == null)
			{
				// Create item for index
				listItem = newItem(index);

				// Add list item
				add(listItem);

				// Populate the list item
				onBeginPopulateItem(listItem);
				populateItem(listItem);
			}
			else setUpItem(listItem, false);

			return listItem;
		}
	}

	public class WebCellBasedViewListViewItem extends WebMarkupContainer implements IProviderStylePropertyChanges
	{
		private ListItem<IRecordInternal> listItem;

		public WebCellBasedViewListViewItem(ListItem<IRecordInternal> listItem)
		{
			super("listViewItem"); //$NON-NLS-1$
			setOutputMarkupId(true);
			this.listItem = listItem;
			add(new ServoyAjaxEventBehavior("onclick", "listView") //$NON-NLS-1$ //$NON-NLS-2$
			{
				@Override
				protected void onEvent(AjaxRequestTarget target)
				{
					markSelected();
					IFoundSetInternal modelFs = WebCellBasedViewListViewItem.this.listItem.getModelObject().getParentFoundSet();
					int recIndex = modelFs.getRecordIndex(WebCellBasedViewListViewItem.this.listItem.getModelObject());
					WebCellBasedView.this.setSelectionMadeByCellAction();
					modelFs.setSelectedIndex(recIndex);
					WebEventExecutor.generateResponse(target, getPage());
				}
			});

			add(new StyleAppendingModifier(new Model<String>()
			{
				@Override
				public String getObject()
				{
					boolean isSelectedEl = isSelected();
					WebCellBasedView view = WebCellBasedViewListViewItem.this.listItem.findParent(WebCellBasedView.class);

					Object color = view.getStyleAttributeForListItem(WebCellBasedViewListViewItem.this.listItem, isSelectedEl,
						ISupportRowStyling.ATTRIBUTE.BGCOLOR, false);

					if (cellview instanceof Portal)
					{
						return color != null ? "background-color: " + color : ""; //$NON-NLS-1$ //$NON-NLS-2$
					}
					else
					{
						return color != null
							? "margin-left: 3px;background-color: " + color : (isSelectedEl ? "border-left: 3px solid black" : "margin-left: 3px"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ 
					}
				}
			}));
		}

		@Override
		protected void onRender(MarkupStream markupStream)
		{
			super.onRender(markupStream);
			changesRecorder.setRendered();
		}

		public void markSelected()
		{
			if (!isSelected())
			{
				WebCellBasedViewListView listView = WebCellBasedViewListViewItem.this.listItem.findParent(WebCellBasedViewListView.class);
				if (listView != null)
				{
					WebCellBasedViewListItem listItemObj;
					int listViewSize = listView.size();
					for (int i = 0; i < listViewSize; i++)
					{
						listItemObj = (WebCellBasedViewListItem)listView.get(i);
						if (((WebCellBasedViewListViewItem)listItemObj.getListContainer()).isSelected())
						{
							((WebCellBasedViewListViewItem)listItemObj.getListContainer()).getStylePropertyChanges().setChanged();
						}
					}
				}
				changesRecorder.setChanged();
			}
		}

		public boolean isSelected()
		{
			IFoundSetInternal modelFs = listItem.getModelObject().getParentFoundSet();
			int recIndex = modelFs.getRecordIndex(listItem.getModelObject());
			return recIndex == modelFs.getSelectedIndex();
		}

		private final IStylePropertyChanges changesRecorder = new ChangesRecorder();

		/*
		 * @see com.servoy.j2db.ui.IProviderStylePropertyChanges#getStylePropertyChanges()
		 */
		public IStylePropertyChanges getStylePropertyChanges()
		{
			return changesRecorder;
		}
	}

	private class WebCellBasedViewListItem extends ListItem<IRecordInternal>
	{
		private WebMarkupContainer listContainer;

		public WebCellBasedViewListItem(int index, IModel<IRecordInternal> model)
		{
			super(index, model);
			setOutputMarkupId(true);
		}

		@Override
		public String getMarkupId()
		{
			return WebCellBasedView.this.getMarkupId() + '_' + super.getMarkupId();
		}

		@Override
		protected void onBeforeRender()
		{
			updateComponentsRenderState(null, Arrays.binarySearch(getSelectedIndexes(), getIndex()) >= 0);
			super.onBeforeRender();
			Iterator< ? extends Component> it = iterator();
			while (it.hasNext())
			{
				Component component = it.next();
				if (component instanceof CellContainer)
				{
					Object c = ((CellContainer)component).iterator().next();
					if (c instanceof WebDataComboBox)
					{
						//HACK: update variable if current value is in valuelist (because setValueObject is not called)
						((WebDataComboBox)c).refreshValueInList();
					}
				}
			}
		}

		public void updateComponentsRenderState(AjaxRequestTarget target, boolean isSelected)
		{
			updateComponentsRenderState(target, null, null, null, null, isSelected, true);
		}

		public void updateComponentsRenderState(AjaxRequestTarget target, String bgColor, String fgColor, String compFont, String compBorder, boolean isSelected)
		{
			updateComponentsRenderState(target, bgColor, fgColor, compFont, compBorder, isSelected, false);
		}

		private void updateComponentsRenderState(AjaxRequestTarget target, String bgColor, String fgColor, String compFont, String compBorder,
			boolean isSelected, boolean ignoreStyles)
		{
			Iterator< ? extends Component> it = getListContainer().iterator();
			while (it.hasNext())
			{
				Component component = it.next();
				if (component.isVisibleInHierarchy())
				{
					Object c = component instanceof CellContainer ? ((CellContainer)component).iterator().next() : component;
					if (c instanceof Component)
					{
						Component innerComponent = (Component)c;
						if (!ignoreStyles)
						{
							WebCellBasedView.this.applyStyleOnComponent(innerComponent, bgColor, fgColor, compFont, compBorder);
							if (innerComponent instanceof IScriptableProvider &&
								((IScriptableProvider)innerComponent).getScriptObject() instanceof IRuntimeComponent &&
								((IRuntimeComponent)((IScriptableProvider)innerComponent).getScriptObject()).isTransparent() && bgColor != null)
							{
								// apply the bg color even if transparent
								if (innerComponent instanceof IProviderStylePropertyChanges &&
									((IProviderStylePropertyChanges)innerComponent).getStylePropertyChanges() instanceof IStylePropertyChangesRecorder)
								{
									((IStylePropertyChangesRecorder)(((IProviderStylePropertyChanges)innerComponent).getStylePropertyChanges())).setBgcolor(bgColor);
								}
							}
						}
						boolean innerComponentChanged = innerComponent instanceof IProviderStylePropertyChanges &&
							((IProviderStylePropertyChanges)innerComponent).getStylePropertyChanges().isChanged();
						if (((updateComponentRenderState(c, isSelected)) || (!ignoreStyles && (bgColor != null || fgColor != null || compFont != null || compBorder != null))) &&
							target != null)
						{
							target.addComponent(innerComponent);
							WebEventExecutor.generateDragAttach(innerComponent, target.getHeaderResponse());
							if (!innerComponent.isVisible())
							{
								((IProviderStylePropertyChanges)innerComponent).getStylePropertyChanges().setRendered();
							}
						}
						else if (innerComponentChanged)
						{
							((IProviderStylePropertyChanges)innerComponent).getStylePropertyChanges().setRendered();
						}
					}
				}
			}
		}

		private boolean updateComponentRenderState(Object component, boolean isSelected)
		{
			if (component instanceof IScriptableProvider && component instanceof IProviderStylePropertyChanges)
			{
				IScriptable s = ((IScriptableProvider)component).getScriptObject();
				if (s instanceof ISupportOnRenderCallback && ((ISupportOnRenderCallback)s).getRenderEventExecutor().hasRenderCallback())
				{
					((ISupportOnRenderCallback)s).getRenderEventExecutor().setRenderState(getModelObject(), getIndex(), isSelected);
					((IProviderStylePropertyChanges)component).getStylePropertyChanges().setChanged();
					return true;
				}
			}

			return false;
		}

		public WebMarkupContainer getListContainer()
		{
			if (listContainer == null)
			{
				if (isListViewMode())
				{
					listContainer = new WebCellBasedViewListViewItem(this);

					add(listContainer);
				}
				else listContainer = this;
			}
			return listContainer;
		}
	}

	private class ReorderableListItem extends WebCellBasedViewListItem
	{
		public ReorderableListItem(int index, IModel<IRecordInternal> model)
		{
			super(index, model);
		}

		@Override
		protected void onComponentTagBody(final MarkupStream markupStream, final ComponentTag openTag)
		{
			renderReorderableTagBody(markupStream, openTag);
		}

		/**
		 * Renders markup for the body of a ComponentTag from the current position in the given markup stream. If the open tag passed in does not require a
		 * close tag, nothing happens. Markup is rendered until the closing tag for openTag is reached.
		 * 
		 * @param markupStream The markup stream
		 * @param openTag The open tag
		 */

		private int renderColumnIdx;
		private int headerMarkupStartIdx;
		private List<Component> orderedHeaders;

		private void renderReorderableTagBody(final MarkupStream markupStream, final ComponentTag openTag)
		{
			renderColumnIdx = 0;
			headerMarkupStartIdx = markupStream.getCurrentIndex();
			orderedHeaders = WebCellBasedView.this.getOrderedHeaders();

			if ((markupStream != null) && (markupStream.getCurrentIndex() > 0))
			{
				// If the original tag has been changed from open-close to open-body-close,
				// than historically renderComponentTagBody gets called, but actually
				// it shouldn't do anything since there is no body for that tag.
				ComponentTag origOpenTag = (ComponentTag)markupStream.get(markupStream.getCurrentIndex() - 1);
				if (origOpenTag.isOpenClose())
				{
					return;
				}
			}

			// If the open tag requires a close tag
			boolean render = openTag.requiresCloseTag();
			if (!render)
			{
				// Tags like <p> do not require a close tag, but they may have.
				render = !openTag.hasNoCloseTag();
			}
			if (render)
			{
				// Loop through the markup in this container
				while (markupStream.hasMore() && !markupStream.get().closes(openTag))
				{
					// Render markup element. Doing so must advance the markup
					// stream
					final int index = markupStream.getCurrentIndex();
					_renderNext(markupStream);
					if (index == markupStream.getCurrentIndex())
					{
						markupStream.throwMarkupException("Markup element at index " + index + " failed to advance the markup stream"); //$NON-NLS-1$ //$NON-NLS-2$
					}
				}
			}
		}

		/**
		 * Renders the next element of markup in the given markup stream.
		 * 
		 * @param markupStream The markup stream
		 */
		private final void _renderNext(final MarkupStream markupStream)
		{
			// Get the current markup element
			final MarkupElement element = markupStream.get();

			// If it a tag like <wicket..> or <span wicket:id="..." >
			if ((element instanceof ComponentTag) && !markupStream.atCloseTag())
			{
				// Get element as tag
				final ComponentTag tag = (ComponentTag)element;

				// Get component id
				final String id = tag.getId();

				// Get the component for the id from the given container
				final Component component = get(id);

				// Failed to find it?
				if (component != null)
				{
					if (component instanceof CellContainer || component instanceof IComponent)
					{
						int currentIdx = markupStream.getCurrentIndex();
						renderColumnCell(renderColumnIdx, markupStream);
						renderColumnIdx++;
						markupStream.setCurrentIndex(currentIdx);
						markupStream.skipComponent();
					}
				}
				else
				{
					// 2rd try: Components like Border and Panel might implement
					// the ComponentResolver interface as well.
					MarkupContainer container = this;
					while (container != null)
					{
						if (container instanceof IComponentResolver)
						{
							if (((IComponentResolver)container).resolve(this, markupStream, tag))
							{
								return;
							}
						}

						container = container.findParent(MarkupContainer.class);
					}

					// 3rd try: Try application's component resolvers
					for (IComponentResolver resolver : getApplication().getPageSettings().getComponentResolvers())
					{
						if (resolver.resolve(this, markupStream, tag))
						{
							return;
						}
					}

					if (tag instanceof WicketTag)
					{
						if (((WicketTag)tag).isChildTag())
						{
							markupStream.throwMarkupException("Found " + tag.toString() + " but no <wicket:extend>"); //$NON-NLS-1$ //$NON-NLS-2$
						}
						else
						{
							markupStream.throwMarkupException("Failed to handle: " + tag.toString()); //$NON-NLS-1$
						}
					}

					// No one was able to handle the component id
					markupStream.throwMarkupException("Unable to find component with id '" + id + "' in " + this + ". This means that you declared wicket:id=" + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ 
						id + " in your markup, but that you either did not add the " + "component to your page at all, or that the hierarchy does not match."); //$NON-NLS-1$ //$NON-NLS-2$
				}
			}
			else
			{
				getResponse().write(element.toCharSequence());
				markupStream.next();
			}
		}

		private void renderColumnCell(int columnIdx, final MarkupStream markupStream)
		{
			Component header = orderedHeaders.get(columnIdx);

			markupStream.setCurrentIndex(headerMarkupStartIdx);
			boolean found = false;
			MarkupElement element;

			while (!found)
			{
				element = markupStream.next();
				if (element == null) throw new RuntimeException("can't find the element for the header componet: " + header); //$NON-NLS-1$
				if ((element instanceof ComponentTag) && !markupStream.atCloseTag())
				{
					// Get element as tag
					final ComponentTag tag = (ComponentTag)element;

					// Get component id
					final String id = tag.getId();

					// Get the component for the id from the given container
					final Component component = get(id);

					// Failed to find it?
					if (component != null)
					{
						if (component instanceof CellContainer || component instanceof IComponent)
						{
							if (component.getId().startsWith(header.getId()))
							{
								if (component instanceof CellContainer)
								{
									Object c = ((CellContainer)component).iterator().next();
									if (c instanceof IProviderStylePropertyChanges)
									{
										// ignore location changes
										Properties prop = ((IProviderStylePropertyChanges)c).getStylePropertyChanges().getChanges();
										prop.remove("left"); //$NON-NLS-1$
										prop.remove("top"); //$NON-NLS-1$
									}
								}

								component.render(markupStream);
								found = true;
							}
						}
					}
				}
			}
		}
	}

	public WebCellBasedView(final String id, final IApplication application, RuntimePortal scriptable, final Form form, final AbstractBase cellview,
		final IDataProviderLookup dataProviderLookup, final IScriptExecuter el, boolean addHeaders, final int startY, final int endY, final int sizeHint,
		int viewType)
	{
		super(id);
		this.application = application;
		this.cellview = cellview;
		this.fc = el.getFormController();
		this.addHeaders = addHeaders;
		this.startY = startY;
		this.endY = endY;
		this.formDesignHeight = form.getSize().height;
		this.sizeHint = sizeHint;
		this.viewType = viewType;
		this.isListViewMode = viewType == IForm.LIST_VIEW || viewType == FormController.LOCKED_LIST_VIEW;

		this.bodyWidthHint = form.getWidth();

		useAJAX = Utils.getAsBoolean(application.getRuntimeProperties().get("useAJAX")); //$NON-NLS-1$
		useAnchors = Utils.getAsBoolean(application.getRuntimeProperties().get("enableAnchors")); //$NON-NLS-1$

		setScrollMode(Boolean.TRUE.equals(application.getClientProperty(IApplication.TABLEVIEW_WC_DEFAULT_SCROLLABLE)));
		isKeepLoadedRowsInScrollMode = Boolean.TRUE.equals(application.getClientProperty(IApplication.TABLEVIEW_WC_SCROLLABLE_KEEP_LOADED_ROWS));

		setOutputMarkupPlaceholderTag(true);

		dataRendererOnRenderWrapper = new DataRendererOnRenderWrapper(this);

		loadingInfo = new Label("info", "Loading ..."); //$NON-NLS-1$
		loadingInfo.setVisible(false);
		add(loadingInfo);

		if (!useAJAX) bodyHeightHint = sizeHint;

		String orientation = OrientationApplier.getHTMLContainerOrientation(application.getLocale(), application.getSolution().getTextOrientation());
		isLeftToRightOrientation = !OrientationApplier.RTL.equalsIgnoreCase(orientation);

		int tFormHeight = 0;
		Iterator<Part> partIte = form.getParts();
		while (partIte.hasNext())
		{
			Part p = partIte.next();
			if (p.getPartType() == Part.BODY)
			{
				tFormHeight = p.getHeight() - startY;
				break;
			}
		}
		formBodySize = new Dimension(form.getWidth(), tFormHeight);


		ChangesRecorder jsChangeRecorder = new ChangesRecorder(null, null)
		{
			@Override
			public boolean isChanged()
			{
				boolean retval = false;
				if (super.isChanged())
				{
					retval = true;
					//TODO: change this; we should not do this, but it is not re-rendered otherwise
					return retval;
				}

				if (!retval)
				{
					Iterator<Component> iterator = elementToColumnIdentifierComponent.values().iterator();
					while (iterator.hasNext())
					{
						Component object = iterator.next();
						if (object instanceof IProviderStylePropertyChanges)
						{
							if (((IProviderStylePropertyChanges)object).getStylePropertyChanges().isChanged())
							{
								retval = true;
								break;
							}
						}
					}
				}
				if (retval)
				{
					MainPage page = (MainPage)getPage();
					page.getPageContributor().addTableToRender(WebCellBasedView.this);
					setRendered();
				}
				return false;
			}

			@Override
			public void setRendered()
			{
				super.setRendered();
				Iterator<Component> iterator = elementToColumnIdentifierComponent.values().iterator();
				while (iterator.hasNext())
				{
					Component comp = iterator.next();
					if (comp instanceof IProviderStylePropertyChanges)
					{
						((IProviderStylePropertyChanges)comp).getStylePropertyChanges().setRendered();
					}
				}
			}
		};
		this.scriptable = scriptable;
		((ChangesRecorder)scriptable.getChangesRecorder()).setAdditionalChangesRecorder(jsChangeRecorder);

		add(TooltipAttributeModifier.INSTANCE);

		final int scrollbars = (cellview instanceof ISupportScrollbars) ? ((ISupportScrollbars)cellview).getScrollbars() : 0;
		add(new StyleAppendingModifier(new Model<String>()
		{
			private static final long serialVersionUID = 1L;

			@Override
			public String getObject()
			{
				if (isScrollMode() && currentData != null && currentData.getSize() > 0) return "overflow-x: hidden; overflow-y: hidden;"; //$NON-NLS-1$
				if (cellview instanceof Portal)
				{
					return scrollBarDefinitionToOverflowAttribute(scrollbars);
				}
				if (findParent(IWebFormContainer.class) != null)
				{
					return ""; //$NON-NLS-1$
				}
				return "overflow: auto;"; //$NON-NLS-1$
			}
		}));
		if (cellview instanceof BaseComponent)
		{
			ComponentFactory.applyBasicComponentProperties(application, this, (BaseComponent)cellview,
				ComponentFactory.getStyleForBasicComponent(application, cellview, form));
		}

		boolean sortable = true;
		String initialSortString = null;
		int onRenderMethodID = 0;
		AbstractBase onRenderPersist = null;
		if (cellview instanceof Portal)
		{
			Portal p = (Portal)cellview;
			isListViewMode = p.getMultiLine();

			setRowBGColorScript(p.getRowBGColorCalculation(), p.getInstanceMethodArguments("rowBGColorCalculation")); //$NON-NLS-1$
			sortable = p.getSortable();
			initialSortString = p.getInitialSort();
			onRenderMethodID = p.getOnRenderMethodID();
			onRenderPersist = p;

			int portalAnchors = p.getAnchors();
			isAnchored = (((portalAnchors & IAnchorConstants.NORTH) > 0) && ((portalAnchors & IAnchorConstants.SOUTH) > 0)) ||
				(((portalAnchors & IAnchorConstants.EAST) > 0) && ((portalAnchors & IAnchorConstants.WEST) > 0));
		}
		else if (cellview instanceof Form)
		{
			initialSortString = form.getInitialSort();
			onRenderMethodID = form.getOnRenderMethodID();
			onRenderPersist = form;
			isAnchored = true;
		}

		if (onRenderMethodID > 0)
		{
			dataRendererOnRenderWrapper.getRenderEventExecutor().setRenderCallback(Integer.toString(onRenderMethodID),
				Utils.parseJSExpressions(onRenderPersist.getInstanceMethodArguments("onRenderMethodID")));
			dataRendererOnRenderWrapper.getRenderEventExecutor().setRenderScriptExecuter(fc != null ? fc.getScriptExecuter() : null);
		}

		initDragNDrop(fc, startY);

		if (sortable)
		{
			if (initialSortString != null)
			{
				StringTokenizer tokByComma = new StringTokenizer(initialSortString, ","); //$NON-NLS-1$
				while (tokByComma.hasMoreTokens())
				{
					String initialSortFirstToken = tokByComma.nextToken();
					StringTokenizer tokBySpace = new StringTokenizer(initialSortFirstToken);
					if (tokBySpace.hasMoreTokens())
					{
						String initialSortColumnName = tokBySpace.nextToken();

						if (tokBySpace.hasMoreTokens())
						{
							String sortDir = tokBySpace.nextToken();
							boolean initialSortAsc = true;
							if (sortDir.equalsIgnoreCase("DESC")) initialSortAsc = false; //$NON-NLS-1$
							initialSortColumnNames.put(initialSortColumnName, new Boolean(initialSortAsc));
						}
					}
				}
			}
			// If no initial sort was specified, then default will be the first PK column.
			if (initialSortColumnNames.size() == 0)
			{
				try
				{
					String dataSource = null;
					if (cellview instanceof Portal)
					{
						Portal p = (Portal)cellview;
						String relation = p.getRelationName();
						int lastDot = relation.lastIndexOf("."); //$NON-NLS-1$
						if (lastDot >= 0)
						{
							relation = relation.substring(lastDot + 1);
						}
						Relation rel = application.getFlattenedSolution().getRelation(relation);
						if (rel != null)
						{
							dataSource = rel.getForeignDataSource();
						}
					}
					else
					{
						dataSource = form.getDataSource();
					}
					if (dataSource != null)
					{
						Iterator<String> pkColumnNames = application.getFoundSetManager().getTable(dataSource).getRowIdentColumnNames();
						while (pkColumnNames.hasNext())
						{
							initialSortColumnNames.put(pkColumnNames.next(), Boolean.TRUE);
						}
					}
				}
				catch (RepositoryException e)
				{
					// We just don't set the initial sort to the PK.
					Debug.log("Failed to get PK columns for table.", e); //$NON-NLS-1$
				}
			}
		}

		maxHeight = 0;
		try
		{
			if (isListViewMode() && !(cellview instanceof Portal))
			{
				Iterator<Part> pIte = form.getParts();
				while (pIte.hasNext())
				{
					Part p = pIte.next();
					if (p.getPartType() == Part.BODY)
					{
						maxHeight = p.getHeight();
						break;
					}
				}
			}
			else
			{
				int minElY = 0;
				boolean isMinElYSet = false;
				int height;
				Iterator<IPersist> components = cellview.getAllObjects(PositionComparator.XY_PERSIST_COMPARATOR);
				while (components.hasNext())
				{
					IPersist element = components.next();
					if (element instanceof Field || element instanceof GraphicalComponent)
					{
						if (element instanceof GraphicalComponent && ((GraphicalComponent)element).getLabelFor() != null)
						{
							labelsFor.put(((GraphicalComponent)element).getLabelFor(), element);
							continue;
						}
						Point l = ((IFormElement)element).getLocation();
						if (l == null)
						{
							continue;// unknown where to add
						}
						if (l.y >= startY && l.y < endY)
						{

							if (isListViewMode())
							{
								height = l.y + ((IFormElement)element).getSize().height;
								if (!isMinElYSet || minElY > l.y)
								{
									minElY = l.y;
									isMinElYSet = true;
								}
							}
							else
							{
								height = ((IFormElement)element).getSize().height;
							}
							if (height > maxHeight) maxHeight = height;
						}
					}
				}
				maxHeight = maxHeight - minElY;
			}
			if (maxHeight == 0) maxHeight = 20;
		}
		catch (Exception ex1)
		{
			Debug.error("Error getting max size out of components", ex1); //$NON-NLS-1$
		}

		// Add the table
		tableContainerBody = new WebMarkupContainer("rowsContainerBody"); //$NON-NLS-1$ 
		tableContainerBody.setOutputMarkupId(true);


		table = new WebCellBasedViewListView("rows", data, 1, cellview, //$NON-NLS-1$
			dataProviderLookup, el, startY, endY, form);
		table.setReuseItems(true);


		tableContainerBody.add(table);
		add(tableContainerBody);

		final LinkedHashMap<String, IDataAdapter> dataadapters = new LinkedHashMap<String, IDataAdapter>();
		final SortedList<IPersist> columnTabSequence = new SortedList<IPersist>(TabSeqComparator.INSTANCE); // in fact ISupportTabSeq persists
		createComponents(application, form, cellview, dataProviderLookup, el, startY, endY, new ItemAdd()
		{
			public void add(IPersist element, Component comp)
			{

				if (element instanceof IFormElement && comp instanceof IComponent)
				{
					((IComponent)comp).setLocation(((IFormElement)element).getLocation());
					((IComponent)comp).setSize(((IFormElement)element).getSize());
				}

				elementToColumnIdentifierComponent.put(element, comp);
				if (cellview instanceof Form && element instanceof ISupportTabSeq && ((ISupportTabSeq)element).getTabSeq() >= 0)
				{
					columnTabSequence.add(element);
				}
				if (comp instanceof IDisplayData)
				{
					String dataprovider = ((IDisplayData)comp).getDataProviderID();

					WebCellAdapter previous = (WebCellAdapter)dataadapters.get(dataprovider);
					if (previous == null)
					{
						WebCellAdapter wca = new WebCellAdapter(dataprovider, WebCellBasedView.this);
						dataadapters.put(dataprovider, wca);
					}
					if (dataprovider != null)
					{
						if (initialSortColumnNames.containsKey(dataprovider)) initialSortedColumns.put(comp.getId(), initialSortColumnNames.get(dataprovider));
					}
				}
			}
		});
		for (int i = columnTabSequence.size() - 1; i >= 0; i--)
		{
			elementTabIndexes.put(columnTabSequence.get(i), Integer.valueOf(i));
		}

		// Add the (sortable) header (and define how to sort the different columns)
		if (addHeaders)
		{
			// elementToColumnHeader will be filled up by SortableCellViewHeaders when components in it are resolved
			headers = new SortableCellViewHeaders(form, this, "header", table, cellview, application, initialSortedColumns, new IHeaders() //$NON-NLS-1$
				{

					public void registerHeader(IPersist matchingElement, Component headerComponent)
					{
						SortableCellViewHeader sortableHeader = (SortableCellViewHeader)headerComponent;
						// set headerComponent width
						Component columnIdentifier = WebCellBasedView.this.elementToColumnIdentifierComponent.get(matchingElement);

						if (columnIdentifier instanceof IProviderStylePropertyChanges)
						{
							String width = (String)((IProviderStylePropertyChanges)columnIdentifier).getStylePropertyChanges().getChanges().get("offsetWidth"); //$NON-NLS-1$
							if (width != null)
							{
								sortableHeader.setWidth(Integer.parseInt(width.substring(0, width.length() - 2)));
							}
							else if (matchingElement instanceof BaseComponent) sortableHeader.setWidth(((BaseComponent)matchingElement).getSize().width);
						}
						sortableHeader.setTabSequenceIndex(tabIndex);
						sortableHeader.setScriptExecuter(el);
						sortableHeader.setResizeClass(columnIdentifier.getId());
						WebCellBasedView.this.registerHeader(matchingElement, headerComponent);
					}
				});
			add(headers);
		}

		// Add a table navigator
		if (useAJAX)
		{
			add(pagingNavigator = new ServoyAjaxPagingNavigator("navigator", table)); //$NON-NLS-1$
			add(tableResizeBehavior = new ServoyTableResizeBehavior(startY, endY, cellview));
			add(new OddEvenSelectedBehavior());
		}
		else
		{
			add(pagingNavigator = new ServoySubmitPagingNavigator("navigator", table)); //$NON-NLS-1$
		}

		//hide all further records (and navigator) if explicitly told that there should be no vertical scrollbar 
		showPageNavigator = !((scrollbars & ISupportScrollbars.VERTICAL_SCROLLBAR_NEVER) == ISupportScrollbars.VERTICAL_SCROLLBAR_NEVER);

		try
		{
			if (cellview instanceof Portal)
			{
				relationName = ((Portal)cellview).getRelationName();
				Relation[] rels = application.getFlattenedSolution().getRelationSequence(((Portal)cellview).getRelationName());

				if (rels != null)
				{
					Relation r = rels[rels.length - 1];
					if (r != null)
					{
						defaultSort = ((FoundSetManager)application.getFoundSetManager()).getSortColumns(
							application.getFoundSetManager().getTable(r.getForeignDataSource()), ((Portal)cellview).getInitialSort());
					}
				}
			}
			else
			{
				defaultSort = ((FoundSetManager)application.getFoundSetManager()).getSortColumns(((Form)cellview).getDataSource(),
					((Form)cellview).getInitialSort());
			}
		}
		catch (RepositoryException e)
		{
			Debug.error(e);
			defaultSort = new ArrayList<SortColumn>(1);
		}

		try
		{
			dal = new DataAdapterList(application, dataProviderLookup, elementToColumnIdentifierComponent, el.getFormController(), dataadapters, null);
		}
		catch (RepositoryException ex)
		{
			Debug.error(ex);
		}

		table.setPageabeMode(!isScrollMode());
		if (isScrollMode())
		{
			tableContainerBody.add(new StyleAppendingModifier(new Model<String>()
			{
				private static final long serialVersionUID = 1L;

				@Override
				public String getObject()
				{
					return scrollBarDefinitionToOverflowAttribute(scrollbars) +
						"position: absolute; left: 0px; right: 0px; bottom: 0px; border-spacing: 0px; -webkit-overflow-scrolling: touch; display: none;"; //$NON-NLS-1$
				}
			}));
			tableContainerBody.add(new SimpleAttributeModifier("class", "rowsContainerBody"));
			tableContainerBody.add(scrollBehavior = new ScrollBehavior("onscroll")); //$NON-NLS-1$
		}

		add(new StyleAppendingModifier(new Model<String>()
		{
			private static final long serialVersionUID = 1L;

			@Override
			public String getObject()
			{
				WebForm container = findParent(WebForm.class);
				if (container != null && container.getBorder() instanceof TitledBorder)
				{
					int offset = ComponentFactoryHelper.getTitledBorderHeight(container.getBorder());
					return "top: " + offset + "px;";
				}
				return ""; //$NON-NLS-1$
			}
		})
		{
			@Override
			public boolean isEnabled(Component component)
			{
				WebForm container = component.findParent(WebForm.class);
				if (container != null && container.getBorder() instanceof TitledBorder)
				{
					return super.isEnabled(component);
				}
				return false;
			}
		});
	}

	private static String scrollBarDefinitionToOverflowAttribute(int scrollbarDefinition)
	{
		String overflow = "";
		if ((scrollbarDefinition & ISupportScrollbars.HORIZONTAL_SCROLLBAR_NEVER) == ISupportScrollbars.HORIZONTAL_SCROLLBAR_NEVER)
		{
			overflow += "overflow-x: hidden;"; //$NON-NLS-1$
		}
		else if ((scrollbarDefinition & ISupportScrollbars.HORIZONTAL_SCROLLBAR_ALWAYS) == ISupportScrollbars.HORIZONTAL_SCROLLBAR_ALWAYS)
		{
			overflow += "overflow-x: scroll;"; //$NON-NLS-1$
		}
		else
		{
			overflow += "overflow-x: auto;"; //$NON-NLS-1$
		}
		if ((scrollbarDefinition & ISupportScrollbars.VERTICAL_SCROLLBAR_NEVER) == ISupportScrollbars.VERTICAL_SCROLLBAR_NEVER)
		{
			overflow += "overflow-y: hidden;"; //$NON-NLS-1$
		}
		else if ((scrollbarDefinition & ISupportScrollbars.VERTICAL_SCROLLBAR_ALWAYS) == ISupportScrollbars.VERTICAL_SCROLLBAR_ALWAYS)
		{
			overflow += "overflow-y: scroll;"; //$NON-NLS-1$
		}
		else
		{
			overflow += "overflow-y: auto;"; //$NON-NLS-1$
		}

		return overflow;
	}

	public final RuntimePortal getScriptObject()
	{
		return scriptable;
	}

	public void setTabSequenceIndex(int tabIndex)
	{
		this.tabIndex = tabIndex;
		((ISupportWebTabSeq)pagingNavigator).setTabSequenceIndex(tabIndex + WebDataRendererFactory.MAXIMUM_TAB_INDEXES_ON_TABLEVIEW - 1);
	}

	private final ArrayList<String> orderedHeaderIds = new ArrayList<String>();

	public ArrayList<Component> getOrderedHeaders()
	{
		ArrayList<Component> orderedHeaders = new ArrayList<Component>();
		List<PersistColumnIdentifierComponent> orderedPersistColumnIdentifierComponent = getOrderedPersistColumnIdentifierComponents();
		orderedHeaderIds.clear();

		Component c;
		for (PersistColumnIdentifierComponent pc : orderedPersistColumnIdentifierComponent)
		{
			c = elementToColumnHeader.get(pc.getPersist());
			if (c == null) orderedHeaders.add(null);
			else orderedHeaders.add(elementToColumnHeader.get(pc.getPersist()));
			orderedHeaderIds.add(pc.getComponent().getId());
		}

		return orderedHeaders;
	}

	public ArrayList<String> getOrderedHeaderIds()
	{
		return orderedHeaderIds;
	}

	private Component getIdentifierComponent(Component headerColumn)
	{
		for (Map.Entry<IPersist, Component> entry : elementToColumnHeader.entrySet())
		{
			if (entry.getValue() == headerColumn)
			{
				return elementToColumnIdentifierComponent.get(entry.getKey());
			}
		}
		return null;
	}

	public void moveColumn(SortableCellViewHeader headerColumn, int x, AjaxRequestTarget ajaxRequestTarget)
	{
		if (headerColumn.getWidth() / 2 < Math.abs(x)) // we have a move
		{
			List<Component> orderedHeaders = getOrderedHeaders();

			SortableCellViewHeader nextHeader;
			int movedHeaderIdx = orderedHeaders.indexOf(headerColumn);
			int nextHeaderIdx;
			int moveToHeaderIdx = -1;

			if (x > 0) // moved to right
			{
				nextHeaderIdx = movedHeaderIdx + 1;
				int offset = (x - headerColumn.getWidth() / 2);
				while (nextHeaderIdx < orderedHeaders.size())
				{
					nextHeader = (SortableCellViewHeader)orderedHeaders.get(nextHeaderIdx);
					if (nextHeader.isUnmovable()) return;
					if (offset < nextHeader.getWidth() || nextHeaderIdx == orderedHeaders.size() - 1) // over next element or end
					{
						if (offset < nextHeader.getWidth() / 2) // move before
						{
							moveToHeaderIdx = nextHeaderIdx - 1;
						}
						else
						// move after
						{
							if (nextHeaderIdx + 1 < orderedHeaders.size())
							{
								moveToHeaderIdx = nextHeaderIdx;
							}
							else
							{
								moveToHeaderIdx = orderedHeaders.size() - 1;
							}
						}
						break;
					}
					else
					{
						offset -= nextHeader.getWidth();
						nextHeaderIdx++;
					}
				}
			}
			else
			// moved left
			{
				nextHeaderIdx = movedHeaderIdx - 1;
				int offset = (Math.abs(x) - headerColumn.getWidth() / 2);
				while (nextHeaderIdx > -1)
				{
					nextHeader = (SortableCellViewHeader)orderedHeaders.get(nextHeaderIdx);
					if (nextHeader.isUnmovable()) return;
					if (offset < nextHeader.getWidth() || nextHeaderIdx == 0) // over next element or end
					{
						if (offset < nextHeader.getWidth() / 2) // move after
						{
							moveToHeaderIdx = nextHeaderIdx + 1;
						}
						else
						// move before
						{
							moveToHeaderIdx = nextHeaderIdx;
						}
						break;
					}
					else
					{
						offset -= nextHeader.getWidth();
						nextHeaderIdx--;
					}
				}
			}

			if (moveToHeaderIdx == -1 || movedHeaderIdx == moveToHeaderIdx)
			{
				return;
			}

			List<Component> headerColumnsBeforeDrag = orderedHeaders;

			moveColumn(orderedHeaders, movedHeaderIdx, moveToHeaderIdx);

			keepGroupOrder(headerColumn, headerColumnsBeforeDrag);


			if (headers != null)
			{
				this.headers.getStylePropertyChanges().setChanged();
			}
			this.getStylePropertyChanges().setChanged();
			WebEventExecutor.generateResponse(ajaxRequestTarget, getPage());
		}
	}

	private void moveColumn(List<Component> orderedHeaders, int columnIndex, int newIndex)
	{
		List<Component> orderedHeaderCopy = new ArrayList<Component>(orderedHeaders);
		orderedHeaderCopy.add(newIndex, orderedHeaderCopy.remove(columnIndex));

		updateXLocationForColumns(orderedHeaderCopy);
	}

	private void updateXLocationForColumns(List<Component> orderedHeaderCopy)
	{
		int startX = 0;
		for (Component c : orderedHeaderCopy)
		{
			for (IPersist p : elementToColumnHeader.keySet())
			{
				if (elementToColumnHeader.get(p).equals(c))
				{
					Component columnIdentifierComponent = elementToColumnIdentifierComponent.get(p);
					Point oldLocation = ((IComponent)columnIdentifierComponent).getLocation();
					if (oldLocation == null)
					{
						oldLocation = ((ISupportBounds)p).getLocation();
					}
					((IComponent)columnIdentifierComponent).setLocation(new Point(startX, (int)oldLocation.getY()));
					startX += ((IComponent)columnIdentifierComponent).getSize().width;
				}
			}
		}
	}

	private void keepGroupOrder(SortableCellViewHeader headerColumn, List<Component> headerColumnsBeforeDrag)
	{
		// check for groups, put the elements in the same order back together

		// first the columns left from the dragged column
		int offset = -1;
		while (moveColumnInSameGroup(headerColumn, headerColumnsBeforeDrag, offset))
		{
			offset--;
		}
		// then the columns right from the dragged column
		offset = 1;
		while (moveColumnInSameGroup(headerColumn, headerColumnsBeforeDrag, offset))
		{
			offset++;
		}
		// check if a column is breaking up a group
		for (Component hc : headerColumnsBeforeDrag)
		{
			moveColumnInSameGroup(hc, headerColumnsBeforeDrag, 1);
		}
	}

	private boolean moveColumnInSameGroup(Component headerColumn, List<Component> headerColumnsBeforeDrag, int offset)
	{
		String groupId = (String)dal.getFormController().getComponentProperty(getIdentifierComponent(headerColumn), ComponentFactory.GROUPID_COMPONENT_PROPERTY);
		if (groupId == null)
		{
			return false;
		}

		// find the columns offsetted to this column in the original columns
		int orgIindex = headerColumnsBeforeDrag.indexOf(headerColumn);
		if (orgIindex == -1)
		{
			return false; // strange, should not happen
		}
		if ((offset < 0 && orgIindex + offset < 0) || (offset > 0 && orgIindex + offset >= headerColumnsBeforeDrag.size()))
		{
			// no more columns in original set
			return false;
		}

		List<Component> orderedHeaders = getOrderedHeaders();

		int currIndex = orderedHeaders.indexOf(headerColumn);
		if (currIndex == -1)
		{
			return false; // strange, should not happen
		}

		Component column2 = headerColumnsBeforeDrag.get(orgIindex + offset);
		if (!groupId.equals(dal.getFormController().getComponentProperty(getIdentifierComponent(column2), ComponentFactory.GROUPID_COMPONENT_PROPERTY)))
		{
			// original column at offset is not part of the same group
			return false;
		}

		int currIndex2 = orderedHeaders.indexOf(column2);
		if (currIndex2 == -1)
		{
			return false; // strange, should not happen
		}

		// move this one next to the prev
		if (offset < 0)
		{
			if (currIndex2 > currIndex)
			{
				if (currIndex2 != currIndex + offset + 1)
				{
					moveColumn(orderedHeaders, currIndex2, currIndex + offset + 1);
				}
			}
			else
			{
				if (currIndex2 != currIndex + offset)
				{
					moveColumn(orderedHeaders, currIndex2, currIndex + offset);
				}
			}
		}
		else
		{
			if (currIndex2 < currIndex)
			{
				if (currIndex2 != currIndex + offset - 1)
				{
					moveColumn(orderedHeaders, currIndex2, currIndex + offset - 1);
				}
			}
			else
			{
				if (currIndex2 != currIndex + offset)
				{
					moveColumn(orderedHeaders, currIndex2, currIndex + offset);
				}
			}
		}

		// moved
		return true;
	}

	public void resizeColumn(SortableCellViewHeader headerColumn, int x)
	{
		int totalWidthToStretch = 0;
		IPersist resizedPersist = null;
		for (IPersist p : elementToColumnHeader.keySet())
		{
			Component c = elementToColumnIdentifierComponent.get(p);
			if (c instanceof IScriptableProvider && ((IScriptableProvider)c).getScriptObject() instanceof IRuntimeComponent)
			{
				IRuntimeComponent ic = (IRuntimeComponent)((IScriptableProvider)c).getScriptObject();
				if (elementToColumnHeader.get(p).equals(headerColumn))
				{
					int height = ic.getHeight();
					Iterator<Component> alreadyAddedComponents = cellToElement.keySet().iterator();
					if (alreadyAddedComponents.hasNext())
					{
						Component firstAddedComponent = alreadyAddedComponents.next();
						if ((firstAddedComponent instanceof IComponent)) height = ((IComponent)firstAddedComponent).getSize().height;
					}
					ic.setSize(ic.getWidth() + x, height);
					if (ic instanceof IProviderStylePropertyChanges)
					{
						resizedComponent = c;
						((IProviderStylePropertyChanges)ic).getStylePropertyChanges().setRendered(); // avoid the tableview to render because of this change
					}
					resizedPersist = p;


					// set width for all cell of the column
					Iterator<Entry<Component, IPersist>> cellToElementIte = cellToElement.entrySet().iterator();
					Entry<Component, IPersist> cellToElementEntry;
					Component cellComponent;
					while (cellToElementIte.hasNext())
					{
						cellToElementEntry = cellToElementIte.next();
						cellComponent = cellToElementEntry.getKey();
						if (p.equals(cellToElementEntry.getValue()) && cellComponent instanceof IScriptableProvider &&
							((IScriptableProvider)cellComponent).getScriptObject() instanceof IRuntimeComponent)
						{
							IRuntimeComponent cellScriptComponent = (IRuntimeComponent)((IScriptableProvider)cellComponent).getScriptObject();
							cellScriptComponent.setSize(cellScriptComponent.getWidth() + x, cellScriptComponent.getHeight());
							if (cellComponent instanceof IProviderStylePropertyChanges)
							{
								((IProviderStylePropertyChanges)cellComponent).getStylePropertyChanges().setRendered(); // avoid the tableview to render because of this change
							}
						}
					}

				}
				else
				{
					totalWidthToStretch += ic.getWidth();
				}
			}
		}
		if (shouldFillAllHorizontalSpace()) distributeExtraSpace(-x, totalWidthToStretch, resizedPersist, false);
		setHeadersWidth();
	}

	// set headers width according to cell's width
	private void setHeadersWidth()
	{
		Iterator<IPersist> columnPersistIte = elementToColumnIdentifierComponent.keySet().iterator();

		IPersist columnPersist;
		Component columnHeader, columnCell;
		while (columnPersistIte.hasNext())
		{
			columnPersist = columnPersistIte.next();
			columnCell = elementToColumnIdentifierComponent.get(columnPersist);
			columnHeader = elementToColumnHeader.get(columnPersist);
			if (columnCell instanceof IProviderStylePropertyChanges)
			{
				String width = (String)((IProviderStylePropertyChanges)columnCell).getStylePropertyChanges().getChanges().get("offsetWidth"); //$NON-NLS-1$

				if (columnHeader instanceof SortableCellViewHeader)
				{
					SortableCellViewHeader sortableColumnHeader = (SortableCellViewHeader)columnHeader;
					if (width != null) sortableColumnHeader.setWidth(Integer.parseInt(width.substring(0, width.length() - 2)));
					else if (columnPersist instanceof BaseComponent) sortableColumnHeader.setWidth(((BaseComponent)columnPersist).getSize().width);
				}
			}
		}
	}

	private void registerHeader(IPersist matchingElement, Component headerComponent)
	{
		elementToColumnHeader.put(matchingElement, headerComponent);
		updateHeader(headerComponent, elementToColumnIdentifierComponent.get(matchingElement));
	}

	private void updateHeaders()
	{
		Iterator<IPersist> it = elementToColumnHeader.keySet().iterator();

		while (it.hasNext())
		{
			IPersist element = it.next();
			Component columnHeader = elementToColumnHeader.get(element);
			Component columnIdentifier = elementToColumnIdentifierComponent.get(element);

			updateHeader(columnHeader, columnIdentifier);
		}
	}

	private void enableChildrenInContainer(MarkupContainer container, final boolean b)
	{
		container.visitChildren(new IVisitor<Component>()
		{
			public Object component(Component component)
			{
				if (component.isEnabled() != b)
				{
					if (component instanceof IComponent)
					{
						if (b)
						{
							// component may be disabled by scripting, do not enable it
							return CONTINUE_TRAVERSAL;
						}
						((IComponent)component).setComponentEnabled(b);
					}
					else
					{
						component.setEnabled(b);
					}
				}
				return CONTINUE_TRAVERSAL;
			}
		});
	}

	private void updateHeader(Component columnHeader, Component columnIdentifier)
	{
		columnHeader.setVisible(columnIdentifier.isVisible());
		columnHeader.setEnabled(isEnabled());
		if (columnHeader instanceof MarkupContainer) enableChildrenInContainer((MarkupContainer)columnHeader, isEnabled());
	}

	private Component focusRequestingColIdentComponent = null;

	/**
	 * Requests focus for the cell in the web cell view corresponding to the selected record and to the given column identifier component.
	 * 
	 * @param columnIdentifierComponent the Component that identifies a column for java script.
	 */
	public void setColumnThatRequestsFocus(final Component columnIdentifierComponent)
	{
		focusRequestingColIdentComponent = null;

		if (currentData == null) return;

		Component cell = getCellToFocus(columnIdentifierComponent);
		if (cell != null)
		{
			IMainContainer currentContainer = ((FormManager)application.getFormManager()).getCurrentContainer();
			if (currentContainer instanceof MainPage)
			{
				((MainPage)currentContainer).componentToFocus(cell);
			}
			else
			{
				Debug.trace("focus couldnt be set on component " + cell); //$NON-NLS-1$
			}
		}
		else
		{
			focusRequestingColIdentComponent = columnIdentifierComponent;
		}
	}

	/**
	 * @param columnIdentifierComponent
	 * @return
	 */
	private Component getCellToFocus(final Component columnIdentifierComponent)
	{
		Component cell = null;

		// this means that the given column of the cell view wants to be focused =>
		// we must focus the cell component that is part of the currently selected record
		int selectedIndex = currentData.getSelectedIndex();
		if (selectedIndex < 0 && currentData.getSize() > 0)
		{
			selectedIndex = 0;
		}

		if (selectedIndex >= 0)
		{
			// we found a record to use - now we must locate the cell component inside this record
			ListItem<IRecordInternal> li = (ListItem<IRecordInternal>)table.get(Integer.toString(selectedIndex));
			if (li != null)
			{
				Iterator< ? extends Component> cells = li.iterator();
				while (cells.hasNext())
				{
					Component someCell = CellContainer.getContentsForCell(cells.next());
					IPersist element = cellToElement.get(someCell);
					if (element != null && elementToColumnIdentifierComponent.get(element) == columnIdentifierComponent)
					{
						cell = someCell;
						break;
					}
				}
			}

		}
		return cell;
	}

	Map<String, IPersist> labelsFor = new HashMap<String, IPersist>();

	private void createComponents(final IApplication app, final Form form, final AbstractBase view, final IDataProviderLookup dataProviderLookup,
		final IScriptExecuter el, final int viewStartY, final int viewEndY, final ItemAdd output)
	{
		List<IPersist> elements = ComponentFactory.sortElementsOnPositionAndGroup(view.getAllObjectsAsList());
		int startX = 0;
		for (int i = 0; i < elements.size(); i++)
		{
			IPersist element = elements.get(i);
			if (element instanceof Field || element instanceof GraphicalComponent || element instanceof Bean)
			{
				if (!isListViewMode())
				{
					if (element instanceof GraphicalComponent && ((GraphicalComponent)element).getLabelFor() != null)
					{
						labelsFor.put(((GraphicalComponent)element).getLabelFor(), element);
						continue;
					}
				}

				Point l = ((IFormElement)element).getLocation();
				if (l == null)
				{
					continue; // unknown where to add
				}

				if (l.y >= viewStartY && l.y < viewEndY)
				{
					IComponent c = ComponentFactory.createComponent(app, form, element, dataProviderLookup, el, false);

					if (cellview instanceof Portal && c instanceof IScriptableProvider)
					{
						IScriptable s = ((IScriptableProvider)c).getScriptObject();
						if (s instanceof ISupportOnRenderCallback && ((ISupportOnRenderCallback)s).getRenderEventExecutor() != null) ComponentFactoryHelper.addPortalOnRenderCallback(
							(Portal)cellview, ((ISupportOnRenderCallback)s).getRenderEventExecutor(), element, fc != null ? fc.getScriptExecuter() : null);
					}

					initializeComponent((Component)c, view, element);
					output.add(element, (Component)c);

					if (!isListViewMode())
					{
						// reset location.x as defined in this order, elements are ordered by location.x which is modified in drag-n-drop
						Point loc = c.getLocation();
						if (loc != null)
						{
							c.setLocation(new Point(startX, loc.y));
						}

						Dimension csize = c.getSize();
						startX += (csize != null) ? csize.width : ((IFormElement)element).getSize().width;
					}
				}
			}
		}
	}

	private void initializeComponent(final Component c, AbstractBase view, Object element)
	{
		if (view instanceof Portal && c instanceof IDisplayData) // Don't know any other place for this
		{
			String id = ((IDisplayData)c).getDataProviderID();
			if (id != null && !ScopesUtils.isVariableScope(id) && id.startsWith(((Portal)view).getRelationName() + '.'))
			{
				((IDisplayData)c).setDataProviderID(id.substring(((Portal)cellview).getRelationName().length() + 1));
			}
		}
		if (c instanceof WebDataCheckBox)
		{
			((WebDataCheckBox)c).setText(""); //$NON-NLS-1$
		}
		if (element != null)
		{
			// apply to this cell the state of the columnIdentifier IComponent
			PropertyCopy.copyElementProps((IComponent)elementToColumnIdentifierComponent.get(element), (IComponent)c);
		}
		else
		{
			Debug.log("Cannot find the IPersist element for cell " + c.getMarkupId()); //$NON-NLS-1$
		}
		if (c instanceof IDisplayData)
		{
			IDisplayData cdd = (IDisplayData)c;
			if (!(dal != null && dal.getFormScope() != null && cdd.getDataProviderID() != null && dal.getFormScope().get(cdd.getDataProviderID()) != Scriptable.NOT_FOUND)) // skip for form variables
			{
				cdd.setValidationEnabled(validationEnabled);
			}
		}
		else if (c instanceof IDisplayRelatedData)
		{
			((IDisplayRelatedData)c).setValidationEnabled(validationEnabled);
		}
		else if (c instanceof IServoyAwareBean)
		{
			((IServoyAwareBean)c).setValidationEnabled(validationEnabled);
		}

		addClassToCellComponent(c);
		if (c instanceof WebDataCompositeTextField) // the check could be extended against IDelegate<?>
		{
			Object delegate = ((WebDataCompositeTextField)c).getDelegate();
			if (delegate instanceof Component)
			{
				addClassToCellComponent((Component)delegate); // make sure that this class is added accordingly in TemplateGenerator as a style selector containing relevant properties
			}
		}

		if (c instanceof ISupportValueList)
		{
			ISupportValueList idVl = (ISupportValueList)elementToColumnIdentifierComponent.get(element);
			IValueList list;
			if (idVl != null && (list = idVl.getValueList()) != null)
			{
				ValueList valuelist = application.getFlattenedSolution().getValueList(list.getName());
				if (valuelist != null && valuelist.getValueListType() == ValueList.CUSTOM_VALUES)
				{
					((ISupportValueList)c).setValueList(list);
				}
			}
		}
	}

	private void addClassToCellComponent(final Component c)
	{
		Model<String> componentClassModel = new Model<String>()
		{
			@Override
			public String getObject()
			{
				return c.getId();
			}
		};

		c.add(new AttributeModifier("class", true, componentClassModel) //$NON-NLS-1$
		{
			@Override
			protected String newValue(final String currentValue, String replacementValue)
			{
				String currentClass = currentValue == null ? "" : currentValue; //$NON-NLS-1$
				String replacementClass = ""; //$NON-NLS-1$
				if (replacementValue != null)
				{
					replacementClass = replacementValue;

					if (currentClass.equals(replacementClass)) return currentClass.trim();

					// check if already added
					int replacementClassIdx = currentClass.indexOf(replacementClass);

					if ((replacementClassIdx != -1) &&
						(replacementClassIdx == 0 || currentClass.charAt(replacementClassIdx - 1) == ' ') &&
						(replacementClassIdx == currentClass.length() - replacementClass.length() || currentClass.charAt(replacementClassIdx +
							replacementClass.length()) == ' '))
					{
						return currentClass.trim();
					}
				}

				String result = replacementClass + " " + currentClass; //$NON-NLS-1$
				return result.trim();
			}
		});
	}

	/*
	 * Number of updated list items from the last rendering
	 */
	private int nrUpdatedListItems;

	/**
	 * @see javax.swing.event.TableModelListener#tableChanged(javax.swing.event.TableModelEvent)
	 */
	public void tableChanged(TableModelEvent e)
	{
		// If it is one row change, only update/touch that row;
		// If we already have more then the half of the table rows changes, just mark the whole table
		// as changed, as it will be faster on the client the component replace
		if (e.getType() == TableModelEvent.UPDATE && e.getFirstRow() == e.getLastRow() && (nrUpdatedListItems < table.getRowsPerPage() / 2))
		{
			Component component = table.get(Integer.toString(e.getFirstRow()));
			if (component instanceof ListItem)
			{
				((ListItem)component).visitChildren(IProviderStylePropertyChanges.class, new IVisitor<Component>()
				{
					public Object component(Component comp)
					{
						if ((comp instanceof IDisplayData) || !(comp instanceof ILabel))
						{
							// labels/buttons that don't display data are not changed
							((IProviderStylePropertyChanges)comp).getStylePropertyChanges().setChanged();
						}
						return CONTINUE_TRAVERSAL_BUT_DONT_GO_DEEPER;
					}
				});
				nrUpdatedListItems++;

				IModel<IRecordInternal> newModel = table.getListItemModel(table.getModel(), e.getFirstRow());
				IModel oldModel = ((ListItem)component).getModel();
				if (newModel != null && oldModel != null && newModel.getObject() != null && !newModel.getObject().equals(oldModel.getObject()))
				{
					// refresh model if it changed
					((ListItem)component).setModel(newModel);
				}
			}
		}
		else
		{
			if (!isScrollMode() || !(scrollBehavior != null && scrollBehavior.isGettingRows())) getStylePropertyChanges().setChanged();
		}

		// We try to detect when a sort has been done on the foundset, and we update the arrows in the header accordingly.
		// This is just an heuristic for filtering out the sort event from all table changed events that are raised.
		if (currentData != null && e.getColumn() == TableModelEvent.ALL_COLUMNS && e.getFirstRow() == 0 && elementToColumnHeader.size() > 0)
		{
			List<SortColumn> sortCols = currentData.getSortColumns();
			if (sortCols != null && sortCols.size() > 0)
			{
				Map<String, Boolean> sortMap = new HashMap<String, Boolean>();
				for (IPersist persist : elementToColumnHeader.keySet())
				{
					SortableCellViewHeader sortableCellViewHeader = (SortableCellViewHeader)elementToColumnHeader.get(persist);
					sortableCellViewHeader.setResizeImage(R_ARROW_OFF);
				}
				for (SortColumn sc : sortCols)
				{
					for (IPersist persist : elementToColumnHeader.keySet())
					{
						Component comp = elementToColumnIdentifierComponent.get(persist);
						SortableCellViewHeader sortableCellViewHeader = (SortableCellViewHeader)elementToColumnHeader.get(persist);
						if (comp instanceof IDisplayData && ((IDisplayData)comp).getDataProviderID() != null)
						{
							IDisplayData dispComp = (IDisplayData)comp;
							List<String> sortingProviders = null;
							if (dispComp instanceof ISupportValueList && ((ISupportValueList)dispComp).getValueList() != null)
							{
								try
								{
									sortingProviders = DBValueList.getShowDataproviders(((ISupportValueList)dispComp).getValueList().getValueList(),
										(Table)currentData.getTable(), dispComp.getDataProviderID(), currentData.getFoundSetManager());
								}
								catch (RepositoryException ex)
								{
									Debug.error(ex);
								}
							}

							if (sortingProviders == null)
							{
								// no related sort, use sort on dataProviderID instead
								sortingProviders = Collections.singletonList(dispComp.getDataProviderID());
							}

							for (String sortingProvider : sortingProviders)
							{
								SortColumn existingSc;
								try
								{
									existingSc = ((FoundSetManager)currentData.getFoundSetManager()).getSortColumn(currentData.getTable(), sortingProvider);
								}
								catch (RepositoryException ex)
								{
									Debug.error(ex);
									continue;
								}

								if (sc.equalsIgnoreSortorder(existingSc))
								{
									boolean descending = sc.getSortOrder() == SortColumn.DESCENDING;
									sortableCellViewHeader.setResizeImage(descending ? R_ARROW_UP : R_ARROW_DOWN);
									sortMap.put(comp.getMarkupId(), Boolean.valueOf(!descending));
								}
							}
						}
					}
				}
				headers.recordSort(sortMap);
			}
		}

		MainPage mp = table.findParent(MainPage.class);
		if (mp != null) mp.triggerBrowserRequestIfNeeded();
	}

	public IStylePropertyChanges getStylePropertyChanges()
	{
		return scriptable.getChangesRecorder();
	}

	private ArrayList<Component> visibleColummIdentifierComponents;

	private ArrayList<Component> getVisibleColummIdentifierComponents()
	{
		ArrayList<Component> colummIdentifierComponents = new ArrayList<Component>();
		Iterator<Component> columnComponentsIte = elementToColumnIdentifierComponent.values().iterator();
		Component c;
		while (columnComponentsIte.hasNext())
		{
			c = columnComponentsIte.next();
			if (c.isVisible()) colummIdentifierComponents.add(c);
		}
		return colummIdentifierComponents;
	}


	/**
	 * @see wicket.MarkupContainer#onRender(wicket.markup.MarkupStream)
	 */
	@Override
	protected void onRender(MarkupStream markupStream)
	{
		super.onRender(markupStream);
		getStylePropertyChanges().setRendered();
		hasOnRender = hasOnRender();
		nrUpdatedListItems = 0;

		clearSelectionByCellActionFlag();
	}

	@Override
	protected void onBeforeRender()
	{
		IWebFormContainer tabPanel = findParent(IWebFormContainer.class);
		Dimension tabSize = null;
		if (tabPanel instanceof WebTabPanel)
		{
			tabSize = ((WebTabPanel)tabPanel).getTabSize();
		}

		boolean canRenderView = true;

		if (tableResizeBehavior != null && isAnchored)
		{
			if (!getPath().equals(lastRenderedPath))
			{
				bodySizeHintSetFromClient = false;
				tabSize = null;
				lastRenderedPath = getPath();
			}
			// delay rendering table view (that can be big) if we
			// just wait for the size response from the browser
			canRenderView = bodySizeHintSetFromClient || tabSize != null;
			if (!canRenderView)
			{
				// force to get a response from the browser
				bodyHeightHint = -1;
				bodyWidthHint = -1;
			}
			if (headers != null) headers.setVisible(canRenderView);
			table.setVisible(canRenderView);
			pagingNavigator.setVisible(canRenderView);
			loadingInfo.setVisible(!canRenderView);
		}

		if (canRenderView)
		{
			ArrayList<Component> oldVisibleColummIdentifierComponents = visibleColummIdentifierComponents;
			visibleColummIdentifierComponents = getVisibleColummIdentifierComponents();

			if (oldVisibleColummIdentifierComponents != null && !oldVisibleColummIdentifierComponents.equals(visibleColummIdentifierComponents))
			{
				distributeExtraSpace();
			}

			if (tabPanel != null)
			{
				if (tabSize != null)
				{
					bodyHeightHint = (int)tabSize.getHeight();
					bodyHeightHint -= getOtherFormPartsHeight();
				}
			}
			else if (bodyHeightHint == -1)
			{
				bodyHeightHint = ((WebClientInfo)RequestCycle.get().getSession().getClientInfo()).getProperties().getBrowserHeight();
				bodyHeightHint -= getOtherFormPartsHeight();
			}

			if (isCurrentDataChanged)
			{
				if (bodyHeightHint == -1) bodyHeightHint = sizeHint;
				isCurrentDataChanged = false;
			}

			if (bodyHeightHint != -1)
			{
				int oldRowsPerPage = table.getRowsPerPage();

				// if the design height of the BODY part is higher then the actual display area available for the BODY (table/list view)
				// then use the design height; this allows a desired behavior (SVY-2943 - small area to display 1-2 rows + scrollbar for 3-4 more and then paging)
				// you can still use only the available area and then use paging by designing table view forms with low body height
				Pair<Boolean, Pair<Integer, Integer>> rowsCalculation = needsMoreThanOnePage(Math.max(bodyHeightHint, endY - startY));
				maxRowsPerPage = rowsCalculation.getRight().getLeft().intValue();

				if (isScrollMode())
				{
					table.setStartIndex(0);
					table.setViewSize(2 * maxRowsPerPage);
				}
				else
				{
					table.setRowsPerPage(maxRowsPerPage);
				}

				// set headers width according to cell's width
				setHeadersWidth();
				int firstSelectedIndex = 0;
				if (currentData != null)
				{
					firstSelectedIndex = currentData.getSelectedIndex();
				}

				// if rowPerPage changed & the selected was visible, switch to the page so it remain visible
				int currentPage = table.getCurrentPage();
				if (maxRowsPerPage != oldRowsPerPage && currentPage * oldRowsPerPage <= firstSelectedIndex &&
					(currentPage + 1) * oldRowsPerPage > firstSelectedIndex) table.setCurrentPage(firstSelectedIndex < 1 ? 0 : firstSelectedIndex /
					maxRowsPerPage);
			}
			pagingNavigator.setVisible(!isScrollMode() && showPageNavigator && table.getPageCount() > 1);
		}
		selectedIndexes = null;
		updateRowComponentsRenderState(null);
		if (dataRendererOnRenderWrapper.getRenderEventExecutor().hasRenderCallback())
		{
			dataRendererOnRenderWrapper.getRenderEventExecutor().setRenderState(null, -1, false);
			dataRendererOnRenderWrapper.getRenderEventExecutor().fireOnRender(false);
		}
		super.onBeforeRender();
	}

	public Object[] getComponents()
	{
		return elementToColumnIdentifierComponent.values().toArray();
	}

	public Object[] getHeaderComponents()
	{
		return elementToColumnHeader.values().toArray();
	}

	public ListView<IRecordInternal> getTable()
	{
		return this.table;
	}

	public void destroy()
	{
		if (dal != null) dal.destroy();
		if (currentData instanceof ISwingFoundSet)
		{
			((ISwingFoundSet)currentData).removeTableModelListener(this);
			((ISwingFoundSet)currentData).getSelectionModel().removeListSelectionListener(this);
		}
	}

	public String getSelectedRelationName()
	{
		return relationName;
	}

	public String[] getAllRelationNames()
	{
		String selectedRelation = getSelectedRelationName();
		if (selectedRelation == null)
		{
			return new String[0];
		}
		else
		{
			return new String[] { selectedRelation };
		}
	}

	public List<SortColumn> getDefaultSort()
	{
		if (currentData != null && defaultSort.size() == 0)
		{
			defaultSort = currentData.getSortColumns();
		}
		return defaultSort;
	}

	public void notifyVisible(boolean b, List<Runnable> invokeLaterRunnables)
	{
		dal.notifyVisible(b, invokeLaterRunnables);
	}

	public void setRecord(IRecordInternal state, boolean stopEditing)
	{
		if (stopEditing)
		{
			stopUIEditing(true);
		}
		setModel(state == null ? null : state.getRelatedFoundSet(relationName, getDefaultSort()));
	}

	private IFoundSetInternal currentData;
	private boolean isCurrentDataChanged;
	private int[] selectedIndexes;
	private String bgColorScript;
	private List<Object> bgColorArgs;

	private boolean isReadOnly;

	private boolean validationEnabled = true;

	public void setModel(IFoundSetInternal fs)
	{
		if (currentData == fs) return;// if is same changes are seen by model listener

		if (currentData instanceof ISwingFoundSet)
		{
			((ISwingFoundSet)currentData).removeTableModelListener(this);
			((ISwingFoundSet)currentData).getSelectionModel().removeListSelectionListener(this);
			// ListSelectionModel lsm = currentData.getSelectionModel();
			// lsm.removeListSelectionListener(this);
		}

		currentData = fs;
		isCurrentDataChanged = true;
		getStylePropertyChanges().setChanged();
		if (currentData == null)
		{
			// table.setSelectionModel(new DefaultListSelectionModel());
			// table.setModel(new DefaultTableModel());
			data.setObject(FoundSetListWrapper.EMPTY);
		}
		else
		{
			// ListSelectionModel lsm = currentData.getSelectionModel();

			// int selected = currentData.getSelectedIndex();
			// table.setSelectionModel(lsm);
			// table.setModel((TableModel)currentData);
			data.setObject(new FoundSetListWrapper((FoundSet)currentData));
			// currentData.setSelectedIndex(selected);

			if (currentData instanceof ISwingFoundSet)
			{
				((ISwingFoundSet)currentData).addTableModelListener(this);
				((ISwingFoundSet)currentData).getSelectionModel().addListSelectionListener(this);
			}
			// lsm.addListSelectionListener(this);

			// valueChanged(null,stopEditing);
		}
		scriptable.setFoundset(currentData);
		for (Object header : getHeaderComponents())
		{
			((SortableCellViewHeader)header).setResizeImage(R_ARROW_OFF);
		}
	}

	private boolean isSelectionByCellAction;

	public void setSelectionMadeByCellAction()
	{
		isSelectionByCellAction = true;
	}

	public void clearSelectionByCellActionFlag()
	{
		isSelectionByCellAction = false;
	}

	public boolean isSelectionByCellAction()
	{
		return isSelectionByCellAction;
	}

	public void valueChanged(ListSelectionEvent e)
	{
		if (currentData != null && !e.getValueIsAdjusting())
		{
			boolean isTableChanged = false;

			//in case selection changed outside of an action on the component, and it's a list view with left-bar selection mark (so, no selection color),
			// we need to re-render the view
			if (!isSelectionByCellAction() && isListViewMode() && getStyleAttributeValue(getRowSelectedStyle(), ISupportRowStyling.ATTRIBUTE.BGCOLOR) == null)
			{
				isTableChanged = true;
			}

			if (!isScrollMode()) //test if selection did move to another page
			{
				int newSelectedIndex = currentData.getSelectedIndex();
				int newPageIndex = newSelectedIndex / table.getRowsPerPage();
				if (table.getCurrentPage() != newPageIndex)
				{
					// try to lock the page of this cellbasedview, so that concurrent rendering can't or won't happen.
					MainPage mp = table.findParent(MainPage.class);
					if (mp != null) mp.touch();
					table.setCurrentPage(newPageIndex);
					// if table row selection color must work then this must be outside this if.
					isTableChanged = true;
				}
			}

			if (isTableChanged) getStylePropertyChanges().setChanged();
		}
	}


	public void setValidationEnabled(boolean b)
	{
		if (validationEnabled != b)
		{
			// find mode / edit mode switch
			getStylePropertyChanges().setChanged();
		}
		validationEnabled = b;
		dal.setFindMode(!b);
	}

	public boolean stopUIEditing(final boolean looseFocus)
	{
		Object hasInvalidValue = visitChildren(IDisplayData.class, new IVisitor<Component>()
		{
			public Object component(Component component)
			{
				if (!((IDisplayData)component).stopUIEditing(looseFocus))
				{
					return Boolean.TRUE;
				}
				return IVisitor.CONTINUE_TRAVERSAL;
			}
		});

		return hasInvalidValue != Boolean.TRUE;
	}

	public void setCursor(Cursor cursor)
	{
	}

	public String getRowBGColorScript()
	{
		return bgColorScript;
	}

	public List<Object> getRowBGColorArgs()
	{
		return bgColorArgs;
	}

	public void setRowBGColorScript(String bgColorScript, List<Object> args)
	{
		this.bgColorScript = bgColorScript;
		this.bgColorArgs = args;
	}

	public boolean editCellAt(int i)
	{
		return false;
	}

	public boolean isEditing()
	{
		return false;
	}

	public void requestFocus()
	{
	}

	public void start(IApplication app)
	{
	}

	public void stop()
	{
	}

	public void ensureIndexIsVisible(int index)
	{
	}

	public Rectangle getVisibleRect()
	{
		return null;
	}

	public void setVisibleRect(Rectangle scrollPosition)
	{

	}

	public boolean isDisplayingMoreThanOneRecord()
	{
		return true;
	}

	public void setEditable(boolean findMode)
	{
	}


	public void setRecordIndex(int i)
	{
		if (currentData != null)
		{
			currentData.setSelectedIndex(i);
		}
	}

	/*
	 * readonly---------------------------------------------------
	 */
	public boolean isReadOnly()
	{
		return isReadOnly;
	}

	public void setReadOnly(boolean b)
	{
		isReadOnly = b;
	}

	public void setName(String n)
	{
		name = n;
	}

	private String name;

	public String getName()
	{
		return name;
	}


	/*
	 * border---------------------------------------------------
	 */
	private Border border;

	public void setBorder(Border border)
	{
		this.border = border;
	}

	public Border getBorder()
	{
		return border;
	}


	/*
	 * opaque---------------------------------------------------
	 */
	public void setOpaque(boolean opaque)
	{
		this.opaque = opaque;
	}

	private boolean opaque;

//	public boolean js_isTransparent()
//	{
//		return !opaque;
//	}
//	public void js_setTransparent(boolean b)
//	{
//		opaque = !b;
//		jsChangeRecorder.setTransparent(b);
//	}
	public boolean isOpaque()
	{
		return opaque;
	}


	/*
	 * tooltip---------------------------------------------------
	 */
//	public String js_getToolTipText()
//	{
//		return tooltip;
//	}
	private String tooltip;

	public void setToolTipText(String tooltip)
	{
		if (Utils.stringIsEmpty(tooltip))
		{
			this.tooltip = null;
		}
		else
		{
			this.tooltip = tooltip;
		}
	}

//	public void js_setToolTipText(String tooltip)
//	{
//		this.tooltip = tooltip;
//	}


	/*
	 * font---------------------------------------------------
	 */
	public void setFont(Font font)
	{
		this.font = font;
	}

	private Font font;

//	public void js_setFont(String spec)
//	{
//		font = PersistHelper.createFont(spec);
//		jsChangeRecorder.setFont(spec);
//	}
	public Font getFont()
	{
		return font;
	}


	private Color background;

	public void setBackground(Color cbg)
	{
		this.background = cbg;
	}

	public Color getBackground()
	{
		return background;
	}


	private Color foreground;

	public void setForeground(Color cfg)
	{
		this.foreground = cfg;
	}

	public Color getForeground()
	{
		return foreground;
	}


	/*
	 * visible---------------------------------------------------
	 */
	public void setComponentVisible(boolean visible)
	{
		if (viewable)
		{
			setVisible(visible);
		}
	}


	public void setComponentEnabled(final boolean b)
	{
		if (accessible)
		{
			if (pagingNavigator != null) pagingNavigator.setEnabled(b);
			if (table != null) table.setEnabled(b);
			if (headers != null) headers.setEnabled(b);
			super.setEnabled(b);
			getStylePropertyChanges().setChanged();
		}
	}

	private boolean accessible = true;

	public void setAccessible(boolean b)
	{
		if (!b) setComponentEnabled(b);
		accessible = b;
	}

	private boolean viewable = true;

	public void setViewable(boolean b)
	{
		if (!b) setComponentVisible(b);
		this.viewable = b;
	}

	public boolean isViewable()
	{
		return viewable;
	}

	/*
	 * location---------------------------------------------------
	 */
	private Point location = new Point(0, 0);

	public int getAbsoluteFormLocationY()
	{
		WebDataRenderer parent = findParent(WebDataRenderer.class);
		if (parent != null)
		{
			return parent.getYOffset() + getLocation().y;
		}
		return getLocation().y;
	}

	public void setLocation(Point location)
	{
		this.location = location;
	}

	public Point getLocation()
	{
		return location;
	}

	/**
	 * @see wicket.Component#isEnabled()
	 */
	@Override
	public boolean isEnabled()
	{
		return super.isEnabled() || !validationEnabled;
	}

	/*
	 * size---------------------------------------------------
	 */
	private Dimension size = new Dimension(0, 0);

	public Dimension getSize()
	{
		return size;
	}

	public Rectangle getWebBounds()
	{
		Dimension d = ((ChangesRecorder)getStylePropertyChanges()).calculateWebSize(size.width, size.height, border, new Insets(0, 0, 0, 0), 0, null);
		return new Rectangle(location, d);
	}

	/**
	 * @see com.servoy.j2db.ui.ISupportWebBounds#getPaddingAndBorder()
	 */
	public Insets getPaddingAndBorder()
	{
		return ((ChangesRecorder)getStylePropertyChanges()).getPaddingAndBorder(size.height, border, new Insets(0, 0, 0, 0), 0, null);
	}


	public void setSize(Dimension size)
	{
		this.size = size;
	}

	/**
	 * @see com.servoy.j2db.ui.IDataRenderer#addDisplayComponent(com.servoy.j2db.persistence.IPersist, com.servoy.j2db.dataprocessing.IDisplay)
	 */
	public void addDisplayComponent(IPersist obj, IDisplay display)
	{
		//ignore
	}

	private ArrayList<PersistColumnIdentifierComponent> getOrderedPersistColumnIdentifierComponents()
	{
		ArrayList<PersistColumnIdentifierComponent> orderedPersistColumnIdentifierComponent = new ArrayList<PersistColumnIdentifierComponent>();

		for (Entry<IPersist, Component> entry : elementToColumnIdentifierComponent.entrySet())
		{
			orderedPersistColumnIdentifierComponent.add(new PersistColumnIdentifierComponent(entry.getKey(), (IComponent)entry.getValue()));
		}
		Collections.sort(orderedPersistColumnIdentifierComponent);
		return orderedPersistColumnIdentifierComponent;
	}

	public void focusFirstField()
	{
		// find column that should get focus
		ArrayList<PersistColumnIdentifierComponent> orderedPersistColumnIdentifierComponent = getOrderedPersistColumnIdentifierComponents();
		Component firstFocusableColumnIdentifier = null;
		for (PersistColumnIdentifierComponent pci : orderedPersistColumnIdentifierComponent)
		{
			IComponent c = pci.getComponent();
			if (!(c instanceof WebBaseButton || c instanceof WebBaseLabel || !c.isEnabled() || (validationEnabled && c instanceof IFieldComponent && !((IFieldComponent)c).isEditable())))
			{
				firstFocusableColumnIdentifier = (Component)c;
				break;
			}
		}
		if (firstFocusableColumnIdentifier != null) setColumnThatRequestsFocus(firstFocusableColumnIdentifier);
	}

	/**
	 * @see com.servoy.j2db.ui.IDataRenderer#getDataAdapterList()
	 */
	public DataAdapterList getDataAdapterList()
	{
		return dal;
	}

	/**
	 * @see com.servoy.j2db.ui.IDataRenderer#refreshRecord(com.servoy.j2db.dataprocessing.IRecordInternal)
	 */
	public void refreshRecord(IRecordInternal record)
	{
		// have to set this because of relookup adapters.
		if (dal != null)
		{
			if (isEditing() && dal.getState() != record)
			{
				stopUIEditing(true);
			}
			dal.setRecord(record, true);
		}
	}

	/**
	 * @see com.servoy.j2db.ui.IDataRenderer#setAllNonFieldsEnabled(boolean)
	 */
	public void setAllNonFieldsEnabled(boolean enabled)
	{
		//ignore
	}

	/**
	 * @see com.servoy.j2db.ui.IDataRenderer#setAllNonRowFieldsEnabled(boolean)
	 */
	public void setAllNonRowFieldsEnabled(boolean enabled)
	{
		//ignore
	}

	public void add(IComponent c, String n)
	{
		//ignore
	}

	/**
	 * @see com.servoy.j2db.ui.IContainer#getComponentIterator()
	 */
	public Iterator<IComponent> getComponentIterator()
	{
		//ignore
		return null;
	}

	/**
	 * @see com.servoy.j2db.ui.IContainer#remove(com.servoy.j2db.ui.IComponent)
	 */
	public void remove(IComponent c)
	{
		//ignore
	}

	public void setTabSeqComponents(List<Component> list)
	{
		if (list == null || list.size() == 0)
		{
			if (elementTabIndexes.size() > 0) getStylePropertyChanges().setChanged();
			elementTabIndexes.clear();
		}
		else
		{
			getStylePropertyChanges().setChanged();
			elementTabIndexes.clear();
			int columnTabIndex = 0;
			for (Component rowIdComponent : list)
			{
				for (Entry<IPersist, Component> entry : elementToColumnIdentifierComponent.entrySet())
				{
					if (componentIdentifiesColumn(rowIdComponent, entry.getValue()))
					{
						elementTabIndexes.put(entry.getKey(), Integer.valueOf(columnTabIndex));
						columnTabIndex++;
						break;
					}
				}
			}
		}
	}

	private boolean componentIdentifiesColumn(Component rowIdComponent, Component value)
	{
		if (rowIdComponent == value)
		{
			return true;
		}
		else if (value instanceof ISupplyFocusChildren< ? >)
		{
			for (Object child : ((ISupplyFocusChildren< ? >)value).getFocusChildren())
			{
				if (child == rowIdComponent) return true;
			}
		}
		return false;
	}

	public boolean isColumnIdentifierComponent(Component c)
	{
		return elementToColumnIdentifierComponent.containsValue(c);
	}

	/**
	 * @see com.servoy.j2db.ui.IComponent#getToolTipText()
	 */
	public String getToolTipText()
	{
		return tooltip;
	}

	private Object getStyleAttributeForListItem(ListItem<IRecordInternal> listItem, boolean isSelected, ISupportRowStyling.ATTRIBUTE rowStyleAttribute,
		boolean asInlineCSSString)
	{
		Object listItemAttrValue = null;
		final IRecordInternal rec = listItem.getModelObject();

		if (rec != null && rec.getRawData() != null)
		{
			IStyleRule style = isSelected ? getRowSelectedStyle() : null;
			if (style != null && style.getAttributeCount() == 0) style = null;
			if (style == null)
			{
				style = (listItem.getIndex() % 2 == 0) ? getRowOddStyle() : getRowEvenStyle(); // because index = 0 means record = 1
			}

			if (asInlineCSSString)
			{
				listItemAttrValue = getStyleAttributeString(style, rowStyleAttribute);
			}
			else
			{
				listItemAttrValue = getStyleAttributeValue(style, rowStyleAttribute);
			}
		}

		return listItemAttrValue;
	}

	/**
	 * Returns for styleAttribute:
	 * <p>
	 *   <b>BGCOLOR</b>: an inline style string with background color to be applied to a component <br/>
	 *   Needed because transparent colors are not supported in all browsers and a fallback color is also applied (if supplied)
	 *            (ex: "background-color: #AAA;background-color: rgba(255,255,255,0.7)" )<br/>
	 *            (<b>doesn't need further processing to be applyed on a component</b>)
	 * </p>
	 * <p>
	 *   <b>FGCOLOR</b>: an inline style string to be applied to a component (same logic as GBcolor)
	 *   (doesn't need further processing)
	 * </p>
	 * <p>
	 *   <b>FONT</b>: string containing font font css rule values (needs further processing ,ex passed in ChangesRecorder.setFont())
	 * </p>
	 *   <b>BORDER</b>: string containing font border css rule values (needs further processing ,ex passed inChangesRecorder.setBorder())
	 * @param style
	 * @param styleAttribute
	 * @return 
	 */
	private String getStyleAttributeString(IStyleRule style, ISupportRowStyling.ATTRIBUTE styleAttribute)
	{
		IStyleSheet ss = getRowStyleSheet();
		if (ss != null && style != null)
		{
			switch (styleAttribute)
			{
				case BGIMAGE :
					String[] bgImageMediaUrls = style.getValues(CSS.Attribute.BACKGROUND_IMAGE.toString());
					if (bgImageMediaUrls != null)
					{
						StringBuffer ret = new StringBuffer();
						for (String val : bgImageMediaUrls)
						{
							TextualStyle headerStyle = new TemplateGenerator.TextualStyle();
							if (val.contains(MediaURLStreamHandler.MEDIA_URL_DEF))
							{
								String urlContentVal = val.replaceAll(".*url\\([\"']?(.*?)[\"']?\\)", "$1"); //extract media://name from url("media:///name") 
								String httpUrl = MediaURLStreamHandler.getTranslatedMediaURL(application.getFlattenedSolution(), urlContentVal);
								headerStyle.setProperty(CSS.Attribute.BACKGROUND_IMAGE.toString(), "url(" + httpUrl + ")");
							}
							else
							{
								headerStyle.setProperty(CSS.Attribute.BACKGROUND_IMAGE.toString(), val);
							}

							//the returned string is style='...' , we nedd to get the ... part
							String inlineStyle = headerStyle.toString();
							if (inlineStyle != null) ret.append(inlineStyle.substring(inlineStyle.indexOf('\'') + 1, inlineStyle.length() - 2));


						}
						return ret.toString();//.replaceAll("(background-image:)(.*?)(;)(background-image:)", "$1");
					}
					else
					{
						return null;
					}
				case BGCOLOR :
					if (style.getValues(CSS.Attribute.BACKGROUND_COLOR.toString()) != null)
					{
						StringBuffer ret = new StringBuffer();
						for (Color c : ss.getBackgrounds(style))
						{
							ret.append(CSS.Attribute.BACKGROUND_COLOR.toString()).append(':').append(PersistHelper.createColorString(c)).append(';');
						}
						return (ret.length() != 0) ? ret.toString() : null;
					}
					else
					{
						return null;
					}

				case FGCOLOR :
					if (style.getValues(CSS.Attribute.COLOR.toString()) != null)
					{
						StringBuffer ret = new StringBuffer();
						for (Color c : ss.getForegrounds(style))
						{
							ret.append(CSS.Attribute.COLOR.toString()).append(':').append(PersistHelper.createColorString(c)).append(';');
						}
						return (ret.length() != 0) ? ret.toString() : null;
					}
					else
					{
						return null;
					}
				case FONT :
					return ss.hasFont(style) ? PersistHelper.createFontString(ss.getFont(style)) : null;
				case BORDER :
					return ss.hasBorder(style) ? ComponentFactoryHelper.createBorderString(ss.getBorder(style)) : null;
			}
		}
		return null;
	}

	private String getStyleAttributeValue(IStyleRule style, ISupportRowStyling.ATTRIBUTE styleAttribute)
	{
		IStyleSheet ss = getRowStyleSheet();
		if (ss != null && style != null)
		{
			switch (styleAttribute)
			{
				case BGCOLOR :
					return style.getValue(CSS.Attribute.BACKGROUND_COLOR.toString()) != null ? PersistHelper.createColorString(ss.getBackground(style)) : null;
				case FGCOLOR :
					return style.getValue(CSS.Attribute.COLOR.toString()) != null ? PersistHelper.createColorString(ss.getForeground(style)) : null;
				case FONT :
					return ss.hasFont(style) ? PersistHelper.createFontString(ss.getFont(style)) : null;
				case BORDER :
					return ss.hasBorder(style) ? ComponentFactoryHelper.createBorderString(ss.getBorder(style)) : null;
			}
		}
		return null;
	}

	protected String getHeaderBgImageStyle()
	{
		return getStyleAttributeString(getHeaderStyle(), ISupportRowStyling.ATTRIBUTE.BGIMAGE);
	}


	protected String getHeaderBgColorStyle()
	{
		return getStyleAttributeString(getHeaderStyle(), ISupportRowStyling.ATTRIBUTE.BGCOLOR);
	}

	protected String getHeaderFgColorStyle()
	{
		return getStyleAttributeString(getHeaderStyle(), ISupportRowStyling.ATTRIBUTE.FGCOLOR);
	}

	protected String getHeaderFont()
	{
		return getStyleAttributeString(getHeaderStyle(), ISupportRowStyling.ATTRIBUTE.FONT);
	}

	protected String getHeaderBorder()
	{
		return getStyleAttributeString(getHeaderStyle(), ISupportRowStyling.ATTRIBUTE.BORDER);
	}

	private Object getListItemFgColor(ListItem<IRecordInternal> listItem, boolean isSelected, boolean asInlineCSSString)
	{
		if (asInlineCSSString)
		{
			return getStyleAttributeForListItem(listItem, isSelected, ISupportRowStyling.ATTRIBUTE.FGCOLOR, true);
		}
		else
		{
			return getStyleAttributeForListItem(listItem, isSelected, ISupportRowStyling.ATTRIBUTE.FGCOLOR, false);
		}
	}

	private Object getListItemFont(ListItem<IRecordInternal> listItem, boolean isSelected)
	{
		return getStyleAttributeForListItem(listItem, isSelected, ISupportRowStyling.ATTRIBUTE.FONT, false);
	}

	private Object getListItemBorder(ListItem<IRecordInternal> listItem, boolean isSelected)
	{
		return getStyleAttributeForListItem(listItem, isSelected, ISupportRowStyling.ATTRIBUTE.BORDER, false);
	}

	private Object getListItemBgColor(ListItem<IRecordInternal> listItem, boolean isSelected, boolean asInlineCssString)
	{
		Object color = null;
		final IRecordInternal rec = listItem.getModelObject();
		String rowBGColorProvider = getRowBGColorScript();
		Row rawData = null;
		if (rec != null && (rawData = rec.getRawData()) != null)
		{
			if (asInlineCssString)
			{
				color = getStyleAttributeForListItem(listItem, isSelected, ISupportRowStyling.ATTRIBUTE.BGCOLOR, true);
			}
			else
			{
				color = getStyleAttributeForListItem(listItem, isSelected, ISupportRowStyling.ATTRIBUTE.BGCOLOR, false);
			}


			if (rowBGColorProvider != null)
			{
				// TODO type and name should be get somehow if this is possible, we have to know the specific cell/column for that. 
				String type = null;//(renderer instanceof IScriptBaseMethods) ? ((IScriptBaseMethods)renderer).js_getElementType() : null;
				String cellName = null;//(renderer instanceof IScriptBaseMethods) ? ((IScriptBaseMethods)renderer).js_getName() : null;

				if (rawData.containsCalculation(rowBGColorProvider))
				{
					// TODO this should be done better....
					// isEdited is always false
					Record.VALIDATE_CALCS.set(Boolean.FALSE);
					try
					{
						color = rec.getParentFoundSet().getCalculationValue(
							rec,
							rowBGColorProvider,
							Utils.arrayMerge(new Object[] { new Integer(listItem.getIndex()), new Boolean(isSelected), type, cellName, Boolean.FALSE },
								Utils.parseJSExpressions(getRowBGColorArgs())), null);
					}
					finally
					{
						Record.VALIDATE_CALCS.set(null);
					}
				}
				else
				{
					try
					{
						FormController currentForm = dal.getFormController();
						color = currentForm.executeFunction(rowBGColorProvider, Utils.arrayMerge(new Object[] { new Integer(listItem.getIndex()), new Boolean(
							isSelected), type, cellName, currentForm.getName(), rec, Boolean.FALSE }, Utils.parseJSExpressions(getRowBGColorArgs())), false,
							null, true, null);
					}
					catch (Exception ex)
					{
						Debug.error(ex);
					}
				}
			}
		}

		return color;
	}

	private void applyStyleOnComponent(Component comp, Object bgColor, Object fgColor, Object compFont, Object compBorder)
	{
		if (comp instanceof IScriptableProvider)
		{
			IScriptable s = ((IScriptableProvider)comp).getScriptObject();

			if (s instanceof IRuntimeComponent)
			{
				IRuntimeComponent sbm = (IRuntimeComponent)s;
				RenderableWrapper sbmRW = null;
				if (s instanceof ISupportOnRenderCallback)
				{
					IScriptRenderMethods sr = ((ISupportOnRenderCallback)s).getRenderable();
					if (sr instanceof RenderableWrapper) sbmRW = (RenderableWrapper)sr;
				}

				if (bgColor != null)
				{
					if (sbmRW != null) sbmRW.clearProperty(RenderableWrapper.PROPERTY_BGCOLOR);
					sbm.setBgcolor(bgColor.toString());
				}
				else
				{
					sbm.setBgcolor(runtimeComponentStyleAttributes.get(sbm).get(RenderableWrapper.PROPERTY_BGCOLOR));
					setParentBGcolor(comp, "");

				}

				if (fgColor != null)
				{
					if (sbmRW != null) sbmRW.clearProperty(RenderableWrapper.PROPERTY_FGCOLOR);
					sbm.setFgcolor(fgColor.toString());
				}
				else
				{
					sbm.setFgcolor(runtimeComponentStyleAttributes.get(sbm).get(RenderableWrapper.PROPERTY_FGCOLOR));
				}

				if (compFont != null)
				{
					if (sbmRW != null) sbmRW.clearProperty(RenderableWrapper.PROPERTY_FONT);
					sbm.setFont(compFont.toString());
				}
				else
				{
					sbm.setFont(runtimeComponentStyleAttributes.get(sbm).get(RenderableWrapper.PROPERTY_FONT));
				}


				if (compBorder != null)
				{
					String newBorder = compBorder.toString();
					Border currentBorder = ComponentFactoryHelper.createBorder(sbm.getBorder());
					Border marginBorder = null;
					if (currentBorder instanceof EmptyBorder)
					{
						marginBorder = currentBorder;
					}
					else if (currentBorder instanceof CompoundBorder && ((CompoundBorder)currentBorder).getInsideBorder() instanceof EmptyBorder)
					{
						marginBorder = ((CompoundBorder)currentBorder).getInsideBorder();
					}

					if (marginBorder != null)
					{
						newBorder = ComponentFactoryHelper.createBorderString(BorderFactory.createCompoundBorder(
							ComponentFactoryHelper.createBorder(newBorder), marginBorder));
					}
					if (sbmRW != null) sbmRW.clearProperty(RenderableWrapper.PROPERTY_BORDER);
					sbm.setBorder(newBorder);
					// reset size so the web size will be recalculated based on the new border
					sbm.setSize(sbm.getWidth(), sbm.getHeight());
				}
				else
				{
					sbm.setBorder(runtimeComponentStyleAttributes.get(sbm).get(RenderableWrapper.PROPERTY_BORDER));
				}
			}
		}
	}

	static void setParentBGcolor(Component comp, Object compColor)
	{
		MarkupContainer cellContainer = comp.getParent();
		String compColorStr = compColor.toString();
		if (cellContainer instanceof CellContainer)
		{
			cellContainer.add(new StyleAppendingModifier(new Model<String>("background-color: " + compColorStr))); //$NON-NLS-1$
		}
	}

	public int onDrag(JSDNDEvent event)
	{
		int onDragID = 0;
		if (cellview instanceof Portal)
		{
			Portal cellviewPortal = (Portal)cellview;
			onDragID = cellviewPortal.getOnDragMethodID();
		}
		else
		{
			onDragID = fc.getForm().getOnDragMethodID();
		}

		if (onDragID > 0)
		{
			Object dragReturn = fc.executeFunction(Integer.toString(onDragID), new Object[] { event }, false, null, false, "onDragMethodID"); //$NON-NLS-1$
			if (dragReturn instanceof Number) return ((Number)dragReturn).intValue();
		}

		return DRAGNDROP.NONE;
	}

	public boolean onDragOver(JSDNDEvent event)
	{
		int onDragOverID = 0;
		if (cellview instanceof Portal)
		{
			Portal cellviewPortal = (Portal)cellview;
			onDragOverID = cellviewPortal.getOnDragOverMethodID();
		}
		else
		{
			onDragOverID = fc.getForm().getOnDragOverMethodID();
		}

		if (onDragOverID > 0)
		{
			Object dragOverReturn = fc.executeFunction(Integer.toString(onDragOverID), new Object[] { event }, false, null, false, "onDragOverMethodID"); //$NON-NLS-1$
			if (dragOverReturn instanceof Boolean) return ((Boolean)dragOverReturn).booleanValue();
		}
		return getOnDropMethodID() > 0;
	}

	private int getOnDropMethodID()
	{
		int onDropID = 0;
		if (cellview instanceof Portal)
		{
			Portal cellviewPortal = (Portal)cellview;
			onDropID = cellviewPortal.getOnDropMethodID();
		}
		else
		{
			onDropID = fc.getForm().getOnDropMethodID();
		}
		return onDropID;
	}

	public boolean onDrop(JSDNDEvent event)
	{
		int onDropID = getOnDropMethodID();
		if (onDropID > 0)
		{
			Object dropHappened = fc.executeFunction(Integer.toString(onDropID), new Object[] { event }, false, null, false, "onDropMethodID"); //$NON-NLS-1$
			if (dropHappened instanceof Boolean) return ((Boolean)dropHappened).booleanValue();
		}
		return false;
	}

	public void onDragEnd(JSDNDEvent event)
	{
		int onDragEndID = 0;
		if (cellview instanceof Portal)
		{
			Portal cellviewPortal = (Portal)cellview;
			onDragEndID = cellviewPortal.getOnDragEndMethodID();
		}
		else
		{
			onDragEndID = fc.getForm().getOnDragEndMethodID();
		}

		if (onDragEndID > 0)
		{
			fc.executeFunction(Integer.toString(onDragEndID), new Object[] { event }, false, null, false, "onDragEndMethodID"); //$NON-NLS-1$
		}
	}

	public IComponent getDragSource(Point xy)
	{
		// don't need this, ignore
		return null;
	}

	public String getDragFormName()
	{
		return getDataAdapterList().getFormController().getName();
	}

	public boolean isGridView()
	{
		return true;
	}

	public boolean isListViewMode()
	{
		return isListViewMode;
	}

	public IRecordInternal getDragRecord(Point xy)
	{
		// don't need this, ignore
		return null;
	}

	public int getYOffset()
	{
		return yOffset;
	}

	private int yOffset;
	private FormController dragNdropController;

	public void initDragNDrop(FormController formController, int clientDesignYOffset)
	{
		this.yOffset = clientDesignYOffset;
		boolean enableDragDrop = false;
		if (cellview instanceof Portal)
		{
			Portal cellviewPortal = (Portal)cellview;
			enableDragDrop = (cellviewPortal.getOnDragMethodID() > 0 || cellviewPortal.getOnDragEndMethodID() > 0 || cellviewPortal.getOnDragOverMethodID() > 0 || cellviewPortal.getOnDropMethodID() > 0);
		}
		else
		{
			Form form = formController.getForm();
			enableDragDrop = (form.getOnDragMethodID() > 0 || form.getOnDragEndMethodID() > 0 || form.getOnDragOverMethodID() > 0 || form.getOnDropMethodID() > 0);
		}

		if (enableDragDrop)
		{
			dragNdropController = formController;
			addDragNDropBehavior();
		}
	}

	public FormController getDragNDropController()
	{
		return dragNdropController;
	}

	private void addDragNDropBehavior()
	{
		DraggableBehavior compDragBehavior = new DraggableBehavior()
		{
			private IComponent hoverComponent;
			private boolean isHoverAcceptDrop;

			@Override
			protected void onDragEnd(String id, int x, int y, int m, AjaxRequestTarget ajaxRequestTarget)
			{
				if (getCurrentDragOperation() != DRAGNDROP.NONE)
				{
					JSDNDEvent event = WebCellBasedView.this.createScriptEvent(EventType.onDragEnd, getDragComponent(), null, m);
					event.setData(getDragData());
					event.setDataMimeType(getDragDataMimeType());
					event.setDragResult(getDropResult() ? getCurrentDragOperation() : DRAGNDROP.NONE);
					WebCellBasedView.this.onDragEnd(event);
				}

				super.onDragEnd(id, x, y, m, ajaxRequestTarget);
			}

			@Override
			protected boolean onDragStart(final String id, int x, int y, int m, AjaxRequestTarget ajaxRequestTarget)
			{
				IComponent comp = getBindedComponentChild(id);
				JSDNDEvent event = WebCellBasedView.this.createScriptEvent(EventType.onDrag, comp, new Point(x, y), m);
				int dragOp = WebCellBasedView.this.onDrag(event);
				if (dragOp == DRAGNDROP.NONE) return false;
				setCurrentDragOperation(dragOp);
				setDragData(event.getData(), event.getDataMimeType());
				setDragComponent(comp);
				setDropResult(false);
				hoverComponent = null;
				isHoverAcceptDrop = false;
				return true;
			}

			@Override
			protected void onDrop(String id, final String targetid, int x, int y, int m, AjaxRequestTarget ajaxRequestTarget)
			{
				if (getCurrentDragOperation() != DRAGNDROP.NONE)
				{
					IComponent comp = getBindedComponentChild(targetid);
					if (hoverComponent == comp && !isHoverAcceptDrop) return;
					JSDNDEvent event = WebCellBasedView.this.createScriptEvent(EventType.onDrop, comp, new Point(x, y), m);
					event.setData(getDragData());
					event.setDataMimeType(getDragDataMimeType());
					setDropResult(WebCellBasedView.this.onDrop(event));
				}
			}

			@Override
			protected void onDropHover(String id, final String targetid, int m, AjaxRequestTarget ajaxRequestTarget)
			{
				if (getCurrentDragOperation() != DRAGNDROP.NONE)
				{
					IComponent comp = getBindedComponentChild(targetid);
					JSDNDEvent event = WebCellBasedView.this.createScriptEvent(EventType.onDragOver, comp, null, m);
					event.setData(getDragData());
					event.setDataMimeType(getDragDataMimeType());
					isHoverAcceptDrop = WebCellBasedView.this.onDragOver(event);
					hoverComponent = comp;
				}
			}

			@Override
			public IComponent getBindedComponentChild(final String childId)
			{
				IComponent comp = super.getBindedComponentChild(childId);
				if (comp == null) comp = WebCellBasedView.this;
				return comp;
			}
		};
		compDragBehavior.setUseProxy(true);
		add(compDragBehavior);
	}

	public JSDNDEvent createScriptEvent(EventType type, IComponent dragSource, Point xy, int modifiers)
	{
		JSDNDEvent jsEvent = new JSDNDEvent();
		jsEvent.setType(type);
		jsEvent.setFormName(getDragFormName());
		if (dragSource instanceof IDataRenderer)
		{
			IDataRenderer dr = (IDataRenderer)dragSource;
			FormController fct = dr.getDataAdapterList().getFormController();
			jsEvent.setSource(fct.getFormScope());
		}
		else
		{
			jsEvent.setSource(dragSource);
			if (dragSource != null)
			{
				if (dragSource instanceof Component)
				{
					WebCellBasedViewListItem listItem = ((Component)dragSource).findParent(WebCellBasedViewListItem.class);
					if (listItem != null)
					{
						IRecordInternal dragRecord = listItem.getModelObject();
						if (dragRecord instanceof Record) jsEvent.setRecord((Record)dragRecord);
					}
				}
				String dragSourceName = dragSource.getName();
				if (dragSourceName == null) dragSourceName = dragSource.getId();
				jsEvent.setElementName(dragSourceName);
			}
		}

		if (xy != null) jsEvent.setLocation(xy);
		jsEvent.setModifiers(modifiers);

		return jsEvent;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.apache.wicket.Component#renderHead(org.apache.wicket.markup.html.internal.HtmlHeaderContainer)
	 */
	@Override
	public void renderHead(HtmlHeaderContainer container)
	{
		super.renderHead(container);
		String columnResizeScript = getColumnResizeScript();
		if (columnResizeScript != null) container.getHeaderResponse().renderOnDomReadyJavascript(columnResizeScript);
		if (isScrollMode())
		{
			String top, scrollPadding, right = null;
			if (headers != null)
			{
				top = "$('#" + headers.getMarkupId() + "').height() + 'px'";
			}
			else
			{
				top = "'0px'";
			}

			ClientInfo info = Session.get().getClientInfo();
			if (info instanceof WebClientInfo && ((WebClientInfo)info).getProperties().isBrowserInternetExplorer())
			{
				scrollPadding = "'0px'";
			}
			else
			{
				scrollPadding = "'12px'";
			}


			StringBuffer tbodyStyle = new StringBuffer("$('#").append(tableContainerBody.getMarkupId()).append("').css('top',").append(top).append(");");
			tbodyStyle.append("$('#").append(tableContainerBody.getMarkupId()).append("').css('padding-right',").append(scrollPadding).append(");");
			tbodyStyle.append("$('#").append(tableContainerBody.getMarkupId()).append("').show();");
			container.getHeaderResponse().renderOnLoadJavascript(tbodyStyle.toString());
			//if (table.gets) container.getHeaderResponse().renderOnDomReadyJavascript(getRowSelectionScript(true));
		}
	}

	private boolean hasOnRender;

	private boolean hasOnRender()
	{
		if (dataRendererOnRenderWrapper.getRenderEventExecutor().hasRenderCallback())
		{
			return true;
		}
		else
		{
			Iterator<Component> compIte = elementToColumnIdentifierComponent.values().iterator();
			Component comp;
			while (compIte.hasNext())
			{
				comp = compIte.next();
				if (comp instanceof IScriptableProvider)
				{
					IScriptable s = ((IScriptableProvider)comp).getScriptObject();
					if (s instanceof ISupportOnRenderCallback && ((ISupportOnRenderCallback)s).getRenderEventExecutor().hasRenderCallback())
					{
						return true;
					}
				}
			}
		}

		return false;
	}

	public String getRowSelectionScript(boolean allCurrentPageRows)
	{
		if (currentData == null) return null;
		List<Integer> indexToUpdate;
		if (!hasOnRender && (bgColorScript != null || (getRowSelectedStyle() != null && getRowSelectedStyle().getAttributeCount() > 0)) &&
			(indexToUpdate = getIndexToUpdate(allCurrentPageRows)) != null)
		{
			int firstRow = table.isPageableMode() ? table.getCurrentPage() * table.getRowsPerPage() : table.getStartIndex();
			int lastRow = firstRow + table.getViewSize() - 1;
			int[] newSelectedIndexes = getSelectedIndexes();

			AppendingStringBuffer sab = new AppendingStringBuffer();
			for (int rowIdx : indexToUpdate)
			{
				if (rowIdx >= firstRow && rowIdx <= lastRow)
				{
					ListItem<IRecordInternal> selectedListItem = (ListItem<IRecordInternal>)table.get(Integer.toString(rowIdx));
					if (selectedListItem != null)
					{
						String selectedId = selectedListItem.getMarkupId();
						boolean isSelected = Arrays.binarySearch(newSelectedIndexes, rowIdx) >= 0;

						Object selectedColor = null, selectedFgColor = null, selectedFont = null, selectedBorder = null;
						selectedColor = getListItemBgColor(selectedListItem, isSelected, true);
						if (!isListViewMode())
						{
							selectedFgColor = getListItemFgColor(selectedListItem, isSelected, true);
							selectedFont = getListItemFont(selectedListItem, isSelected);
							selectedBorder = getListItemBorder(selectedListItem, isSelected);
						}
						selectedColor = (selectedColor == null ? "" : selectedColor.toString()); //$NON-NLS-1$
						selectedFgColor = (selectedFgColor == null) ? "" : selectedFgColor.toString(); //$NON-NLS-1$
						String fstyle = "", fweight = "", fsize = "", ffamily = ""; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$ //$NON-NLS-4$
						if (selectedFont != null)
						{
							Pair<String, String> fontCSSProps[] = PersistHelper.createFontCSSProperties(selectedFont.toString());
							for (Pair<String, String> fontCSSProp : fontCSSProps)
							{
								if (fontCSSProp != null)
								{
									String key = fontCSSProp.getLeft();
									String value = fontCSSProp.getRight();
									if (value == null) value = ""; //$NON-NLS-1$
									if ("font-style".equals(key)) //$NON-NLS-1$
									fstyle = value;
									else if ("font-weight".equals(key)) //$NON-NLS-1$
									fweight = value;
									else if ("font-size".equals(key)) //$NON-NLS-1$
									fsize = value;
									else if ("font-family".equals(key)) //$NON-NLS-1$
									ffamily = value;
								}
							}
						}
						String bstyle = "", bwidth = "", bcolor = ""; //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						if (selectedBorder != null)
						{
							Properties borderProperties = new Properties();
							ComponentFactoryHelper.createBorderCSSProperties(selectedBorder.toString(), borderProperties);
							bstyle = borderProperties.getProperty("border-style"); //$NON-NLS-1$
							if (bstyle == null) bstyle = ""; //$NON-NLS-1$
							bwidth = borderProperties.getProperty("border-width"); //$NON-NLS-1$
							bcolor = borderProperties.getProperty("border-color"); //$NON-NLS-1$
							if (bcolor == null)
							{
								bcolor = borderProperties.getProperty("border-top-color", ""); //$NON-NLS-1$ //$NON-NLS-2$
							}
							else
							{
								bcolor = getFirstToken(bcolor);
							}
						}
						else
						{

						}

						sab.append("Servoy.TableView.setRowStyle('"). //$NON-NLS-1$
						append(selectedId).append("', '"). //$NON-NLS-1$
						append(selectedColor).append("', '"). //$NON-NLS-1$
						append(selectedFgColor).append("', '"). //$NON-NLS-1$
						append(fstyle).append("', '"). //$NON-NLS-1$
						append(fweight).append("', '"). //$NON-NLS-1$
						append(fsize).append("', '"). //$NON-NLS-1$
						append(ffamily).append("', '"). //$NON-NLS-1$
						append(bstyle).append("', '"). //$NON-NLS-1$
						append(bwidth).append("', '"). //$NON-NLS-1$
						append(bcolor).append("', "). //$NON-NLS-1$
						append(isListViewMode()).append(");\n"); //$NON-NLS-1$
					}
				}
			}

			String rowSelectionScript = sab.toString();
			if (rowSelectionScript.length() > 0) return rowSelectionScript;
		}
		return null;
	}

	public void updateRowComponentsRenderState(AjaxRequestTarget target)
	{
		if (currentData == null) return;
		List<Integer> indexToUpdate;
		if ((indexToUpdate = getIndexToUpdate(false)) != null)
		{
			int firstRow = table.isPageableMode() ? table.getCurrentPage() * table.getRowsPerPage() : table.getStartIndex();
			int lastRow = firstRow + table.getViewSize() - 1;
			int[] newSelectedIndexes = getSelectedIndexes();

			for (int rowIdx : indexToUpdate)
			{
				if (rowIdx >= firstRow && rowIdx <= lastRow)
				{
					ListItem<IRecordInternal> selectedListItem = (ListItem<IRecordInternal>)table.get(Integer.toString(rowIdx));
					if (selectedListItem instanceof WebCellBasedViewListItem)
					{
						boolean isSelected = Arrays.binarySearch(newSelectedIndexes, rowIdx) >= 0;
						String sColor = null, sFgColor = null, sStyleFont = null, sStyleBorder = null;
						if (!isListViewMode())
						{
							Object color = WebCellBasedView.this.getListItemBgColor(selectedListItem, isSelected, false);
							sColor = (color == null || color instanceof Undefined) ? null : color.toString();
							Object fgColor = WebCellBasedView.this.getListItemFgColor(selectedListItem, isSelected, false);
							sFgColor = (fgColor == null || fgColor instanceof Undefined) ? null : fgColor.toString();
							Object styleFont = WebCellBasedView.this.getListItemFont(selectedListItem, isSelected);
							sStyleFont = (styleFont == null || styleFont instanceof Undefined) ? null : styleFont.toString();
							Object styleBorder = WebCellBasedView.this.getListItemBorder(selectedListItem, isSelected);
							sStyleBorder = (styleBorder == null || styleBorder instanceof Undefined) ? null : styleBorder.toString();
						}

						((WebCellBasedViewListItem)selectedListItem).updateComponentsRenderState(target, sColor, sFgColor, sStyleFont, sStyleBorder, isSelected);
					}
				}
			}

			selectedIndexes = newSelectedIndexes;
		}
	}

	@SuppressWarnings("nls")
	public String getColumnResizeScript()
	{
		if (resizedComponent instanceof IProviderStylePropertyChanges)
		{
			String tableId = getMarkupId();
			String classId = resizedComponent.getId();
			String sWidth = (String)((IProviderStylePropertyChanges)resizedComponent).getStylePropertyChanges().getChanges().get("width"); //$NON-NLS-1$
			if (sWidth != null)
			{
				resizedComponent = null;
				return new AppendingStringBuffer("Servoy.TableView.setTableColumnWidth('").append(tableId).append("', '").append(classId).append("', ").append(
					Integer.parseInt(sWidth.substring(0, sWidth.length() - 2))).append(")").toString();
			}
		}

		return null;
	}

	private List<Integer> getIndexToUpdate(boolean allCurrentPageIndexes)
	{
		if (allCurrentPageIndexes)
		{
			List<Integer> _selectedIndexes = new ArrayList<Integer>();
			int firstRow = table.isPageableMode() ? table.getCurrentPage() * table.getRowsPerPage() : table.getStartIndex();
			int lastRow = firstRow + table.getViewSize() - 1;
			for (int index = firstRow; index <= lastRow; index++)
			{
				_selectedIndexes.add(Integer.valueOf(index));
			}
			return _selectedIndexes;
		}
		else
		{

			if (currentData == null) return null;

			List<Integer> indexesToUpdate = new ArrayList<Integer>();
			List<Integer> oldSelectedIndexes = new ArrayList<Integer>();
			List<Integer> newSelectedIndexesA = new ArrayList<Integer>();
			if (selectedIndexes != null)
			{
				for (int oldSelected : selectedIndexes)
					oldSelectedIndexes.add(new Integer(oldSelected));
			}

			int[] newSelectedIndexes = getSelectedIndexes();
			for (int sel : newSelectedIndexes)
			{
				Integer selection = new Integer(sel);
				newSelectedIndexesA.add(selection);
				// add new selection
				if (oldSelectedIndexes.indexOf(selection) == -1) indexesToUpdate.add(selection);
			}

			for (int sel : oldSelectedIndexes)
			{
				Integer selection = new Integer(sel);
				// add removed selection
				if (newSelectedIndexesA.indexOf(selection) == -1) indexesToUpdate.add(selection);
			}

			return (indexesToUpdate.size() > 0) ? indexesToUpdate : null;
		}
	}

	private int[] getSelectedIndexes()
	{
		if (currentData instanceof FoundSet) return ((FoundSet)currentData).getSelectedIndexes();
		else return new int[] { currentData.getSelectedIndex() };
	}

	/**
	 * Estimates if, for a given height, the table will need more than one page
	 * to display all data (and thus will need a page navigator).
	 * 
	 * Returns:
	 * - a flag telling if more than one page is needed; 
	 * - the number of max rows that fit in one page;
	 * - the total height in pixels used up by the table.
	 */
	private Pair<Boolean, Pair<Integer, Integer>> needsMoreThanOnePage(int height)
	{
		int reservedHeight = 0;
		if (addHeaders)
		{
			reservedHeight = 20; // extra 20 == the header
		}
		else
		{
			// iphone/mac issue (#185741)
			ClientInfo webClientInfo = Session.get().getClientInfo();
			if (webClientInfo instanceof WebClientInfo && ((WebClientInfo)webClientInfo).getProperties().isBrowserSafari())
			{
				reservedHeight = 5;
			}
		}
		int totalRealHeight = reservedHeight + getOtherFormPartsHeight();

		int maxRows = Math.max((height - reservedHeight) / maxHeight, 1);
		// if only 1px is missing for another row, increase the maxRows;
		// windows web clients does not return accurately the clientHeight property
		if (maxHeight - ((height - reservedHeight) % maxHeight) < 2) maxRows++;

		boolean moreThanOnePage = currentData != null && currentData.getSize() > maxRows;
		if (moreThanOnePage)
		{
			reservedHeight += 20; // the page navigator
			maxRows = Math.max((height - reservedHeight) / maxHeight, 1);
			// if only 1px is missing for another row, increase the maxRows;
			// windows web clients does not return accurately the clientHeight property			
			if (maxHeight - ((height - reservedHeight) % maxHeight) < 2) maxRows++;
		}

		if (currentData != null) totalRealHeight += Math.min(currentData.getSize(), maxRows) * maxHeight;

		Pair<Integer, Integer> heights = new Pair<Integer, Integer>(new Integer(maxRows), new Integer(totalRealHeight));
		return new Pair<Boolean, Pair<Integer, Integer>>(new Boolean(moreThanOnePage), heights);
	}

	private boolean shouldFillAllHorizontalSpace()
	{
		boolean shouldFillAllHorizSpace = false;
		if (cellview instanceof ISupportScrollbars)
		{
			int scrollbars = ((ISupportScrollbars)cellview).getScrollbars();
			if ((scrollbars & ISupportScrollbars.HORIZONTAL_SCROLLBAR_NEVER) == ISupportScrollbars.HORIZONTAL_SCROLLBAR_NEVER)
			{
				for (IPersist element : elementToColumnIdentifierComponent.keySet())
				{
					if (element instanceof ISupportAnchors)
					{
						int anchors = ((ISupportAnchors)element).getAnchors();
						if (((anchors & IAnchorConstants.EAST) != 0) && ((anchors & IAnchorConstants.WEST) != 0))
						{
							shouldFillAllHorizSpace = true;
							break;
						}
					}
				}
			}
		}
		return shouldFillAllHorizSpace;
	}

	/**
	 * Distributes an amount of horizontal free space to some or the columns of the table.
	 * 
	 * Can be called in two situations:
	 * 
	 * 1. When the browser windows is resized.
	 * 
	 * In this case the positive/negative extra space gets distributed to those columns that are
	 * anchored left + right.
	 * 
	 * 2. When a column is resized
	 * 
	 * In this case the positive/negative extra space gets distributed to all other columns,
	 * regardless of their anchoring.
	 * 
	 * In both scenarios the extra space is distributed proportionally to the sizes of the 
	 * involved columns.
	 */
	private void distributeExtraSpace(int delta, int totalWidthToStretch, IPersist dontTouchThis, boolean onlyAnchoredColumns)
	{
		if (totalWidthToStretch == 0) return;

		int consumedDelta = 0;
		IRuntimeComponent lastStretched = null;
		for (IPersist element : elementToColumnIdentifierComponent.keySet())
		{
			boolean distributeToThisColumn = true;
			if (dontTouchThis != null && element.equals(dontTouchThis)) distributeToThisColumn = false;
			if (distributeToThisColumn && onlyAnchoredColumns)
			{
				if (element instanceof ISupportAnchors)
				{
					int anchors = ((ISupportAnchors)element).getAnchors();
					if (((anchors & IAnchorConstants.EAST) == 0) || ((anchors & IAnchorConstants.WEST) == 0)) distributeToThisColumn = false;
				}
				else distributeToThisColumn = false;
			}

			if (distributeToThisColumn)
			{
				Component c = elementToColumnIdentifierComponent.get(element);
				if (c instanceof IScriptableProvider && ((IScriptableProvider)c).getScriptObject() instanceof IRuntimeComponent && c.isVisible())
				{
					IRuntimeComponent ic = (IRuntimeComponent)((IScriptableProvider)c).getScriptObject();
					int thisDelta = delta * ic.getWidth() / totalWidthToStretch;
					consumedDelta += thisDelta;
					int newWidth = ic.getWidth() + thisDelta;

					int height = ic.getHeight();
					Iterator<Component> alreadyAddedComponents = cellToElement.keySet().iterator();
					if (alreadyAddedComponents.hasNext())
					{
						Component firstAddedComponent = alreadyAddedComponents.next();
						if ((firstAddedComponent instanceof IComponent)) height = ((IComponent)firstAddedComponent).getSize().height;
					}
					ic.setSize(newWidth, height);

					lastStretched = ic;
				}
			}
		}
		// we can have some leftover due to rounding errors, just put it into the last stretched column.
		if ((delta - consumedDelta != 0) && (lastStretched != null))
		{
			lastStretched.setSize(lastStretched.getWidth() + delta - consumedDelta, lastStretched.getHeight());
		}

		updateXLocationForColumns(getOrderedHeaders());
	}

	private void distributeExtraSpace()
	{
		int totalDefaultWidth = 0;
		int totalWidthToStretch = 0;
		int stretchedElementsCount = 0;
		for (IPersist element : elementToColumnIdentifierComponent.keySet())
		{
			Object scriptobject = elementToColumnIdentifierComponent.get(element);
			if (!((Component)scriptobject).isVisible()) continue;
			if (scriptobject instanceof IScriptableProvider)
			{
				scriptobject = ((IScriptableProvider)scriptobject).getScriptObject();
			}
			if (scriptobject instanceof IRuntimeComponent)
			{
				int width = ((IRuntimeComponent)scriptobject).getWidth();
				totalDefaultWidth += width;
				if (element instanceof ISupportAnchors)
				{
					int anchors = ((ISupportAnchors)element).getAnchors();
					if (((anchors & IAnchorConstants.EAST) != 0) && ((anchors & IAnchorConstants.WEST) != 0))
					{
						totalWidthToStretch += width;
						stretchedElementsCount++;
					}
				}
			}
		}

		boolean shouldFillAllHorizSpace = shouldFillAllHorizontalSpace();
		if (shouldFillAllHorizSpace)
		{
			if (stretchedElementsCount > 0)
			{
				int delta = bodyWidthHint - totalDefaultWidth;
				distributeExtraSpace(delta, totalWidthToStretch, null, true);
				setHeadersWidth();
			}
		}
	}

	private int getOtherFormPartsHeight()
	{
		int bodyDesignHeight = endY - startY;
		int otherPartsHeight = (cellview instanceof Portal) ? 0 : formDesignHeight - bodyDesignHeight;
		return otherPartsHeight;
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportOnRenderWrapper#getOnRenderComponent()
	 */
	public ISupportOnRenderCallback getOnRenderComponent()
	{
		return dataRendererOnRenderWrapper;
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportOnRenderWrapper#getOnRenderElementType()
	 */
	public String getOnRenderElementType()
	{
		return cellview instanceof Portal ? IRuntimeComponent.PORTAL : IRuntimeComponent.FORM;
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportOnRenderWrapper#getOnRenderToString()
	 */
	public String getOnRenderToString()
	{
		return cellview.toString();
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportOddEvenStyling#getOddStyle()
	 */
	public IStyleRule getRowOddStyle()
	{
		return oddStyle;
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportOddEvenStyling#getEvenStyle()
	 */
	public IStyleRule getRowEvenStyle()
	{
		return evenStyle;
	}

	public void setRowStyles(IStyleSheet styleSheet, IStyleRule oddStyle, IStyleRule evenStyle, IStyleRule selectedStyle, IStyleRule headerStyle)
	{
		this.styleSheet = styleSheet;
		this.oddStyle = oddStyle;
		this.evenStyle = evenStyle;
		this.selectedStyle = selectedStyle;
		this.headerStyle = headerStyle;
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportOddEvenStyling#getStyleSheet()
	 */
	public IStyleSheet getRowStyleSheet()
	{
		return styleSheet;
	}

	/*
	 * @see com.servoy.j2db.ui.ISupportRowStyling#getSelectedStyle()
	 */
	public IStyleRule getRowSelectedStyle()
	{
		return selectedStyle;
	}

	public IStyleRule getHeaderStyle()
	{
		return headerStyle;
	}

	public void setScrollMode(boolean scrollMode)
	{
		this.isScrollMode = scrollMode;
	}

	public boolean isScrollMode()
	{
		return isScrollMode;
	}

	private static String getFirstToken(String s)
	{
		if (s != null)
		{
			StringTokenizer st = new StringTokenizer(s);
			if (st.hasMoreTokens()) return st.nextToken();
		}
		return "";
	}

	private class ScrollBehavior extends ServoyAjaxEventBehavior
	{
		private boolean isGettingRows;

		public ScrollBehavior(String event)
		{
			super(event);
		}

		private static final long serialVersionUID = 1L;

		boolean isGettingRows()
		{
			return isGettingRows;
		}

		@Override
		public void renderHead(IHeaderResponse response)
		{
			super.renderHead(response);
			StringBuffer sb = new StringBuffer();
			sb.append("Servoy.TableView.currentScrollTop['").append(WebCellBasedView.this.tableContainerBody.getMarkupId()).append("'] = 0;"); //$NON-NLS-1$ //$NON-NLS-2$
			sb.append("Servoy.TableView.hasTopBuffer['").append(WebCellBasedView.this.tableContainerBody.getMarkupId()).append("'] = false;"); //$NON-NLS-1$ //$NON-NLS-2$
			sb.append("Servoy.TableView.hasBottomBuffer['").append(WebCellBasedView.this.tableContainerBody.getMarkupId()).append("'] = true;"); //$NON-NLS-1$ //$NON-NLS-2$
			sb.append("Servoy.TableView.keepLoadedRows = " + isKeepLoadedRowsInScrollMode + ";"); //$NON-NLS-1$ //$NON-NLS-2$
			sb.append("Servoy.TableView.scrollToTop('").append(WebCellBasedView.this.tableContainerBody.getMarkupId()).append("');"); //$NON-NLS-1$ //$NON-NLS-2$
			response.renderOnDomReadyJavascript(sb.toString());

		}

		@Override
		protected void onEvent(AjaxRequestTarget target)
		{
			int scrollDiff = Utils.getAsInteger(RequestCycle.get().getRequest().getParameter("scrollDiff")); //$NON-NLS-1$

			Collection<ListItem< ? >> newRows = null;
			StringBuffer rowsBuffer = null;
			int newRowsCount = 0, rowsToRemove = 0;
			int viewStartIdx = table.getStartIndex();
			int viewSize = table.getViewSize();
			int pageViewSize = 3 * maxRowsPerPage;

			if (scrollDiff > 0)
			{
				int tableSize = table.getList().size();

				if (viewStartIdx + viewSize < tableSize)
				{
					newRowsCount = Math.min(2 * maxRowsPerPage, tableSize - (viewStartIdx + viewSize));
					if (!isKeepLoadedRowsInScrollMode && viewSize > pageViewSize) rowsToRemove = maxRowsPerPage;

					table.setStartIndex(viewStartIdx + rowsToRemove);
					table.setViewSize(viewSize + newRowsCount - rowsToRemove);
					newRows = getRows(table, viewStartIdx + viewSize, newRowsCount);
					rowsBuffer = renderRows(getResponse(), newRows);
				}
			}
			else
			{
				if (viewStartIdx > 0)
				{
					newRowsCount = Math.min(Math.max(Math.abs(scrollDiff), maxRowsPerPage), viewStartIdx);

					table.setStartIndex(viewStartIdx - newRowsCount);
					if (newRowsCount > pageViewSize)
					{
						rowsToRemove = -1; // remove all
						newRows = getRows(table, viewStartIdx - newRowsCount, viewSize);
					}
					else
					{
						if (viewSize > pageViewSize) rowsToRemove = maxRowsPerPage;
						table.setViewSize(viewSize + newRowsCount - rowsToRemove);
						newRows = getRows(table, viewStartIdx - newRowsCount, newRowsCount);
					}

					rowsBuffer = renderRows(getResponse(), newRows);
				}
			}

			if (rowsBuffer != null)
			{
				boolean hasTopBuffer = table.getStartIndex() > 0;
				boolean hasBottomBuffer = table.getStartIndex() + table.getViewSize() < table.getList().size();

				StringBuffer sb = new StringBuffer();
				sb.append("Servoy.TableView.appendRows('"); //$NON-NLS-1$
				sb.append(WebCellBasedView.this.tableContainerBody.getMarkupId()).append("','"); //$NON-NLS-1$
				sb.append(rowsBuffer.toString()).append("',"); //$NON-NLS-1$
				sb.append(newRowsCount).append(","); //$NON-NLS-1$
				sb.append(rowsToRemove).append(","); //$NON-NLS-1$
				sb.append(scrollDiff).append(", "); //$NON-NLS-1$
				sb.append(hasTopBuffer).append(","); //$NON-NLS-1$
				sb.append(hasBottomBuffer).append(");"); //$NON-NLS-1$

				if (newRows != null)
				{
					Page page = findPage();
					if (page instanceof MainPage)
					{
						PageContributor pc = (PageContributor)((MainPage)page).getPageContributor();
						sb.append(pc.getListenersScript(getRowsComponents(newRows)));
					}
				}

				target.appendJavascript(sb.toString());
			}
		}

		@Override
		protected CharSequence generateCallbackScript(final CharSequence partialCall)
		{
			return super.generateCallbackScript(partialCall + "+'&scrollDiff='+scrollDiff"); //$NON-NLS-1$
		}

		@Override
		protected IAjaxCallDecorator getAjaxCallDecorator()
		{
			return new AjaxPostprocessingCallDecorator(null)
			{
				private static final long serialVersionUID = 1L;

				@SuppressWarnings("nls")
				@Override
				public CharSequence postDecorateScript(CharSequence script)
				{
					StringBuilder scriptBuilder = new StringBuilder();
					if (WebCellBasedView.this.headers != null)
					{
						scriptBuilder.append("Servoy.TableView.scrollHeader('");
						scriptBuilder.append(WebCellBasedView.this.headers.getMarkupId());
						scriptBuilder.append("', '");
						scriptBuilder.append(WebCellBasedView.this.tableContainerBody.getMarkupId());
						scriptBuilder.append("');");
					}

					scriptBuilder.append("clearTimeout(Servoy.TableView.appendRowsTimer); Servoy.TableView.appendRowsTimer = setTimeout(\"var scrollDiff = Servoy.TableView.needToUpdateRowsBuffer('");
					scriptBuilder.append(WebCellBasedView.this.tableContainerBody.getMarkupId());
					scriptBuilder.append("'); if (scrollDiff != 0) { ");
					scriptBuilder.append(script);
					scriptBuilder.append("};\", 500);");

					return scriptBuilder.toString();
				}
			};
		}

		private Collection<Component> getRowsComponents(Collection<ListItem< ? >> rows)
		{
			ArrayList<Component> rowsComponents = new ArrayList<Component>();

			Iterator<ListItem< ? >> rowsIte = rows.iterator();
			while (rowsIte.hasNext())
			{
				rowsComponents.addAll(getRowComponents(rowsIte.next()));
			}

			return rowsComponents;
		}

		private Collection<Component> getRowComponents(ListItem< ? > row)
		{
			final ArrayList<Component> rowComponents = new ArrayList<Component>();

			row.visitChildren(IComponent.class, new IVisitor<Component>()
			{

				public Object component(Component component)
				{
					rowComponents.add(component);
					return IVisitor.CONTINUE_TRAVERSAL;
				}

			});
			return rowComponents;
		}

		private Collection<ListItem< ? >> getRows(WebCellBasedViewListView listView, int startIdx, int rowsCount)
		{
			ArrayList<ListItem< ? >> rows = new ArrayList<ListItem< ? >>();

			int endIdx = startIdx + rowsCount;
			ListItem< ? > listItem;
			isGettingRows = true;
			for (int i = startIdx; i < endIdx; i++)
			{
				listItem = listView.getOrCreateListItem(i);
				rows.add(listItem);
			}
			isGettingRows = false;

			return rows;
		}

		private StringBuffer renderRows(Response response, Collection<ListItem< ? >> rows)
		{
			StringBuffer output = new StringBuffer();
			Iterator<ListItem< ? >> rowsIte = rows.iterator();
			while (rowsIte.hasNext())
			{
				output.append(renderComponent(response, rowsIte.next()));
			}

			return output;
		}

		private CharSequence renderComponent(Response response, Component component)
		{
			StringResponse stringResponse = new StringResponse();

			RequestCycle.get().setResponse(stringResponse);

			// Initialize temporary variables
			final Page page = component.findParent(Page.class);
			if (page == null)
			{
				//					// dont throw an exception but just ignore this component, somehow
				//					// it got removed from the page.
				//					log.debug("component: " + component + " with markupid: " + markupId +
				//						" not rendered because it was already removed from page");
				return null;
			}

			page.startComponentRender(component);

			try
			{
				component.prepareForRender();
			}
			catch (RuntimeException e)
			{
				try
				{
					component.afterRender();
				}
				catch (RuntimeException e2)
				{
					// ignore this one could be a result off.
				}
				// Restore original response
				RequestCycle.get().setResponse(response);
				throw e;
			}

			try
			{
				component.renderComponent();
			}
			catch (RuntimeException e)
			{
				RequestCycle.get().setResponse(response);
				throw e;
			}

			page.endComponentRender(component);

			// Restore original response
			RequestCycle.get().setResponse(response);

			String s = stringResponse.getBuffer().toString();
			s = s.replace("\r", ""); //$NON-NLS-1$ //$NON-NLS-2$
			s = s.replace("\n", ""); //$NON-NLS-1$ //$NON-NLS-2$
			s = s.replace("\t", ""); //$NON-NLS-1$ //$NON-NLS-2$
			s = s.replace("\\", "\\\\"); //$NON-NLS-1$ //$NON-NLS-2$
			s = s.replace("\'", "\\\'"); //$NON-NLS-1$ //$NON-NLS-2$

			return s;
		}
	}
}

class FindStateItemModel extends RecordItemModel
{

	private final IRecordInternal record;

	public FindStateItemModel(IRecordInternal r)
	{
		record = r;
	}

	@Override
	protected IRecordInternal getRecord()
	{
		return record;
	}

}

class FoundsetRecordItemModel extends RecordItemModel
{
	private static final long serialVersionUID = 1L;

	private transient IRecordInternal record;//we need to keep reference since pk can change

	/** The ListView's list model */
	private final ListView<IRecordInternal> listView;

	/* The list item's index */
	private final Object[] pk;

	private final int index;

	/**
	 * @param listView The ListView
	 * @param index 
	 * @param pk The pk of the record that must be shown
	 */
	public FoundsetRecordItemModel(ListView<IRecordInternal> listView, IRecordInternal r, int index)
	{
		super();
		record = r;
		this.pk = record.getPK();
		this.listView = listView;
		this.index = index;
	}

	public int getRowIndex()
	{
		return index;
	}

	/**
	 * @see com.servoy.j2db.server.headlessclient.dataui.RecordItemModel#getRecord()
	 */
	@Override
	protected IRecordInternal getRecord()
	{
		if (record == null)
		{
			// Re-attach the model object based on index and ListView model object
			Object object = listView.getModelObject();
			if (object instanceof FoundSetListWrapper)
			{
				record = ((FoundSetListWrapper)object).getRecord(pk);
			}
		}
		return record;
	}
}