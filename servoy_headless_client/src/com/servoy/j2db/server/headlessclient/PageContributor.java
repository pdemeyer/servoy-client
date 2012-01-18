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
package com.servoy.j2db.server.headlessclient;

import java.awt.Rectangle;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.SortedSet;

import org.apache.wicket.AttributeModifier;
import org.apache.wicket.Component;
import org.apache.wicket.MarkupContainer;
import org.apache.wicket.Page;
import org.apache.wicket.RequestCycle;
import org.apache.wicket.ResourceReference;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.AjaxRequestTarget.IJavascriptResponse;
import org.apache.wicket.behavior.IBehavior;
import org.apache.wicket.markup.MarkupStream;
import org.apache.wicket.markup.html.IHeaderResponse;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.internal.HtmlHeaderContainer;
import org.apache.wicket.markup.html.resources.JavascriptResourceReference;
import org.apache.wicket.model.Model;
import org.apache.wicket.protocol.http.WebRequest;

import com.servoy.j2db.IApplication;
import com.servoy.j2db.server.headlessclient.dataui.AbstractServoyDefaultAjaxBehavior;
import com.servoy.j2db.server.headlessclient.dataui.ChangesRecorder;
import com.servoy.j2db.server.headlessclient.dataui.WebBaseLabel;
import com.servoy.j2db.server.headlessclient.dataui.WebCellBasedView;
import com.servoy.j2db.server.headlessclient.dataui.WebDataCheckBoxChoice;
import com.servoy.j2db.server.headlessclient.dataui.WebDataRadioChoice;
import com.servoy.j2db.server.headlessclient.dataui.WebEventExecutor;
import com.servoy.j2db.server.headlessclient.eventthread.IEventDispatcher;
import com.servoy.j2db.ui.IComponent;
import com.servoy.j2db.ui.IFieldComponent;
import com.servoy.j2db.ui.IProviderStylePropertyChanges;
import com.servoy.j2db.ui.IStylePropertyChanges;
import com.servoy.j2db.ui.ISupportOnRenderCallback;
import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.OrientationApplier;
import com.servoy.j2db.util.Pair;
import com.servoy.j2db.util.Utils;

/**
 * Implementation of {@link IPageContributorInternal} that is a wicket component that is added to the page for adding all kinds of behaviors and scripts to the main page.
 * 
 * @author jcompagner
 */
public class PageContributor extends WebMarkupContainer implements IPageContributorInternal
{
	private static final long serialVersionUID = 1L;
	public static final ResourceReference anchorlayout = new JavascriptResourceReference(PageContributor.class, "anchorlayout.js"); //$NON-NLS-1$

	private IRepeatingView repeatingView;

	private final Map<String, IBehavior> behaviors = new HashMap<String, IBehavior>();

	private final EventCallbackBehavior eventCallbackBehavior;

	private StringBuffer dynamicJS;
	protected ChangesRecorder jsChangeRecorder = new ChangesRecorder(null, null);

	private long lastTableUpdate = -1;
	private final List<Component> tablesToRender = new ArrayList<Component>();
	private SortedSet<FormAnchorInfo> formAnchorInfos;
	private boolean anchorInfoChanged = false;
	private StringBuffer componentsThatNeedAnchorRelayout;
	private boolean isResizing = false;
	private final Map<String, Pair<List<String>, Boolean>> eventMarkupIds = new HashMap<String, Pair<List<String>, Boolean>>();
	private final Map<String, IEventCallback> eventCallback = new HashMap<String, IEventCallback>();

	private final IApplication application;

	public PageContributor(final IApplication application, String id)
	{
		super(id, new Model());
		this.application = application;
		setOutputMarkupPlaceholderTag(true);

		add(new AbstractServoyDefaultAjaxBehavior()
		{
			private static final long serialVersionUID = 1L;

			@Override
			protected void respond(AjaxRequestTarget target)
			{
				String update = getRequestCycle().getRequest().getParameter("update"); //$NON-NLS-1$
				// get the update parameter and check if that is still the same, else wait for the next.
				if (Long.parseLong(update) == lastTableUpdate)
				{
					for (int i = 0; i < tablesToRender.size(); i++)
					{
						Component comp = tablesToRender.get(i);
						if (comp.isVisibleInHierarchy())
						{
							target.addComponent(comp);
						}
					}
					tablesToRender.clear();
					WebEventExecutor.generateResponse(target, findPage());
				}
				else
				{
					Debug.log("IGNORED TABLE REQUEST");
				}
			}

			@Override
			public void renderHead(IHeaderResponse response)
			{
				super.renderHead(response);
				response.renderOnDomReadyJavascript(getCallbackScript().toString());
			}

			@Override
			public CharSequence getCallbackUrl(boolean onlyTargetActivePage)
			{
				CharSequence url = super.getCallbackUrl(true);
				url = url + "&update=" + lastTableUpdate; //$NON-NLS-1$
				return url;
			}

			@Override
			public boolean isEnabled(Component component)
			{
				return tablesToRender.size() > 0 && super.isEnabled(component);
			}
		});
		add(new AbstractServoyDefaultAjaxBehavior()
		{
			private static final long serialVersionUID = 1L;
			private DelayedDialog localCopy;

			@Override
			protected void respond(AjaxRequestTarget target)
			{
				if (localCopy != null)
				{
					((WebFormManager)application.getFormManager()).showDelayedFormInDialog(localCopy.type, localCopy.formName, localCopy.r, localCopy.title,
						localCopy.resizeble, localCopy.showTextToolbar, localCopy.closeAll, localCopy.modal, localCopy.dialogName);
					localCopy = null;
					WebEventExecutor.generateResponse(target, findPage());
				}
			}

			@Override
			public void renderHead(IHeaderResponse response)
			{
				super.renderHead(response);
				response.renderOnDomReadyJavascript(getCallbackScript().toString());
			}

			@Override
			public boolean isEnabled(Component component)
			{
				if (super.isEnabled(component))
				{
					if (delayedDialog != null)
					{
						localCopy = delayedDialog.duplicate();
						delayedDialog = null;
					}
					return localCopy != null;
				}
				return false;
			}
		});
		add(eventCallbackBehavior = new EventCallbackBehavior());
	}

	@Override
	public void renderHead(HtmlHeaderContainer container)
	{
		super.renderHead(container);

		IHeaderResponse response = container.getHeaderResponse();

		String djs = getDynamicJavaScript();
		if (djs != null)
		{
			response.renderOnLoadJavascript(djs);
		}
		Page page = findPage();
		if (page instanceof MainPage)
		{
			Component focus = ((MainPage)page).getAndResetToFocusComponent();
			if (focus != null)
			{
				response.renderOnLoadJavascript("setTimeout(\"requestFocus('" + focus.getMarkupId() + "');\",0);"); //$NON-NLS-1$ //$NON-NLS-2$
			}
		}


		if (formAnchorInfos != null && formAnchorInfos.size() != 0 && WebClientSession.get() != null &&
			Utils.getAsBoolean(WebClientSession.get().getWebClient().getRuntimeProperties().get("enableAnchors"))) //$NON-NLS-1$
		{

			if (anchorInfoChanged)
			{
				response.renderJavascriptReference(anchorlayout);
				response.renderOnLoadJavascript("setTimeout(\"layoutEntirePage();\", 10);"); // setTimeout is important here, to let the browser apply CSS styles during Ajax calls //$NON-NLS-1$
				String sb = FormAnchorInfo.generateAnchoringFunctions(formAnchorInfos, getOrientation());
				response.renderJavascript(sb, null);
				anchorInfoChanged = false;
			}
			else if (componentsThatNeedAnchorRelayout != null && componentsThatNeedAnchorRelayout.length() > 0)
			{
				response.renderJavascriptReference(anchorlayout);
				response.renderOnLoadJavascript("setTimeout(\"layoutSpecificElements();\", 10);");
				response.renderJavascript("executeLayoutSpecificElements = function()\n{\n" + componentsThatNeedAnchorRelayout.append("\n}"), null);
			}
		}
		if (componentsThatNeedAnchorRelayout != null) componentsThatNeedAnchorRelayout.setLength(0);

		// Enable this for Firebug debugging under IE/Safari/etc.
		//response.renderJavascriptReference("http://getfirebug.com/releases/lite/1.2/firebug-lite-compressed.js"); //$NON-NLS-1$
	}

	private String getOrientation()
	{
		String orientation = OrientationApplier.getHTMLContainerOrientation(application.getLocale(), application.getSolution().getTextOrientation());
		if (orientation.equals(AttributeModifier.VALUELESS_ATTRIBUTE_REMOVE)) orientation = "ltr"; //$NON-NLS-1$
		return orientation;
	}

	public void setFormAnchorInfos(SortedSet<FormAnchorInfo> infos, boolean onlyChanged)
	{
		anchorInfoChanged = !Utils.equalObjects(formAnchorInfos, infos);
		if (infos == null)
		{
			formAnchorInfos = null;
		}
		else
		{
			if (!onlyChanged || !infos.equals(formAnchorInfos))
			{
				if (!isResizing) getStylePropertyChanges().setChanged();
				formAnchorInfos = infos;
			}
		}
	}

	public void markComponentForAnchorLayoutIfNeeded(Component component)
	{
		if (formAnchorInfos != null && formAnchorInfos.size() != 0)
		{
			// see if this component is actually affected by layout or not and generate anchoring properties for it if it is
			String s = FormAnchorInfo.generateAnchoringParams(formAnchorInfos, component);
			if (s != null)
			{
				if (componentsThatNeedAnchorRelayout == null) componentsThatNeedAnchorRelayout = new StringBuffer();
				componentsThatNeedAnchorRelayout.append("layoutOneElement(").append(s).append(");\n");
				getStylePropertyChanges().setChanged();
			}
		}
	}

	public void setResizing(boolean b)
	{
		isResizing = b;
	}

	public void setEventListeners(String event, List<String> markupIds, IEventCallback callback, boolean post)
	{
		Pair<List<String>, Boolean> pair = new Pair<List<String>, Boolean>(markupIds, Boolean.valueOf(post));
		boolean equals = pair.equals(eventMarkupIds.get(event));
		if (markupIds != null && markupIds.size() != 0 && !equals)
		{
			Pair<List<String>, Boolean> old = eventMarkupIds.get(event);
			if (old != null && old.getLeft().size() != 0 && !equals)
			{
				Debug.trace("Overwriting event listeners not for event '" + event + "'"); //$NON-NLS-1$ //$NON-NLS-2$
			}
			getStylePropertyChanges().setChanged();
			eventMarkupIds.put(event, pair);
			eventCallback.put(event, callback);
		}
	}

	private DelayedDialog delayedDialog = null;

	public void showFormInDialogDelayed(int type, String formName, Rectangle r, String title2, boolean resizeble, boolean showTextToolbar, boolean closeAll,
		boolean modal, String dialogName)
	{
		delayedDialog = new DelayedDialog(type, formName, r, title2, resizeble, showTextToolbar, closeAll, modal, dialogName);
		getStylePropertyChanges().setChanged();
	}

	public void showNoDialog()
	{
		delayedDialog = null;
	}

	public void addTableToRender(Component comp)
	{
		getStylePropertyChanges().setChanged();
		if (!tablesToRender.contains(comp)) tablesToRender.add(comp);
		lastTableUpdate = System.currentTimeMillis();
	}

	public void addBehavior(String name, IBehavior behavior)
	{
		if (behaviors.put(name, behavior) == null)
		{
			getStylePropertyChanges().setChanged();
			add(behavior);
		}
	}

	public void removeBehavior(String name)
	{
		IBehavior behavior = null;
		if ((behavior = behaviors.remove(name)) != null)
		{
			getStylePropertyChanges().setChanged();
			remove(behavior);
		}
	}

	public void addDynamicJavaScript(String js)
	{
		if (dynamicJS == null) dynamicJS = new StringBuffer();
		dynamicJS.append(js);
		getStylePropertyChanges().setChanged();
	}

	private String getDynamicJavaScript()
	{
		String retval = null;
		if (dynamicJS != null) retval = dynamicJS.toString();
		dynamicJS = null;
		return retval;
	}

	public IBehavior getBehavior(String name)
	{
		return behaviors.get(name);
	}

	public IStylePropertyChanges getStylePropertyChanges()
	{
		return jsChangeRecorder;
	}

	@Override
	protected void onRender(MarkupStream markupStream)
	{
		super.onRender(markupStream);
		getStylePropertyChanges().setRendered();
	}

	public static List<Component> getVisibleChildren(Component component, final boolean onlyChanged)
	{
		final List<Component> visibleChildren = new ArrayList<Component>();
		if (component.isVisibleInHierarchy() &&
			(!onlyChanged || (component instanceof IProviderStylePropertyChanges && ((IProviderStylePropertyChanges)component).getStylePropertyChanges().isChanged())))
		{
			visibleChildren.add(component);
		}
		if (component instanceof MarkupContainer)
		{
			((MarkupContainer)component).visitChildren(IProviderStylePropertyChanges.class, new IVisitor<Component>()
			{
				public Object component(Component stylePropertyChange)
				{
					if (!stylePropertyChange.isVisibleInHierarchy())
					{
						return IVisitor.CONTINUE_TRAVERSAL_BUT_DONT_GO_DEEPER;
					}
					if (onlyChanged && !((IProviderStylePropertyChanges)stylePropertyChange).getStylePropertyChanges().isChanged())
					{
						return IVisitor.CONTINUE_TRAVERSAL;
					}
					visibleChildren.add(stylePropertyChange);
					// add all children from here
					if (stylePropertyChange instanceof MarkupContainer)
					{
						((MarkupContainer)stylePropertyChange).visitChildren(IComponent.class, new IVisitor<Component>()
						{
							public Object component(Component fieldComponent)
							{
								if (!fieldComponent.isVisibleInHierarchy())
								{
									return IVisitor.CONTINUE_TRAVERSAL_BUT_DONT_GO_DEEPER;
								}
								visibleChildren.add(fieldComponent);
								return IVisitor.CONTINUE_TRAVERSAL;
							}
						});
					}
					return IVisitor.CONTINUE_TRAVERSAL_BUT_DONT_GO_DEEPER;
				}
			});
		}
		return visibleChildren;
	}

	/**
	 * Called when all components have been rendered. The map contains the rendered components.
	 */
	public void onAfterRespond(Map<String, Component> map, IJavascriptResponse response)
	{
		response.addJavascript(getListenersScript(map.values()));
	}

	public String getListenersScript(Collection<Component> components)
	{
		// find all field components that will be re-rendered, look for children because some may have been added during 
		// rendering (for example, extra rows in table view)
		final List<String> focusGainedFields = new ArrayList<String>();
		final List<String> focusLostFields = new ArrayList<String>();

		for (Object comp : components)
		{
			for (Component c : getVisibleChildren((Component)comp, false))
			{
				addComponentToEventListWhenNeeded(c, focusGainedFields, focusLostFields);
			}
		}
		MainPage mainPage = (MainPage)findPage();
		if (!eventCallback.containsKey("focus")) setEventListeners("focus", focusGainedFields, mainPage, false); //$NON-NLS-1$ //$NON-NLS-2$
		if (!eventCallback.containsKey("blur")) setEventListeners("blur", focusLostFields, mainPage, true /* handle changed data */); //$NON-NLS-1$ //$NON-NLS-2$

		Map<String, Pair<List<String>, Boolean>> markupIdMap = new HashMap<String, Pair<List<String>, Boolean>>();
		markupIdMap.put("focus", new Pair<List<String>, Boolean>(focusGainedFields, Boolean.FALSE)); //$NON-NLS-1$
		markupIdMap.put("blur", new Pair<List<String>, Boolean>(focusLostFields, Boolean.TRUE /* handle changed data */)); //$NON-NLS-1$

		String js = eventCallbackBehavior.getAddListsenersScript(markupIdMap);
		if (components.size() > 0 && components.iterator().next().findParent(WebCellBasedView.class) != null)
		{
			// in tableview non changed fields can be replaced with ajax causing focus event to come twice
			js = "setTimeout(function(){" + js + "},100)";
		}

		return js;
	}

	public void onBeforeRespond(Map<String, Component> map, AjaxRequestTarget target)
	{
	}

	public void addFocusEventListeners(MainPage mainPage)
	{
		final List<String> focusGainedFields = new ArrayList<String>();
		final List<String> focusLostFields = new ArrayList<String>();
		// find all field components that will be re-rendered
		for (Component component : getVisibleChildren(mainPage, false))
		{
			addComponentToEventListWhenNeeded(component, focusGainedFields, focusLostFields);
		}
		setEventListeners("focus", focusGainedFields, mainPage, false); //$NON-NLS-1$
		setEventListeners("blur", focusLostFields, mainPage, true /* handle changed data */); //$NON-NLS-1$
	}


	private static void addComponentToEventListWhenNeeded(Component c, List<String> focusGainedFields, List<String> focusLostFields)
	{
		if (!c.isEnabled()) return;
		if (c instanceof IFieldComponent && ((IFieldComponent)c).getEventExecutor() != null)
		{
			// Skip RadioChoice and CheckboxChoice, they are inside <div>s and does not really 
			// make sense to fire on blur/focus gain.
			if (!(c instanceof WebDataRadioChoice || c instanceof WebDataCheckBoxChoice))
			{
				// always install a focus handler when in a table view to detect change of selectedIndex and test for record validation
				if (((IFieldComponent)c).getEventExecutor().hasEnterCmds() ||
					c.findParent(WebCellBasedView.class) != null ||
					(((IFieldComponent)c).getScriptObject() instanceof ISupportOnRenderCallback && ((ISupportOnRenderCallback)((IFieldComponent)c).getScriptObject()).getRenderEventExecutor().hasRenderCallback()))
				{
					focusGainedFields.add(c.getMarkupId());
				}
				// Always trigger event on focus lost:
				// 1) check for new selected index, record validation may have failed preventing a index changed
				// 2) prevent focus gained to be called when field validation failed
				// 3) general ondata change
				focusLostFields.add(c.getMarkupId());
			}
		}
		else if (c instanceof WebBaseLabel)
		{
			focusGainedFields.add(c.getMarkupId());
		}
	}

	private class EventCallbackBehavior extends AbstractServoyDefaultAjaxBehavior
	{
		private static final long serialVersionUID = 1L;

		@Override
		protected void respond(final AjaxRequestTarget target)
		{
			if (Debug.tracing()) Debug.trace("Event response callback " + getRequestCycle().getRequest().getURL()); //$NON-NLS-1$
			final String markupId = getRequestCycle().getRequest().getParameter("id"); //$NON-NLS-1$
			final String event = getRequestCycle().getRequest().getParameter("event"); //$NON-NLS-1$
			if (markupId != null && event != null)
			{
				final IEventCallback callback = eventCallback.get(event);
				if (callback == null)
				{
					Debug.trace("Callback handler not found, event=" + event + " id=" + markupId); //$NON-NLS-1$ //$NON-NLS-2$
				}
				else
				{
					IEventDispatcher eventDispatcher = ((WebClient)application).getEventDispatcher();
					if (eventDispatcher != null)
					{
						eventDispatcher.addEvent(new Runnable()
						{
							public void run()
							{
								callback.respond(target, event, markupId);
							}
						});
						WebEventExecutor.generateResponse(target, getPage());
					}
					else
					{
						callback.respond(target, event, markupId);
					}
				}
			}
			else
			{
				Debug.error("Missing id or event parameter in callback " + getRequestCycle().getRequest().getURL()); //$NON-NLS-1$
			}
		}

		@Override
		public void renderHead(IHeaderResponse response)
		{
			super.renderHead(response);
			// if it's ajax request it is already sent via onAfterRespond
			if (!((WebRequest)RequestCycle.get().getRequest()).isAjax() && !eventMarkupIds.isEmpty())
			{
				response.renderOnLoadJavascript(getAddListsenersScript(eventMarkupIds));
				eventMarkupIds.clear();
			}
		}

		@Override
		public CharSequence getCallbackUrl(boolean onlyTargetActivePage)
		{
			return super.getCallbackUrl(true);
		}


		public String getAddListsenersScript(Map<String, Pair<List<String>, Boolean>> markupIdMap)
		{
			if (markupIdMap == null || markupIdMap.isEmpty())
			{
				return null;
			}
			// function addListeners(strEvent, callbackUrl, ids, post)
			StringBuffer js = new StringBuffer();
			js.append("var cb='").append(getCallbackUrl()).append('\''); //$NON-NLS-1$
			for (Entry<String, Pair<List<String>, Boolean>> entry : markupIdMap.entrySet())
			{
				Pair<List<String>, Boolean> pair = entry.getValue();
				List<String> ids = pair.getLeft();
				if (!ids.isEmpty())
				{
					js.append(";\naddListeners('"); //$NON-NLS-1$
					js.append(entry.getKey());
					js.append("',cb,");//$NON-NLS-1$
					for (int i = 0; i < ids.size(); i++)
					{
						js.append((i == 0) ? '[' : ',');
						js.append('\'');
						js.append(ids.get(i));
						js.append('\'');
					}
					js.append("],").append(pair.getRight().booleanValue()).append(')');//$NON-NLS-1$
				}
			}
			return js.toString();
		}

	}

	public class DelayedDialog implements Serializable
	{
		private final int type;
		private final String formName;
		private final Rectangle r;
		private final String title;
		private final boolean resizeble;
		private final boolean showTextToolbar;
		private final boolean closeAll;
		private final boolean modal;
		private final String dialogName;

		public DelayedDialog(int type, String formName, Rectangle r, String title, boolean resizeble, boolean showTextToolbar, boolean closeAll, boolean modal,
			String dialogName)
		{
			this.type = type;
			this.formName = formName;
			this.r = r;
			this.title = title;
			this.resizeble = resizeble;
			this.showTextToolbar = showTextToolbar;
			this.closeAll = closeAll;
			this.modal = modal;
			this.dialogName = dialogName;
		}


		public DelayedDialog duplicate()
		{
			return new DelayedDialog(type, formName, r, title, resizeble, showTextToolbar, closeAll, modal, dialogName);
		}
	}

	/**
	 * @param container
	 */
	public void addRepeatingView(IRepeatingView rp)
	{
		this.repeatingView = rp;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.servoy.j2db.server.headlessclient.IPageContributor#getRepeatingView()
	 */
	public IRepeatingView getRepeatingView()
	{
		return repeatingView;
	}
	
}
