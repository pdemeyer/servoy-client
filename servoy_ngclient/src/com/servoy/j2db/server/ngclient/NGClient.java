package com.servoy.j2db.server.ngclient;

import java.awt.Dimension;
import java.awt.print.PageFormat;
import java.io.IOException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.TimeZone;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.FutureTask;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import org.json.JSONArray;

import com.servoy.j2db.IApplication;
import com.servoy.j2db.IBasicFormManager;
import com.servoy.j2db.IDataRendererFactory;
import com.servoy.j2db.IFormController;
import com.servoy.j2db.IServiceProvider;
import com.servoy.j2db.J2DBGlobals;
import com.servoy.j2db.Messages;
import com.servoy.j2db.dataprocessing.FoundSetManager;
import com.servoy.j2db.dataprocessing.SwingFoundSetFactory;
import com.servoy.j2db.persistence.RepositoryException;
import com.servoy.j2db.persistence.Solution;
import com.servoy.j2db.persistence.SolutionMetaData;
import com.servoy.j2db.server.headlessclient.AbstractApplication;
import com.servoy.j2db.server.headlessclient.eventthread.IEventDispatcher;
import com.servoy.j2db.server.ngclient.eventthread.EventDispatcher;
import com.servoy.j2db.server.ngclient.eventthread.NGEvent;
import com.servoy.j2db.server.shared.ApplicationServerRegistry;
import com.servoy.j2db.server.shared.IApplicationServer;
import com.servoy.j2db.server.shared.WebCredentials;
import com.servoy.j2db.ui.ItemFactory;
import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.RendererParentWrapper;
import com.servoy.j2db.util.ServoyScheduledExecutor;
import com.servoy.j2db.util.Settings;

// TODO we should add a subclass between ClientState and SessionClient, (remove all "session" and wicket related stuff out of SessionClient)
// then we can extend that one.
public class NGClient extends AbstractApplication implements INGApplication, IChangeListener
{
	private static final long serialVersionUID = 1L;

	private final INGClientWebsocketSession wsSession;

	private IEventDispatcher<NGEvent> executor;

	private transient volatile ServoyScheduledExecutor scheduledExecutorService;

	private NGRuntimeWindowManager runtimeWindowManager;

	private Map<Object, Object> uiProperties;


	public NGClient(INGClientWebsocketSession wsSession)
	{
		super(new WebCredentials());
		this.wsSession = wsSession;
		settings = Settings.getInstance();
		try
		{
			applicationSetup();
			applicationInit();
			applicationServerInit();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			Debug.error(e);
		}
	}


	public void loadSolution(String solutionName) throws RepositoryException
	{
		try
		{
			SolutionMetaData solutionMetaData = getApplicationServer().getSolutionDefinition(solutionName, getSolutionTypeFilter());
			if (solutionMetaData == null)
			{
				throw new IllegalArgumentException(Messages.getString("servoy.exception.solutionNotFound", new Object[] { solutionName })); //$NON-NLS-1$
			}
			loadSolution(solutionMetaData);
		}
		catch (RemoteException e)
		{
			throw new RepositoryException(e);
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.servoy.j2db.ClientState#getFormManager()
	 */
	@Override
	public INGFormManager getFormManager()
	{
		return (INGFormManager)super.getFormManager();
	}

	public Map<String, Map<String, Map<String, Object>>> getChanges()
	{
		Map<String, Map<String, Map<String, Object>>> changes = new HashMap<>(8);

		for (IFormController fc : getFormManager().getCachedFormControllers())
		{
			if (fc.isFormVisible())
			{
				Map<String, Map<String, Object>> formChanges = ((WebFormUI)fc.getFormUI()).getAllChanges();
				if (formChanges.size() > 0)
				{
					changes.put(fc.getName(), formChanges);
				}
			}
		}
		return changes;
	}

	@Override
	protected void solutionLoaded(Solution s)
	{
		super.solutionLoaded(s);
		getWebsocketSession().solutionLoaded(s);
	}

	@Override
	public INGClientWebsocketSession getWebsocketSession()
	{
		return wsSession;
	}

	@Override
	public void valueChanged()
	{
		getWebsocketSession().valueChanged();
	}

	@Override
	protected void doInvokeLater(Runnable r)
	{
		getEventDispatcher().addEvent(new NGEvent(this, r));
	}

	@Override
	public boolean isEventDispatchThread()
	{
		return getEventDispatcher().isEventDispatchThread();
	}

	@Override
	public void invokeAndWait(Runnable r)
	{
		FutureTask<Object> future = new FutureTask<Object>(r, null);
		getEventDispatcher().addEvent(new NGEvent(this, future));
		try
		{
			future.get(); // blocking
		}
		catch (InterruptedException e)
		{
			Debug.trace(e);
		}
		catch (ExecutionException e)
		{
			e.getCause().printStackTrace();
			Debug.error(e.getCause());
		}
	}

	@Override
	public Locale getLocale() // TODO provide actual Implementatin
	{
		return new Locale("en", "US");
	}

	@Override
	public void setLocale(Locale locale)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public TimeZone getTimeZone()
	{
		// TODO get from actual client?
		return null;
	}

	@Override
	public void setTimeZone(TimeZone timeZone)
	{
		// TODO should this be remembered?
		super.setTimeZone(timeZone);
	}

	@Override
	public String getI18NMessage(String i18nKey)
	{
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getI18NMessage(String i18nKey, Object[] array)
	{
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getI18NMessageIfPrefixed(String i18nKey)
	{
		// TODO Auto-generated method stub
		return i18nKey;
	}

	@Override
	public void setI18NMessage(String i18nKey, String value)
	{
		// TODO Auto-generated method stub

	}

	@Override
	public void refreshI18NMessages()
	{
		// TODO Auto-generated method stub

	}

	@Override
	public void setI18NMessagesFilter(String columnname, String[] value)
	{
		// TODO Auto-generated method stub

	}

	@Override
	public ResourceBundle getResourceBundle(Locale locale)
	{
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	protected boolean startApplicationServerConnection()
	{
		try
		{
			applicationServer = ApplicationServerRegistry.getService(IApplicationServer.class);
			return true;
		}
		catch (Exception ex)
		{
			reportError(Messages.getString("servoy.client.error.finding.dataservice"), ex); //$NON-NLS-1$
			return false;
		}
	}

	@Override
	protected void loadSolution(SolutionMetaData solutionMeta) throws RepositoryException
	{
		if (loadSolutionsAndModules(solutionMeta))
		{
			J2DBGlobals.firePropertyChange(this, "solution", null, getSolution()); //$NON-NLS-1$
		}
	}

	@Override
	protected IBasicFormManager createFormManager()
	{
		return new NGFormManager(this);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.servoy.j2db.server.ngclient.INGApplication#getChangeListener()
	 */
	@Override
	public IChangeListener getChangeListener()
	{
		return this;
	}

	@Override
	protected void createFoundSetManager()
	{
		foundSetManager = new FoundSetManager(this, new SwingFoundSetFactory());
		foundSetManager.init();
	}

	@Override
	public ScheduledExecutorService getScheduledExecutor()
	{
		if (scheduledExecutorService == null && !isShutDown())
		{
			synchronized (J2DBGlobals.class)
			{
				if (scheduledExecutorService == null)
				{
					scheduledExecutorService = new ServoyScheduledExecutor(1, 4, 1)
					{
						private IServiceProvider prev;

						@Override
						protected void beforeExecute(Thread t, Runnable r)
						{
							super.beforeExecute(t, r);
							prev = J2DBGlobals.getServiceProvider();
							if (prev != NGClient.this)
							{
								// if this happens it is a webclient in developer..
								// and the provider is not set for this web client. so it must be set.
								J2DBGlobals.setServiceProvider(NGClient.this);
							}
						}

						@Override
						protected void afterExecute(Runnable r, Throwable t)
						{
							super.afterExecute(r, t);
							J2DBGlobals.setServiceProvider(prev);
						}
					};
				}
			}
		}
		return scheduledExecutorService;
	}

	@Override
	public URL getServerURL()
	{
		// TODO get from actual client
		return super.getServerURL();
	}

	@Override
	public int getApplicationType()
	{
		return IApplication.NG_CLIENT;
	}

	@Override
	public String getClientOSName()
	{
		// TODO check the actual client
		return super.getClientOSName();
	}

	@Override
	public int getClientPlatform()
	{
		// TODO check the actual client
		return super.getClientPlatform();
	}

	@Override
	public String getApplicationName()
	{
		return "Servoy NGClient";
	}

	@Override
	public boolean putClientProperty(Object name, Object val)
	{
		if (uiProperties == null)
		{
			uiProperties = new HashMap<Object, Object>();
		}
		uiProperties.put(name, val);
		return true;
	}

	@Override
	public Object getClientProperty(Object name)
	{
		return (uiProperties == null) ? null : uiProperties.get(name);
	}

	@Override
	public void setTitle(String title)
	{
		getRuntimeWindowManager().getCurrentWindow().setTitle(title);
	}

	@Override
	public ItemFactory getItemFactory()
	{
		// Not used in NGClient
		return null;
	}

	@Override
	public IDataRendererFactory getDataRenderFactory()
	{
		// Not used in NGClient
		return null;
	}

	@Override
	public RendererParentWrapper getPrintingRendererParent()
	{
		// Not used in NGClient
		return null;
	}

	@Override
	public PageFormat getPageFormat()
	{
		// Not used in NGClient
		return null;
	}

	@Override
	public void setPageFormat(PageFormat currentPageFormat)
	{
		// Not used in NGClient
	}

	@Override
	public String getUserProperty(String name)
	{
		try
		{
			return (String)getWebsocketSession().executeServiceCall("$applicationService", "getUserProperty", new Object[] { name });
		}
		catch (IOException e)
		{
			Debug.error("Error getting getting property '" + name + "'", e);
		}
		return null;
	}

	@Override
	public void setUserProperty(String name, String value)
	{
		try
		{
			getWebsocketSession().executeServiceCall("$applicationService", "setUserProperty", new Object[] { name, value });
		}
		catch (IOException e)
		{
			Debug.error("Error getting setting property '" + name + "' value: " + value, e);
		}

	}

	@SuppressWarnings("nls")
	@Override
	public String[] getUserPropertyNames()
	{
		JSONArray result;
		try
		{
			result = (JSONArray)getWebsocketSession().executeServiceCall("$applicationService", "getUserPropertyNames", null);
			String[] names = new String[result.length()];
			for (int i = 0; i < names.length; i++)
			{
				names[i] = result.optString(i);
			}
			return names;
		}
		catch (IOException e)
		{
			Debug.error("Error getting user property names", e);
		}
		return new String[0];
	}

	@Override
	public void looseFocus()
	{
		// TODO call request focus on a div in a client?
	}

	@Override
	public Dimension getScreenSize()
	{
		// TODO just call the client to get the size
		return null;
	}

	@Override
	public boolean showURL(String url, String target, String target_options, int timeout_ms, boolean onRootFrame)
	{
		// TODO call client directly with the options given here.
		return false;
	}

	@Override
	public NGRuntimeWindowManager getRuntimeWindowManager()
	{
		if (runtimeWindowManager == null)
		{
			runtimeWindowManager = new NGRuntimeWindowManager(this);
		}
		return runtimeWindowManager;
	}

	public final synchronized IEventDispatcher<NGEvent> getEventDispatcher()
	{
		if (executor == null)
		{
			Thread thread = new Thread(executor = createDispatcher(), "Executor,clientid:" + getClientID());
			thread.setDaemon(true);
			thread.start();
		}
		return executor;
	}

	/**
	 * Method to create the {@link IEventDispatcher} runnable
	 */
	protected IEventDispatcher<NGEvent> createDispatcher()
	{
		return new EventDispatcher<NGEvent>(this);
	}

	@Override
	public void shutDown(boolean force)
	{
		super.shutDown(force);
		if (executor != null) executor.destroy();
		executor = null;
		if (scheduledExecutorService != null)
		{
			scheduledExecutorService.shutdownNow();
			try
			{
				scheduledExecutorService.awaitTermination(10, TimeUnit.SECONDS);
			}
			catch (InterruptedException e)
			{
			}
			scheduledExecutorService = null;
		}
		getWebsocketSession().closeSession();
	}
}
