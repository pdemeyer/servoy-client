/*

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

package com.servoy.extension.parser;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipFile;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.FactoryConfigurationError;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.servoy.extension.ExtensionUtils;
import com.servoy.extension.ExtensionUtils.EntryInputStreamRunner;
import com.servoy.extension.IExtensionProvider;
import com.servoy.extension.IMessageProvider;
import com.servoy.extension.Message;
import com.servoy.extension.MessageKeeper;
import com.servoy.extension.VersionStringUtils;
import com.servoy.j2db.util.Debug;
import com.servoy.j2db.util.Pair;
import com.servoy.j2db.util.Utils;

/**
 * This class parses an .exp file and provides it's contents in a friendly way. 
 * @author acostescu
 */
public class EXPParser implements IMessageProvider
{

	public static final String EXTENSION_XML = "package.xml"; //$NON-NLS-1$
	public static final String EXTENSION_SCHEMA = "servoy-extension.xsd"; //$NON-NLS-1$

	// xml tag/attribute names & values
	public static final String EXTENSION_ID = "extension-id"; //$NON-NLS-1$
	public static final String EXTENSION_NAME = "extension-name"; //$NON-NLS-1$
	public static final String VERSION = "version"; //$NON-NLS-1$
	public static final String DEPENDENCIES = "dependencies"; //$NON-NLS-1$
	public static final String SERVOY_DEPENDENCY = "servoy"; //$NON-NLS-1$
	public static final String PATH = "path"; //$NON-NLS-1$
	public static final String MAX_VERSION = "max-version"; //$NON-NLS-1$
	public static final String MIN_VERSION = "min-version"; //$NON-NLS-1$
	public static final String INCLUSIVE_MIN_MAX_ATTR = "inclusive"; //$NON-NLS-1$
	public static final String FALSE_VALUE = "false"; //$NON-NLS-1$
	public static final String EXTENSION_DEPENDENCY = "extension"; //$NON-NLS-1$
	public static final String LIB_DEPENDENCY = "lib"; //$NON-NLS-1$
	public static final String ID = "id"; //$NON-NLS-1$
	public static final String CONTENT = "content"; //$NON-NLS-1$
	public static final String IMPORT_SOLUTION = "importSolution"; //$NON-NLS-1$
	public static final String IMPORT_STYLE = "importStyle"; //$NON-NLS-1$
	public static final String TEAM_PROJECT_SET = "teamProjectSet"; //$NON-NLS-1$
	public static final String ECLIPSE_UPDATE_SITE = "eclipseUpdateSite"; //$NON-NLS-1$
	public static final String URL = "url"; //$NON-NLS-1$
	public static final String INFO = "info"; //$NON-NLS-1$
	public static final String ICON = "icon"; //$NON-NLS-1$
	public static final String DESCRIPTION = "description"; //$NON-NLS-1$
	public static final String RESTART = "requiresRestart"; //$NON-NLS-1$

	protected File expFile;
	protected FullDependencyMetadata dependencyMetadata;
	protected ExtensionConfiguration xml;
	protected boolean dependencyParsed = false;
	protected boolean allParsed = false;

	protected MessageKeeper messages = new MessageKeeper();

	public EXPParser(File expFile)
	{
		this.expFile = expFile;
	}

	@SuppressWarnings("nls")
	public FullDependencyMetadata parseDependencyInfo()
	{
		if (!dependencyParsed)
		{
			dependencyParsed = true;

			ZipFile zipFile = null;
			try
			{
				zipFile = new ZipFile(expFile);
				ZipEntry extensionFile = zipFile.getEntry(EXTENSION_XML);
				if (extensionFile != null)
				{
					Boolean adheresToSchema = runOnEntry(zipFile, extensionFile, new ValidateAgainstSchema(expFile.getName()));

					if (Boolean.TRUE.equals(adheresToSchema))
					{
						dependencyMetadata = runOnEntry(zipFile, extensionFile, new ParseDependencyMetadata(expFile.getName(), messages));
					}
				}
				else
				{
					messages.addError("Reading extension package '" + expFile.getName() + "' failed; it will be ignored. Reason: missing 'package.xml'.");
				}
			}
			catch (ZipException e)
			{
				messages.addError("Reading extension package '" + expFile.getName() + "' failed; it will be ignored. Reason: " + e.getMessage() + ".");
				Debug.trace("Reading extension package '" + expFile.getName() + "' failed; it will be ignored.", e);
			}
			catch (IOException e)
			{
				messages.addError("Reading extension package '" + expFile.getName() + "' failed; it will be ignored. Reason: " + e.getMessage() + ".");
				Debug.trace("Reading extension package '" + expFile.getName() + "' failed; it will be ignored.", e);
			}
			finally
			{
				if (zipFile != null)
				{
					try
					{
						zipFile.close();
					}
					catch (IOException e)
					{
						// ignore
					}
				}
			}
		}
		return dependencyMetadata;
	}

	@SuppressWarnings("nls")
	public ExtensionConfiguration parseWholeXML()
	{
		if (!allParsed)
		{
			allParsed = true;
			parseDependencyInfo(); // will parse it if not already parsed; also checks against schema

			if (dependencyMetadata != null)
			{
				// valid dependency metadata and was validated against schema; parse the rest of the XML
				try
				{
					Pair<Boolean, ExtensionConfiguration> result = ExtensionUtils.runOnEntry(expFile, EXTENSION_XML, new ParseAllRemaining(expFile,
						dependencyMetadata));
					xml = result.getRight();
					if (Boolean.FALSE.equals(result.getLeft()))
					{
						// this shouldn't happen as package.xml was found before when parsing the same zip file for dependency info
						Debug.warn("'package.xml' no longer found when trying to parse it for extension '" + dependencyMetadata.id + "'. File: '" +
							expFile.getCanonicalPath() + "'.");
					}
				}
				catch (ZipException e)
				{
					messages.addError("Zip problems encountered while trying to parse entire 'package.xml' for extension '" + dependencyMetadata.id +
						"'. Reason: " + e.getMessage() + ".");
					Debug.trace(e);
				}
				catch (IOException e)
				{
					messages.addError("IO problems encountered while trying to parse entire 'package.xml' for extension '" + dependencyMetadata.id +
						"'. Reason: " + e.getMessage() + ".");
					Debug.trace(e);
				}
			}
		}

		return xml;
	}

	protected <T> T runOnEntry(ZipFile zipFile, ZipEntry extensionFile, EntryInputStreamRunner<T> runner) throws IOException
	{
		InputStream is = null;
		BufferedInputStream bis = null;
		try
		{
			is = zipFile.getInputStream(extensionFile);
			bis = new BufferedInputStream(is);

			return runner.runOnEntryInputStream(bis);
		}
		finally
		{
			Utils.closeInputStream(bis);
		}
	}

	public Message[] getMessages()
	{
		return messages.getMessages();
	}

	public void clearMessages()
	{
//		messages.clear(); as all is cached, clearing error messages is misleading, cause they won't reappear; cached data is returned
	}

	// this is done separately, although schema is used when parsing also, because in
	// that case we only receive some hard-to-differentiate error and parsing continues,
	// but we actually want to parse only if XML is valid from the schema's point of view
	@SuppressWarnings("nls")
	protected class ValidateAgainstSchema implements EntryInputStreamRunner<Boolean>
	{

		private final String zipFileName;

		public ValidateAgainstSchema(String zipFileName)
		{
			this.zipFileName = zipFileName;
		}

		public Boolean runOnEntryInputStream(InputStream is)
		{
			// verify that XML adheres to our schema
			boolean adheresToSchema = false;
			SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema");
			if (factory != null)
			{
				try
				{
					Schema schema = factory.newSchema(IExtensionProvider.class.getResource(EXTENSION_SCHEMA));
					Validator validator = schema.newValidator();
					Source source = new StreamSource(is);

					try
					{
						validator.validate(source);
						adheresToSchema = true;
					}
					catch (SAXException ex)
					{
						messages.addError("Invalid 'package.xml' in package '" + zipFileName + "'; .xsd validation failed. Reason: " + ex.getMessage() + ".");
						Debug.trace("Invalid 'package.xml' in package '" + zipFileName + "'; .xsd validation failed.", ex);
					}
					catch (IOException ex)
					{
						messages.addError("Invalid 'package.xml' in package '" + zipFileName + "'; .xsd validation failed. Reason: " + ex.getMessage() + ".");
						Debug.trace("Invalid 'package.xml' in package '" + zipFileName + "'; .xsd validation failed.", ex);
					}
				}
				catch (SAXException ex)
				{
					messages.addError("Unable to validate 'package.xml' against the .xsd. Please report this problem to Servoy.");
					Debug.error("Error compiling 'servoy-extension.xsd'.");
				}
			}
			else
			{
				messages.addError("Unable to validate 'package.xml' against the .xsd. Please report this problem to Servoy.");
				Debug.error("Cannot find schema factory.");
			}

			return Boolean.valueOf(adheresToSchema);
		}

	}

	/**
	 * Parses the whole XML file (except dependency that is already parsed) to construct an in-memory representation of it.
	 */
	protected class ParseAllRemaining implements EntryInputStreamRunner<ExtensionConfiguration>
	{

		private final File zipFile;
		private final FullDependencyMetadata dependencyInfo;

		public ParseAllRemaining(File zipFile, FullDependencyMetadata dependencyInfo)
		{
			this.zipFile = zipFile;
			this.dependencyInfo = dependencyInfo;
		}

		public ExtensionConfiguration runOnEntryInputStream(InputStream is)
		{
			// TODO parse the rest of the xml
			ExtensionConfiguration wholeXML = null;
			SchemaFactory factory = SchemaFactory.newInstance("http://www.w3.org/2001/XMLSchema"); //$NON-NLS-1$
			if (factory != null)
			{
				Schema schema = null;
				try
				{
					// prepare to verify that XML adheres to our schema; because of this schema defined default values will be set as well when parsing
					schema = factory.newSchema(IExtensionProvider.class.getResource(EXTENSION_SCHEMA));
				}
				catch (SAXException ex)
				{
					messages.addError("Unable to validate 'package.xml' against the .xsd. Please report this problem to Servoy."); //$NON-NLS-1$
					Debug.error("Error compiling 'servoy-extension.xsd'."); //$NON-NLS-1$
				}

				if (schema != null)
				{
					try
					{
						DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
						dbf.setNamespaceAware(true);
						dbf.setSchema(schema);
						DocumentBuilder db = dbf.newDocumentBuilder();
						db.setErrorHandler(new ParseDependencyMetadataErrorHandler(zipFile.getName(), messages));

						Document doc = db.parse(is); // should we use UTF-8 here?
						Element root = doc.getDocumentElement(); // "servoy-extension" tag
						root.normalize();

						// as this was already validated by schema, we need less null-checks and less structure checks
						Content content = null;

						NodeList list = root.getElementsByTagName(CONTENT);
						if (list != null && list.getLength() == 1)
						{
							List<String> solutionToImportPaths = new ArrayList<String>();
							List<String> styleToImportPaths = new ArrayList<String>();
							List<String> teamProjectSetPaths = new ArrayList<String>();
							List<String> eclipseUpdateSiteURLs = new ArrayList<String>();

							Element contentNode = (Element)list.item(0);

							Element element;

							int i = 0;
							list = contentNode.getElementsByTagName(IMPORT_SOLUTION);
							while (list != null && list.getLength() > i)
							{
								element = ((Element)list.item(i++));
								solutionToImportPaths.add(element.getAttribute(PATH));
							}

							i = 0;
							list = contentNode.getElementsByTagName(IMPORT_STYLE);
							while (list != null && list.getLength() > i)
							{
								element = ((Element)list.item(i++));
								styleToImportPaths.add(element.getAttribute(PATH));
							}

							i = 0;
							list = contentNode.getElementsByTagName(TEAM_PROJECT_SET);
							while (list != null && list.getLength() > i)
							{
								element = ((Element)list.item(i++));
								teamProjectSetPaths.add(element.getAttribute(PATH));
							}

							i = 0;
							list = contentNode.getElementsByTagName(ECLIPSE_UPDATE_SITE);
							while (list != null && list.getLength() > i)
							{
								element = ((Element)list.item(i++));
								eclipseUpdateSiteURLs.add(element.getAttribute(URL));
							}

							content = new Content(solutionToImportPaths.size() > 0 ? solutionToImportPaths.toArray(new String[solutionToImportPaths.size()])
								: null, styleToImportPaths.size() > 0 ? styleToImportPaths.toArray(new String[styleToImportPaths.size()]) : null,
								teamProjectSetPaths.size() > 0 ? teamProjectSetPaths.toArray(new String[teamProjectSetPaths.size()]) : null,
								eclipseUpdateSiteURLs.size() > 0 ? eclipseUpdateSiteURLs.toArray(new String[eclipseUpdateSiteURLs.size()]) : null);
						}

						Info info = null;

						list = root.getElementsByTagName(INFO);
						if (list != null && list.getLength() == 1)
						{
							Element infoNode = (Element)list.item(0);
							String description = null;

							list = infoNode.getElementsByTagName(DESCRIPTION);
							if (list != null && list.getLength() == 1)
							{
								description = list.item(0).getTextContent();
							}

							String iconPath = null;

							list = infoNode.getElementsByTagName(ICON);
							if (list != null && list.getLength() == 1)
							{
								iconPath = ((Element)list.item(0)).getAttribute(PATH);
							}

							String url = null;

							list = infoNode.getElementsByTagName(URL);
							if (list != null && list.getLength() == 1)
							{
								url = list.item(0).getTextContent();
							}

							info = new Info(iconPath, url, description);
						}

						boolean requiresRestart = false;
						list = root.getElementsByTagName(RESTART);
						if (list != null && list.getLength() == 1)
						{
							requiresRestart = true;
						}

						wholeXML = new ExtensionConfiguration(dependencyInfo, content, info, requiresRestart);
					}
					catch (ParserConfigurationException e)
					{
						messages.addError("Cannot parse 'package.xml' in package '" + zipFile.getName() + "'. Reason: " + e.getMessage() + "."); //$NON-NLS-1$//$NON-NLS-2$ //$NON-NLS-3$
						Debug.trace("Cannot parse 'package.xml' in package '" + zipFile.getName() + "'.", e); //$NON-NLS-1$ //$NON-NLS-2$
					}
					catch (SAXException e)
					{
						messages.addError("Cannot parse 'package.xml' in package '" + zipFile.getName() + "'. Reason: " + e.getMessage() + "."); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						Debug.trace("Cannot parse 'package.xml' in package '" + zipFile.getName() + "'.", e); //$NON-NLS-1$ //$NON-NLS-2$
					}
					catch (IOException e)
					{
						messages.addError("Cannot parse 'package.xml' in package '" + zipFile.getName() + "'. Reason: " + e.getMessage() + "."); //$NON-NLS-1$//$NON-NLS-2$ //$NON-NLS-3$
						Debug.trace("Cannot parse 'package.xml' in package '" + zipFile.getName() + "'.", e); //$NON-NLS-1$//$NON-NLS-2$
					}
					catch (FactoryConfigurationError e)
					{
						messages.addError("Unable to parse 'package.xml'. Please report this problem to Servoy."); //$NON-NLS-1$
						Debug.error("Cannot find document builder factory."); //$NON-NLS-1$
					}
				}
			}
			else
			{
				messages.addError("Unable to validate 'package.xml' against the .xsd. Please report this problem to Servoy."); //$NON-NLS-1$
				Debug.error("Cannot find schema factory."); //$NON-NLS-1$
			}
			return wholeXML;
		}

		// gets & creates a (possibly exclusive or unbounded) min or max version string from the element
		protected String getMinMaxVersion(Element element, String minOrMax)
		{
			String minMaxVersion = VersionStringUtils.UNBOUNDED;

			NodeList verNode = element.getElementsByTagName(minOrMax);
			if (verNode != null && verNode.getLength() == 1)
			{
				minMaxVersion = verNode.item(0).getTextContent();
				NamedNodeMap attrs = verNode.item(0).getAttributes();
				if (attrs != null)
				{
					Node attr = attrs.getNamedItem(INCLUSIVE_MIN_MAX_ATTR);
					if (attr != null && FALSE_VALUE.equals(attr.getNodeValue()))
					{
						minMaxVersion = VersionStringUtils.createExclusiveVersionString(minMaxVersion);
					}
				}
			}

			return minMaxVersion;
		}

	}
}