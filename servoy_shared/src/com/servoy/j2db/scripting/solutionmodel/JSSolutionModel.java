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
package com.servoy.j2db.scripting.solutionmodel;

import java.awt.Dimension;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.servoy.j2db.FlattenedSolution;
import com.servoy.j2db.FormManager;
import com.servoy.j2db.IApplication;
import com.servoy.j2db.documentation.ServoyDocumented;
import com.servoy.j2db.persistence.BaseComponent;
import com.servoy.j2db.persistence.Form;
import com.servoy.j2db.persistence.IServer;
import com.servoy.j2db.persistence.Media;
import com.servoy.j2db.persistence.Part;
import com.servoy.j2db.persistence.Relation;
import com.servoy.j2db.persistence.RepositoryException;
import com.servoy.j2db.persistence.ScriptMethod;
import com.servoy.j2db.persistence.ScriptNameValidator;
import com.servoy.j2db.persistence.ScriptVariable;
import com.servoy.j2db.persistence.Style;
import com.servoy.j2db.persistence.Table;
import com.servoy.j2db.persistence.ValueList;
import com.servoy.j2db.scripting.IReturnedTypesProvider;
import com.servoy.j2db.scripting.ScriptObjectRegistry;
import com.servoy.j2db.util.DataSourceUtils;
import com.servoy.j2db.util.ImageLoader;
import com.servoy.j2db.util.Utils;

/**
 * @author jcompagner
 */
@ServoyDocumented(category = ServoyDocumented.RUNTIME, publicName = "SolutionModel", scriptingName = "solutionModel")
public class JSSolutionModel
{
	static
	{
		ScriptObjectRegistry.registerReturnedTypesProviderForClass(JSSolutionModel.class, new IReturnedTypesProvider()
		{
			@SuppressWarnings("deprecation")
			public Class< ? >[] getAllReturnedTypes()
			{
				return new Class< ? >[] { ALIGNMENT.class, ANCHOR.class, CURSOR.class, DEFAULTS.class, DISPLAYTYPE.class, JOINTYPE.class, MEDIAOPTION.class, PARTS.class, PRINTSLIDING.class, SCROLLBAR.class, VALUELIST.class, VARIABLETYPE.class, VIEW.class, JSForm.class, JSField.class, JSButton.class, JSComponent.class, JSLabel.class, JSMethod.class, JSPortal.class, JSPart.class, JSRelation.class, JSRelationItem.class, JSStyle.class, JSTabPanel.class, JSTab.class, JSMedia.class, JSValueList.class, JSVariable.class };
			}
		});
	}

	private volatile IApplication application;

	public JSSolutionModel(IApplication application)
	{
		this.application = application;
	}

	public JSForm js_newForm(String name, String serverName, String tableName, String styleName, boolean show_in_menu, int width, int height)
	{
		String dataSource = DataSourceUtils.createDBTableDataSource(serverName, tableName);
		return js_newForm(name, dataSource, styleName, show_in_menu, width, height);
	}

	public JSForm js_newForm(String name, String dataSource, String styleName, boolean show_in_menu, int width, int height)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		try
		{
			Style style = null;
			if (styleName != null)
			{
				style = fs.getStyle(styleName);
			}
			Form form = fs.getSolutionCopy().createNewForm(new ScriptNameValidator(fs), style, name, dataSource, show_in_menu, new Dimension(width, height));
			form.createNewPart(Part.BODY, height);
			((FormManager)application.getFormManager()).addForm(form, false);
			return new JSForm(application, form, true);
		}
		catch (RepositoryException e)
		{
			throw new RuntimeException(e);
		}
	}

	public JSForm js_newForm(String name, JSForm toclonefrom)
	{
		return js_cloneForm(name, toclonefrom);
	}

	/**
	 * Creates a new JSForm Object.
	 * 
	 * NOTE: See the JSForm node for more information about form objects that can be added to the new form. 
	 *
	 * @sample
	 * var myForm = solutionModel.newForm('newForm', 'myServer', 'myTable', 'myStyleName', false, 800, 600)
	 * //now you can add stuff to the form (under JSForm node)
	 * //add a label
	 * myForm.newLabel('Name', 20, 20, 120, 30)
	 * //add a "normal" text entry field
	 * myForm.newTextField('dataProviderNameHere', 140, 20, 140,20)
	 *
	 * @param name the specified name of the form
	 *
	 * @param server_name|data_source the specified name of the server or datasource for the specified table
	 *
	 * @param table_name optional the specified name of the table
	 *
	 * @param style the specified style  
	 *
	 * @param show_in_menu if true show the name of the new form in the menu; or false for not showing
	 *
	 * @param width the width of the form in pixels
	 *
	 * @param height the height of the form in pixels
	 * 
	 * @return a new JSForm object
	 */
	public JSForm js_newForm(Object[] args)
	{
		if (args == null)
		{
			return null;
		}
		if (args.length == 2 && args[1] instanceof JSForm)
		{
			return js_cloneForm(String.valueOf(args[0]), (JSForm)args[1]);
		}
		if (args.length < 6)
		{
			return null;
		}
		int a = 0;
		String name = String.valueOf(args[a++]);
		String dataSource = null;
		if (args[4] instanceof Boolean && args.length > 6)
		{
			// separate server and table arguments
			Object serverName = args[a++];
			Object tableName = args[a++];
			if (serverName != null && tableName != null)
			{
				dataSource = DataSourceUtils.createDBTableDataSource(serverName.toString(), tableName.toString());
			}
		}
		else
		{
			// combined datasource argument
			Object ds = args[a++];
			if (ds != null)
			{
				dataSource = ds.toString();
			}
		}

		String styleName = String.valueOf(args[a++]);
		if ("null".equals(styleName)) styleName = null; //$NON-NLS-1$
		boolean show_in_menu = Utils.getAsBoolean(args[a++]);
		int width = Utils.getAsInteger(args[a++]);
		int height = Utils.getAsInteger(args[a++]);

		FlattenedSolution fs = application.getFlattenedSolution();
		try
		{
			Style style = null;
			if (styleName != null)
			{
				style = fs.getStyle(styleName);
			}
			Form form = fs.getSolutionCopy().createNewForm(new ScriptNameValidator(fs), style, name, dataSource, show_in_menu, new Dimension(width, height));
			form.createNewPart(Part.BODY, height);
			((FormManager)application.getFormManager()).addForm(form, false);
			return new JSForm(application, form, true);
		}
		catch (RepositoryException e)
		{
			throw new RuntimeException(e);
		}

	}

	/**
	 * Gets the style specified by the given name.
	 * 
	 * @sample
	 * 	var style = solutionModel.getStyle('my_existing_style')
	 * 	style.content = 'combobox { color: #0000ff;font: italic 10pt "Verdana";}'
	 * 
	 * @param name the specified name of the style
	 * 
	 * @return a JSStyle
	 */
	public JSStyle js_getStyle(String name)
	{
		Style style = application.getFlattenedSolution().getStyle(name);
		if (style != null)
		{
			return new JSStyle(application, style, false);
		}
		return null;
	}

	/**
	 * Creates a new style with the given css content string under the given name.
	 * 
	 * NOTE: Will throw an exception if a style with that name already exists.  
	 * 
	 * @sample
	 * 	var form = solutionModel.newForm('myForm','myServer','myTable',null,true,1000,800);
	 * 	if (form.transparent == false)
	 * 	{
	 * 		var style = solutionModel.newStyle('myStyle','form { background-color: yellow; }');
	 * 		style.text = style.text + 'field { background-color: blue; }';
	 * 		form.styleName = 'myStyle';
	 * 	}
	 * 	var field = form.newField('columnTextDataProvider',JSField.TEXT_FIELD,100,100,100,50);
	 * 	forms['myForm'].controller.show();
	 *
	 * @param name the name of the new style
	 * 
	 * @param content the css content of the new style
	 * 
	 * @return a JSStyle object
	 */
	public JSStyle js_newStyle(String name, String content)
	{
		Style style = application.getFlattenedSolution().createStyle(name, content);
		if (style != null)
		{
			return new JSStyle(application, style, true);
		}
		return null;
	}

	/**
	 * Makes an exact copy of the given form and gives it the new name.
	 *
	 * @sample 
	 * // get an existing form
	 * var form = solutionModel.getForm("existingForm")
	 * // make a clone/copy from it
	 * var clone = solutionModel.cloneForm("clonedForm", form)
	 * // add a new label to the clone
	 * clone.newLabel("added label",50,50,80,20);
	 * // show it
	 * forms["clonedForm"].controller.show();
	 *
	 * @param newName the new name for the form clone
	 *
	 * @param jsForm the form to be cloned 
	 * 
	 * @return a JSForm
	 */
	public JSForm js_cloneForm(String newName, JSForm jsForm)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		Form clone = fs.clonePersist(jsForm.getForm(), newName, fs.getSolutionCopy());
		((FormManager)application.getFormManager()).addForm(clone, false);
		return new JSForm(application, clone, true);
	}

	public <T extends BaseComponent> JSComponent< ? > js_cloneComponent(String newName, JSComponent<T> component)
	{
		return js_cloneComponent(newName, component, null);
	}


	/**
	 * Makes an exact copy of the given component (JSComponent/JSField/JSLabel), gives it a new name and optionally moves it to a new parent form.
	 *
	 * @sample
	 * // get an existing field to clone.
	 * var field = solutionModel.getForm("formWithField").getField("fieldName");
	 * // get the target form for the copied/cloned field
	 * var form = solutionModel.getForm("targetForm");
	 * // make a clone/copy of the field and re parent it to the target form.
	 * var clone = solutionModel.cloneComponent("clonedField",field,form);
	 * // show it
	 * forms["targetForm"].controller.show();
	 * 
	 * @param newName the new name of the cloned component
	 *
	 * @param component the component to clone
	 *
	 * @param newParentForm optional the new parent form 
	 * 
	 * @return the exact copy of the given component
	 */
	public <T extends BaseComponent> JSComponent< ? > js_cloneComponent(String newName, JSComponent<T> component, JSForm newParentForm)
	{
		if (!(component.getBaseComponent(false).getParent() instanceof Form))
		{
			throw new RuntimeException("only components of a form can be cloned"); //$NON-NLS-1$
		}
		JSForm parent = newParentForm;
		if (parent == null)
		{
			parent = (JSForm)component.getJSParent();
		}
		parent.checkModification();
		Form form = parent.getForm();
		FlattenedSolution fs = application.getFlattenedSolution();
		fs.clonePersist(component.getBaseComponent(false), newName, form);
		return parent.js_getComponent(newName);
	}

	/**
	 * Removes the specified form during the persistent connected client session.
	 * 
	 * NOTE: Make sure you call history.remove first in your Servoy method (script). 
	 *
	 * @sample
	 * //first remove it from the current history, to destroy any active form instance
	 * var success = history.removeForm('myForm')
	 * //removes the named form from this session, please make sure you called history.remove() first
	 * if(success)
	 * {
	 * 	solutionModel.removeForm('myForm')
	 * }
	 *
	 * @param name the specified name of the form to remove
	 * 
	 * @return true is form has been removed, false if form could not be removed
	 */
	public boolean js_removeForm(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		Form form = fs.getForm(name);
		if (form != null)
		{
			if (((FormManager)application.getFormManager()).removeForm(form))
			{
				fs.deletePersistCopy(form, false);
				return true;
			}
		}
		return false;
	}


	/**
	 * Reverts the specified form to the original (blueprint) version of the form; will result in an exception error if the form is not an original form.
	 * 
	 * NOTE: Make sure you call history.remove first in your Servoy method (script) or call form.controller.recreateUI() before the script ends.
	 *
	 * @sample
	 *  // revert the form to the original solution form, removing any changes done to it through the solution model.
	 *  var revertedForm = solutionModel.revertForm('myForm')
	 *  // add a label on a random place.
	 *  revertedForm.newLabel("MyLabel",Math.random()*100,Math.random()*100,80,20);
	 *  // make sure that the ui is up to date.
	 *  forms.myForm.controller.recreateUI();
	 *
	 * @param name the specified name of the form to revert
	 * 
	 * @return a JSForm object
	 */
	public JSForm js_revertForm(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		Form form = fs.getForm(name);
		if (form != null)
		{
			fs.deletePersistCopy(form, true);
			form = fs.getForm(name);
			((FormManager)application.getFormManager()).addForm(form, false);
			application.getFlattenedSolution().registerChangedForm(form);
			return new JSForm(application, form, false);
		}
		return null;
	}

	/**
	 * Gets the specified form object and returns information about the form (see JSForm node).
	 *
	 * @sample
	 * var myForm = solutionModel.getForm('existingFormName');
	 * //get the style of the form (for all other properties see JSForm node)
	 * var styleName = myForm.styleName;
	 *
	 * @param name the specified name of the form
	 * 
	 * @return a JSForm
	 */
	public JSForm js_getForm(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		Form form = fs.getForm(name);

		if (form != null)
		{
			return new JSForm(application, form, false);
		}
		return null;
	}

	public JSForm[] js_getForms(String datasource)
	{
		if (datasource == null) throw new IllegalArgumentException("SolutionModel.getForms() param datasource (server/table) is null"); //$NON-NLS-1$
		return getForms(datasource);
	}

	/**
	 * Get an array of forms, that are all based on datasource/servername or tablename.
	 *
	 * @sample
	 * var forms = solutionModel.getForms(datasource)
	 * for (var i in forms)
	 * 		application.output(forms[i].name)
	 *
	 * @param server optional the datasource or servername 
	 * 
	 * @param tablename optional the tablename
	 * 
	 * @return an array of JSForm type elements
	 */
	public JSForm[] js_getForms(String server, String tablename)
	{
		return js_getForms(DataSourceUtils.createDBTableDataSource(server, tablename));
	}

	public JSForm[] js_getForms()
	{
		return getForms(null);
	}

	/**
	 * @param datasource
	 * @return
	 */
	private JSForm[] getForms(String datasource)
	{
		FlattenedSolution fs = application.getFlattenedSolution();

		Iterator<Form> forms = fs.getForms(datasource, true);

		ArrayList<JSForm> list = new ArrayList<JSForm>();
		while (forms.hasNext())
		{
			list.add(new JSForm(application, forms.next(), false));
		}
		return list.toArray(new JSForm[list.size()]);
	}


	/**
	 * Gets the specified media object; can be assigned to a button/label.
	 *
	 * @sample
	 * var myMedia = solutionModel.getMedia('button01.gif')
	 * //now set the imageMedia property of your label or button
	 * //myButton.imageMedia = myMedia
	 * // OR
	 * //myLabel.imageMedia = myMedia
	 *
	 * @param name the specified name of the media object
	 * 
	 * @return a JSMedia element
	 */
	public JSMedia js_getMedia(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		Media media = fs.getMedia(name);
		if (media != null)
		{
			return new JSMedia(media, application.getFlattenedSolution(), false);
		}
		return null;
	}

	/**
	 * Creates a new media object that can be assigned to a label or a button.
	 *
	 * @sample
	 * var myMedia = solutionModel.newMedia('button01.gif',bytes)
	 * //now set the imageMedia property of your label or button
	 * //myButton.imageMedia = myMedia
	 * // OR
	 * //myLabel.imageMedia = myMedia
	 *
	 * @param name The name of the new media
	 * 
	 * @param bytes The content
	 * 
	 * @return a JSMedia object
	 *  
	 */
	public JSMedia js_newMedia(String name, byte[] bytes)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		try
		{
			Media media = fs.getSolutionCopy().createNewMedia(new ScriptNameValidator(fs), name);
			media.setPermMediaData(bytes);
			media.setMimeType(ImageLoader.getContentType(bytes));
			if (media != null)
			{
				return new JSMedia(media, application.getFlattenedSolution(), true);
			}
			return null;
		}
		catch (RepositoryException e)
		{
			throw new RuntimeException("error createing new media with name " + name, e); //$NON-NLS-1$
		}
	}

	/**
	 * Gets the list of all media objects.
	 * 
	 * @sample
	 * 	var mediaList = solutionModel.getMediaList();
	 * 	if (mediaList.length != 0 && mediaList != null) {
	 * 		for (var x in mediaList) {
	 * 			application.output(mediaList[x]);
	 * 		}
	 * 	}
	 * 
	 * 	@return a list with all the media objects.
	 * 	
	 */
	public JSMedia[] js_getMediaList()
	{
		FlattenedSolution fs = application.getFlattenedSolution();

		ArrayList<JSMedia> lst = new ArrayList<JSMedia>();
		Iterator<Media> media = fs.getMedias(true);
		while (media.hasNext())
		{
			lst.add(new JSMedia(media.next(), application.getFlattenedSolution(), false));
		}
		return lst.toArray(new JSMedia[lst.size()]);
	}

	/**
	 * Gets an existing valuelist by the specified name and returns a JSValueList Object that can be assigned to a field.
	 *
	 * @sample
	 * var myValueList = solutionModel.getValueList('myValueListHere')
	 * //now set the valueList property of your field
	 * //myField.valuelist = myValueList
	 *
	 * @param name the specified name of the valuelist
	 * 
	 * @return a JSValueList object
	 */
	public JSValueList js_getValueList(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		ValueList valuelist = fs.getValueList(name);
		if (valuelist != null)
		{
			return new JSValueList(valuelist, application, false);
		}
		return null;

	}

	/**
	 * Gets an array of all valuelists for the currently active solution.
	 *
	 * @sample 
	 * 	var valueLists = solutionModel.getValueLists();
	 * 	if (valueLists != null && valueLists.length != 0)
	 * 		for (var i in valueLists)
	 * 			application.output(valueLists[i].name); 
	 * 
	 * @return an array of JSValueList objects
	 */
	public JSValueList[] js_getValueLists()
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		ArrayList<JSValueList> valuelists = new ArrayList<JSValueList>();
		Iterator<ValueList> iterator = fs.getValueLists(true);
		while (iterator.hasNext())
		{
			valuelists.add(new JSValueList(iterator.next(), application, false));
		}
		return valuelists.toArray(new JSValueList[valuelists.size()]);

	}


	/**
	 * Creates a new valuelist with the specified name and number type.
	 *
	 * @sample
	 * var vl1 = solutionModel.newValueList("customText",JSValueList.CUSTOM_VALUES);
	 * vl1.customValues = "customvalue1\ncustomvalue2";
	 * var vl2 = solutionModel.newValueList("customid",JSValueList.CUSTOM_VALUES);
	 * vl2.customValues = "customvalue1|1\ncustomvalue2|2";
	 * var form = solutionModel.newForm("customValueListForm",controller.getDataSource(),null,true,300,300);
	 * var combo1 = form.newComboBox("globals.text",10,10,120,20);
	 * combo1.valuelist = vl1;
	 * var combo2 = form.newComboBox("globals.id",10,60,120,20);
	 * combo2.valuelist = vl2;
	 *
	 * @param name the specified name for the valuelist
	 *
	 * @param type the specified number type for the valuelist; may be JSValueList.CUSTOM_VALUES, JSValueList.DATABASE_VALUES, JSValueList.EMPTY_VALUE_ALWAYS, JSValueList.EMPTY_VALUE_NEVER
	 * 
	 * @return a JSValueList object
	 */
	public JSValueList js_newValueList(String name, int type)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		try
		{
			ValueList valuelist = fs.getSolutionCopy().createNewValueList(new ScriptNameValidator(fs), name);
			if (valuelist != null)
			{
				valuelist.setValueListType(type);
				return new JSValueList(valuelist, application, true);
			}
		}
		catch (RepositoryException e)
		{
			throw new RuntimeException(e);
		}
		return null;

	}

	/**
	 * Creates a new global variable with the specified name and number type.
	 * 
	 * NOTE: The global variable number type is based on the value assigned from the SolutionModel-JSVariable node; for example: JSVariable.INTEGER.
	 *
	 * @sample 
	 *	var myGlobalVariable = solutionModel.newGlobalVariable('newGlobalVariable',JSVariable.INTEGER); 
	 *	myGlobalVariable.defaultValue = 12;
	 *
	 * @param name the specified name for the global variable 
	 *
	 * @param type the specified number type for the global variable
	 * 
	 * @return a JSVariable object
	 */
	public JSVariable js_newGlobalVariable(String name, int type)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		try
		{
			ScriptVariable variable = fs.getSolutionCopy().createNewScriptVariable(new ScriptNameValidator(application.getFlattenedSolution()), name, type);
			application.getScriptEngine().getGlobalScope().put(variable);
			return new JSVariable(application, variable, true);
		}
		catch (RepositoryException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * Gets an existing global variable by the specified name.
	 *
	 * @sample 
	 * 	var globalVariable = solutionModel.getGlobalVariable('globalVariableName');
	 * 	application.output(globalVariable.name + " has the default value of " + globalVariable.defaultValue);
	 * 
	 * @param name the specified name of the global variable
	 * 
	 * @return a JSVariable 
	 */
	public JSVariable js_getGlobalVariable(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		ScriptVariable variable = fs.getScriptVariable(name);
		if (variable != null)
		{
			return new JSVariable(application, variable, false);
		}
		return null;
	}

	/**
	 * Gets an array of all global variables.
	 * 
	 * @sample
	 * 	var globalVariables = solutionModel.getGlobalVariables();
	 * 	for (var i in globalVariables)
	 * 		application.output(globalVariables[i].name + " has the default value of " + globalVariables[i].defaultValue);
	 * 
	 * @return an array of JSVariable type elements
	 * 
	 */
	public JSVariable[] js_getGlobalVariables()
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		ArrayList<JSVariable> variables = new ArrayList<JSVariable>();
		Iterator<ScriptVariable> scriptVariables = fs.getScriptVariables(true);
		while (scriptVariables.hasNext())
		{
			variables.add(new JSVariable(application, scriptVariables.next(), false));
		}
		return variables.toArray(new JSVariable[variables.size()]);
	}

	/**
	 * Creates a new global method with the specified code.
	 *
	 * @sample 
	 *  var method = solutionModel.newGlobalMethod('function myglobalmethod(){currentcontroller.newRecord()}')
	 *
	 * @param code the specified code for the global method
	 * 
	 * @return a JSMethod object
	 */
	public JSMethod js_newGlobalMethod(String code)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		String name = JSMethod.parseName(code);

		try
		{
			ScriptMethod method = fs.getSolutionCopy().createNewGlobalScriptMethod(new ScriptNameValidator(application.getFlattenedSolution()), name);
			method.setDeclaration(code);
			application.getScriptEngine().getGlobalScope().put(method, method);
			return new JSMethod(application, method, true);
		}
		catch (RepositoryException e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * Gets an existing global method by the specified name.
	 *
	 * @sample 
	 * 	var method = solutionModel.getGlobalMethod("nameOfGlobalMethod"); 
	 * 	if (method != null) application.output(method.code);
	 * 
	 * @param name the name of the specified global method
	 * 
	 * @return a JSMethod
	 */
	public JSMethod js_getGlobalMethod(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		ScriptMethod sm = fs.getScriptMethod(name);
		if (sm != null)
		{
			return new JSMethod(application, sm, false);
		}
		return null;
	}

	/**
	 * Get a JSMethod instance with arguments to be assigned to an event.
	 *
	 * @sample 
	 * var str = "John's Bookstore"
	 * var form = solutionModel.getForm('orders')
	 * var button = form.getButton('abutton')
	 * var method = form.getFormMethod('doit') // has 4 arguments: event (fixed), boolean, number and string
	 * // string arguments have to be quoted, they are interpreted before the method is called
	 * var quotedString = "'"+utils.stringReplace(str, "'", "\\'")+"'"
	 * // list all arguments the method has, use nulls for fixed arguments (like event)
	 * button.onAction = solutionModel.newMethodWithArguments(method, null, true, 42, quotedString)
	 * 
	 * @param method JSMethod to be assigned to an event
	 * 
	 * @param args positional arguments
	 * 
	 * @return a JSMethod
	 */
	public JSMethod js_newMethodWithArguments(JSMethod method, Object... args)
	{
		if (method == null || args == null || args.length == 0)
		{
			return method;
		}
		return new JSMethodWithArguments(method, args);
	}

	/**
	 * The list of all global methods.
	 * 
	 * @sample
	 * 	var methods = solutionModel.getGlobalMethods(); 
	 * 	if (methods != null)
	 * 		for (var x in methods) 
	 * 			application.output(methods[x].getName());
	 * 
	 * @return an array of JSMethod type elements
	 * 
	 */
	public JSMethod[] js_getGlobalMethods()
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		ArrayList<JSMethod> methods = new ArrayList<JSMethod>();
		Iterator<ScriptMethod> scriptMethods = fs.getScriptMethods(true);
		while (scriptMethods.hasNext())
		{
			methods.add(new JSMethod(application, scriptMethods.next(), false));
		}
		return methods.toArray(new JSMethod[methods.size()]);
	}

	//newRelation(String name, String primaryServerName, String primaryTableName, String foreignServerName, String foreignTableName,int joinType) <b>
	//newRelation(String name, String primaryDatasource, String foreignDataSource,int joinType)
	/**
	 * Creates a new JSRelation Object with a specified name; includes the primary datasource, optional table name, foreign datasource, optional foreign table name, and the type of join for the new relation.
	 *
	 * @sample 
	 * var rel = solutionModel.newRelation('myRelation','myPrimaryServerName','myPrimaryTableName','myForeignServerName','myForeignTableName',JSRelation.INNER_JOIN);
	 * application.output(rel.getRelationItems()); 
	 *
	 * @param name the specified name of the new relation
	 *
	 * @param primary_server_name|primary_data_source the specified name of the primary server or datasource
	 *
	 * @param primary_table_name optional the specified name of the primary table
	 *
	 * @param foreign_server_name|foreign_data_source the specified name of the foreign server or datasource
	 *
	 * @param foreign_table_name optional the specified name of the foreign table
	 *
	 * @param join_type the type of join for the new relation; JSRelation.INNER_JOIN, JSRelation.LEFT_OUTER_JOIN
	 * 
	 * @return a JSRelation object
	 */
	public JSRelation js_newRelation(Object[] args)
	{
		String name = null;
		String primaryDataSource = null;
		String foreignDataSource = null;
		int joinType;

		FlattenedSolution fs = application.getFlattenedSolution();

		try
		{
			int a = 0;
			// name
			if (a < args.length && args[a] != null)
			{
				name = args[a++].toString();
			}
			// primary server data source or server+table
			if (a < args.length && args[a] != null)
			{
				String primary = args[a++].toString();
				if (primary.indexOf(':') < 0 && a < args.length && args[a] != null)
				{
					// not an uri, server/table combi
					String primaryTableName = args[a++].toString();
					IServer primaryServer = fs.getSolution().getServer(primary);
					if (primaryServer == null) throw new RuntimeException("cant create relation, primary server not found: " + primary); //$NON-NLS-1$
					if (primaryServer.getTable(primaryTableName) == null) throw new RuntimeException("cant create relation, primary table not found: " + //$NON-NLS-1$
						primaryTableName);

					primaryDataSource = DataSourceUtils.createDBTableDataSource(primary, primaryTableName);
				}
				else
				{
					// uri
					primaryDataSource = primary;
				}
			}
			// foreign server data source or server+table
			if (a < args.length && args[a] != null)
			{
				String foreign = args[a++].toString();
				if (foreign.indexOf(':') < 0 && a < args.length && args[a] != null)
				{
					// not an uri, server/table combi
					String foreignTableName = args[a++].toString();
					IServer foreignServer = fs.getSolution().getServer(foreign);
					if (foreignServer == null) throw new RuntimeException("cant create relation, foreign server not found: " + foreign); //$NON-NLS-1$
					if (foreignServer.getTable(foreignTableName) == null) throw new RuntimeException("cant create relation, foreign table not found: " + //$NON-NLS-1$
						foreignTableName);

					foreignDataSource = DataSourceUtils.createDBTableDataSource(foreign, foreignTableName);
				}
				else
				{
					// uri
					foreignDataSource = foreign;
				}
			}
			if (a < args.length && args[a] != null)
			{
				joinType = Utils.getAsInteger(args[a]);
			}
			else
			{
				return null;
			}
			if (name == null || primaryDataSource == null || foreignDataSource == null)
			{
				return null;
			}

			Relation relation = fs.getSolutionCopy().createNewRelation(new ScriptNameValidator(fs), name, primaryDataSource, foreignDataSource, joinType);
			return new JSRelation(relation, application, true);
		}
		catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}

	/**
	 * Gets an existing relation by the specified name and returns a JSRelation Object.
	 * 
	 * @sample 
	 * 	var relation = solutionModel.getRelation('name');
	 *	application.output("The primary server name is " + relation.primaryServerName);
	 * 	application.output("The primary table name is " + relation.primaryTableName); 
	 * 	application.output("The foreign table name is " + relation.foreignTableName); 
	 * 	application.output("The relation items are " + relation.getRelationItems());
	 * 
	 * @param name the specified name of the relation
	 * 
	 * @return a JSRelation
	 */
	public JSRelation js_getRelation(String name)
	{
		FlattenedSolution fs = application.getFlattenedSolution();
		Relation relation = fs.getRelation(name);
		if (relation != null)
		{
			return new JSRelation(relation, application, false);
		}
		return null;

	}

	/**
	 * Gets an array of all relations; or an array of all global relations if the specified table is NULL.
	 *
	 * @sample 
	 * 	var relations = solutionModel.getRelations('server_name','table_name');
	 * 	if (relations.length != 0)
	 * 		for (var i in relations)
	 * 			application.output(relations[i].name);
	 *
	 * @param primary_server_name/primary_data_source optional the specified name of the server or datasource for the specified table
	 *
	 * @param primary_table_name optional the specified name of the table
	 * 
	 * @return an array of all relations (all elements in the array are of type JSRelation)
	 */
	public JSRelation[] js_getRelations(Object[] args)
	{
		FlattenedSolution fs = application.getFlattenedSolution();

		try
		{
			String servername = null;
			String tablename = null;
			if (args.length == 2)
			{
				servername = (String)args[0];
				tablename = (String)args[1];
			}
			Table primaryTable = null;
			if (servername != null && tablename != null)
			{
				IServer primaryServer = fs.getSolution().getServer(servername);
				if (primaryServer == null) throw new RuntimeException("cant create relation, primary server not found: " + servername); //$NON-NLS-1$
				primaryTable = (Table)primaryServer.getTable(tablename);
				if (primaryTable == null) throw new RuntimeException("cant create relation, primary table not found: " + tablename); //$NON-NLS-1$
			}

			List<JSRelation> relations = new ArrayList<JSRelation>();
			Iterator<Relation> iterator = fs.getRelations(primaryTable, true, true);
			while (iterator.hasNext())
			{
				Relation relation = iterator.next();
				if ((primaryTable == null && relation.isGlobal()) || (primaryTable != null && !relation.isGlobal()))
				{
					relations.add(new JSRelation(relation, application, false));
				}
			}
			return relations.toArray(new JSRelation[relations.size()]);
		}
		catch (Exception e)
		{
			throw new RuntimeException(e);
		}
	}


	/**
	 * @see java.lang.Object#toString()
	 */
	@Override
	public String toString()
	{
		return "SolutionModel"; //$NON-NLS-1$
	}

	public void destroy()
	{
		application = null;
	}
}
