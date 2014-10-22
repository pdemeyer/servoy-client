{
	"name": "servoydefault-portal",
	"displayName": "Portal",
	"icon": "servoydefault/portal/portal.gif",
	"definition": "servoydefault/portal/portal.js",
	"libraries": [{"name":"svy-portal.css", "version":"1", "url":"servoydefault/portal/portal.css", "mimetype":"text/css"},
				{"name":"ui-grid", "version":"v3.0.0-rc.12", "url":"servoydefault/portal/js/ui-grid.js", "mimetype":"text/javascript"},
				{"name":"ui-grid", "version":"v3.0.0-rc.12", "url":"servoydefault/portal/css/ui-grid.min.css", "mimetype":"text/css"}],
	"model":
	{
	        "background" : "color", 
	        "borderType" : "border", 
	        "childElements" : { "type" : "component[]", "elementConfig" : {"forFoundsetTypedProperty": "relatedFoundset"} }, 
	        "enabled" : {"type":"boolean", "default":true}, 
	        "foreground" : "color", 
	        "headerHeight" : {"type" :"int",  "default" : 32}, 
	        "initialSort" : "string", 
	        "intercellSpacing" : "dimension", 
	        "location" : "point", 
	        "multiLine" : "boolean", 
	        "relatedFoundset" : "foundset", 
	        "reorderable" : "boolean", 
	        "resizable" : "boolean", 
	        "resizeble" : "boolean", 
	        "rowBGColorCalculation" : "string", 
	        "rowHeight" : "int", 
	        "scrollbars" : {"type" :"int", "scope" :"design"}, 
	        "showHorizontalLines" : "boolean", 
	        "showVerticalLines" : "boolean", 
	        "size" : {"type" :"dimension",  "default" : {"width":200, "height":200}}, 
	        "sortable" : "boolean", 
	        "styleClass" : "string", 
	        "tabSeq" : {"type" :"tabseq", "scope" :"design"}, 
	        "transparent" : "boolean", 
	        "visible" : {"type":"boolean", "default":true} 
	},
	"handlers":
	{
	        "onDragEndMethodID" : "function", 
	        "onDragMethodID" : "function", 
	        "onDragOverMethodID" : "function", 
	        "onDropMethodID" : "function", 
	        "onRenderMethodID" : "function" 
	},
	"api":
	{
	        "deleteRecord": {
	
	        },
	        "duplicateRecord": {
				"parameters":[
								{                                                                 
 								"name":"addOnTop",
								"type":"boolean",
			            		"optional":true
			            		}             
							 ]
	        },
	        "getMaxRecordIndex": {
	            "returns": "int"
	        },
	        "getScrollX": {
	            "returns": "int"
	        },
	        "getScrollY": {
	            "returns": "int"
	        },
	        "getSelectedIndex": {
	            "returns": "int"
	        },
	        "getSortColumns": {
	            "returns": "string"
	        },
	        "newRecord": {
				"parameters":[
								{                                                                 
 								"name":"addOnTop",
								"type":"boolean",
			            		"optional":true
			            		}             
							 ]
	        },
	        "setScroll": {
				"parameters":[
								{                                                                 
 								"name":"x",
								"type":"int"
			                	},
             					{                                                                 
 								"name":"y",
								"type":"int"
			                	}             
							 ]
	        },
	        "setSelectedIndex": {
				"parameters":[
								{                                                                 
 								"name":"index",
								"type":"int"
			                	}             
							 ]
	        }
	}
	 
}