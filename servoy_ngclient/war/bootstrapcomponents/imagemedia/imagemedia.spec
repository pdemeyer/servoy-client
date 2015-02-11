{
	"name": "bootstrapcomponents-imagemedia",
	"displayName": "Image Media",
	"version": 1,
	"icon": "servoydefault/imagemedia/IMG16.png",
	"definition": "bootstrapcomponents/imagemedia/imagemedia.js",
	"libraries": [],
	"model":
	{
			"alternate" : { "type" : "tagstring" }, 
	        "dataProviderID" : { "type":"dataprovider", "tags": { "scope" :"design" }, "ondatachange": { "onchange":"onDataChangeMethodID", "callback":"onDataChangeCallback"}}, 
	        "styleClass" : { "type" :"styleclass", "tags": { "scope" :"design" }, "values" :["img-responsive","img-rounded","img-circle", "img-thumbnail","media-object"]} 
	},
	"handlers":
	{
			"onActionMethodID" : "function",
	        "onRightClickMethodID" : "function" 
	},
	"api":
	{
	
	}
	 
}