name: 'svy-radiogroup',
displayName: 'Radio group',
definition: 'servoydefault/radiogroup/radiogroup.js',
libraries: [],
model:
{
        background : 'color', 
        borderType : 'border', 
        dataProviderID : { 'type':'dataprovider', 'ondatachange': { 'onchange':'onDataChangeMethodID', 'callback':'onDataChangeCallback'}}, 
        editable : {type:'boolean', default:true}, 
        enabled : {type:'boolean', default:true}, 
        fontType : 'font', 
        foreground : 'color', 
        format : {for:'dataProviderID' , type:'format'}, 
        horizontalAlignment : {type:'int', values:[{DEFAULT:-1}, {LEFT:0}, {CENTER:2},{RIGHT:4}]}, 
        location : 'point', 
        margin : 'dimension', 
        placeholderText : 'tagstring', 
        scrollbars : 'int', 
        size : 'dimension', 
        styleClass : { type:'styleclass', values:['form-control', 'input-sm', 'svy-padding-xs']}, 
        tabSeq : 'tabseq', 
        text : 'tagstring', 
        toolTipText : 'tagstring', 
        transparent : 'boolean', 
        valuelistID : { type: 'valuelist', for: 'dataProviderID'}, 
        verticalAlignment : {type:'int', values:[{DEFAULT:-1}, {TOP:1}, {CENTER:2} ,{BOTTOM:3}]}, 
        visible : {type:'boolean', default:true} 
},
handlers:
{
        onActionMethodID : 'function', 
        onDataChangeMethodID : 'function', 
        onFocusGainedMethodID : 'function', 
        onFocusLostMethodID : 'function', 
        onRenderMethodID : 'function', 
        onRightClickMethodID : 'function' 
},
api:
{
        getScrollX:{
            returns: 'int',
                 }, 
        getScrollY:{
            returns: 'int',
                 }, 
        getSelectedElements:{
            returns: 'object []',
                 }, 
        requestFocus:{
            
            parameters:[{'mustExecuteOnFocusGainedMethod':'boolean','optional':'true'}]
        }, 
        setScroll:{
            
            parameters:[{'x':'int'},{'y':'int'}]
        }, 
        setValueListItems:{
            
            parameters:[{'value':'object'}]
        } 
}
 
