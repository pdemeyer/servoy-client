name: 'svy-listbox',
displayName: 'ListBox',
definition: 'servoydefault/listbox/listbox.js',
libraries: [],
model:
{
        background : 'color', 
        borderType : 'border', 
        dataProviderID : { 'type':'dataprovider', scope:'design', 'ondatachange': { 'onchange':'onDataChangeMethodID', 'callback':'onDataChangeCallback'}}, 
        editable : {type:'boolean', default:true}, 
        enabled : {type:'boolean', default:true}, 
        fontType : 'font', 
        foreground : 'color', 
        format : {for:'dataProviderID' , type:'format'}, 
        horizontalAlignment : {type:'int', scope:'design', values:[{LEFT:2}, {CENTER:0},{RIGHT:4}],default: -1}, 
        location : 'point', 
        margin : {type:'dimension', scope:'design'}, 
        multiselectListbox : 'boolean', 
        placeholderText : 'tagstring', 
        scrollbars : {type:'int', scope:'design'}, 
        size : {type:'dimension',  default: {width:140, height:140}}, 
        styleClass : { type:'styleclass', scope:'design', values:['form-control', 'input-sm', 'svy-padding-xs']}, 
        tabSeq : {type:'tabseq', scope:'design'}, 
        text : 'tagstring', 
        toolTipText : 'tagstring', 
        transparent : 'boolean', 
        valuelistID : { type: 'valuelist', scope:'design', for: 'dataProviderID'}, 
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
        getScrollX: {
            returns: 'int'
        },
        getScrollY: {
            returns: 'int'
        },
        getSelectedElements: {
            returns: 'object []'
        },
        requestFocus: {
            parameters:[{'mustExecuteOnFocusGainedMethod':'boolean','optional':'true'}]
        },
        setScroll: {
            parameters:[{'x':'int'},{'y':'int'}]
        },
        setValueListItems: {
            parameters:[{'value':'dataset'}]
        }
}
 
