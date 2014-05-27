angular.module('svyRadiogroup',['servoy']).directive('svyRadiogroup', function($utils) {  
    return {
      restrict: 'E',
      transclude: true,
      scope: {
        model: "=svyModel",
        handlers: "=svyHandlers",
        api: "=svyApi"
      },
      controller: function($scope, $element, $attrs) {
          $scope.notNullOrEmpty = $utils.notNullOrEmpty // TODO remove the need for this
          $scope.style = {width:'100%',height:'100%'}
          angular.extend($scope.style ,$utils.getScrollbarsStyleObj($scope.model.scrollbars));
          
          $scope.api.setScroll = function(x, y) {
         	 $element.scrollLeft(x);
         	 $element.scrollTop(y);
          }
          
          $scope.api.getScrollX = function() {
         	 return $element.scrollLeft();
          }
          
          $scope.api.getScrollY = function() {
         	 return $element.scrollTop();
          }
          
          $scope.api.setValueListItems = function(values) 
          {
        	  var valuelistItems = [];
        	  for (var i = 0; i < values.length; i++)
        	  {
        		  var item = {};
        		  item['displayValue'] = values[i][0];
        		  if (values[i][1] !== undefined)
        		  {
        			  item['realValue'] = values[i][1];
        		  }
        		  valuelistItems.push(item); 
        	  }
        	  $scope.model.valuelistID = valuelistItems;
          }
      },
      templateUrl: 'servoydefault/radiogroup/radiogroup.html',
      replace: true
    };
  })

  
  
  
  
