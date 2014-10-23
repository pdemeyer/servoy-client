
describe('servoydefaultTextfield component', function() {
	//jasmine.DEFAULT_TIMEOUT_INTERVAL = 1000;
    var $scope 
    var $compile  
	var $httpBackend 
	var $timeout
	var handlersMock = {			
    		myTextfield: {
				svy_apply : function(property, beanModel, rowId){
					 
				},
				svy_servoyApi: {
					setFormEnabled: function (formname, enabled) {
						
					},
					setFormReadOnly: function (formname, readOnly) {
						
					},
					showForm: function(formname,relationname,formIndex) {
					},
					hideForm: function(formname,relationname,formIndex) {
					},
					getFormUrl: function (formId) {
						
					}
				},
			}
	}
	var modelMock = {
			myTextfield: {
				   enabled:true,
				   dataProviderID:"some data",
				   visible:true,
				   location:{
				      "x":89,
				      "y":43
				   },
				   size:{
				      "width":114,
				      "height":40
				   },
				   name:"myTextfield"
				}	}
    var apiMock ={
    		myTextfield:{
    		
    	}
    }
	
	beforeEach(function(){		
	  module('servoy-components')  // generated by ngHtml2JsPreprocessor from all .html template files , as strings in the svyTemplate module
	   // 1. Include your application module for testing.
	  module(function ($provide) {
		  $provide.factory('$servoyInternal', function() {});
	  });
      module('servoydefaultTextfield');
	  
      // 2. Define a new mock module. (don't need to mock the servoy module for tabpanel since it receives it's dependencies with attributes in the isolated scope)
      // 3. Define a provider with the same name as the one you want to mock (in our case we want to mock 'servoy' dependency.
//      angular.module('servoyMock', [])
//          .factory('$X', function(){
//              // Define you mock behaviour here.
//          });

      // 4. Include your new mock module - this will override the providers from your original module.
//      angular.mock.module('servoyMock');

      // 5. Get an instance of the provider you want to test.
      inject(function(_$httpBackend_,_$rootScope_,_$compile_ ,$templateCache,_$q_,_$timeout_){
    	  
    	  $compile = _$compile_
    	  $timeout = _$timeout_
    	  $scope = _$rootScope_.$new();
    	  $scope.handlers = angular.copy(handlersMock);
    	  $scope.model= angular.copy(modelMock); 
    	  $scope.api= angular.copy(apiMock); 
  	  })
  	  
  	  // mock timout
	  jasmine.clock().install();
	});
    afterEach(function() {
        jasmine.clock().uninstall();
    })
      
    it("should have onaction", function() {
  		var template= '<data-servoydefault-textfield name="myTextfield" svy-model="model.myTextfield" svy-api="api.myTextfield" svy-handlers="handlers.myTextfield" '+
			'svy-apply="handlers.myTextfield.svy_apply" svy-servoyApi="handlers.myTextfield.svy_servoyApi"/>'
  		var clicked = false;
  		$scope.handlers.myTextfield.onActionMethodID = function(event) {
  			clicked = true;
  		}
        // This will find your directive and run everything
        var myTextfield = $compile(template)($scope);             
        // Now run a $digest cycle to update your template with new data
  		$scope.$digest();
//  		myTextfield.triggerHandler("click")
//  		expect( clicked).toBe(true);
	  });
    
    it("should have focusgained and focuslost", function() {
  		var template= '<data-servoydefault-textfield name="myTextfield" svy-model="model.myTextfield" svy-api="api.myTextfield" svy-handlers="handlers.myTextfield" '+
  				'svy-apply="handlers.myTextfield.svy_apply" svy-servoyApi="handlers.myTextfield.svy_servoyApi"/>'
  		var focus = false;
  		$scope.handlers.myTextfield.onFocusGainedMethodID = function(event) {
  			focus = true;
  		}
  		var blur = false; 
  		$scope.handlers.myTextfield.onFocusLostMethodID = function(event) {
			blur = true;
		}
        // This will find your directive and run everything
        var textComponent = $compile(template)($scope);             
        // Now run a $digest cycle to update your template with new data
 		$scope.$digest();
 		textComponent.triggerHandler("focus")
 		textComponent.triggerHandler("blur")
 		
 		expect( focus).toBe(true);
 		expect( blur).toBe(true);
	  });
    
    it("test action trigger only on enter key", function() {
  		var template= '<data-servoydefault-textfield name="myTextfield" svy-model="model.myTextfield" svy-api="api.myTextfield" svy-handlers="handlers.myTextfield" '+
  				'svy-apply="handlers.myTextfield.svy_apply" svy-servoyApi="handlers.myTextfield.svy_servoyApi"/>'
  		var onaction = false; 
  		$scope.handlers.myTextfield.onActionMethodID = function(event) {
  			onaction = true;
		}
        // This will find your directive and run everything
        var textComponent = $compile(template)($scope);             
        // Now run a $digest cycle to update your template with new data
 		$scope.$digest();
 		textComponent[0].triggerKey(65);
 		expect( onaction).toBe(false);
 		textComponent[0].triggerKey(13);
 		expect( onaction).toBe(true);
	  });
}); 
