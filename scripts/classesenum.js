var callback = { 
	'onMatch': function(cname){
		if(cname.indexOf("com.") != -1){
			console.log(cname); 
		}
	}, 
	'onComplete': function() {
		console.log("done"); 
	},
	'onError': function(){
		console.log("There is error");
	}
};

Java.perform(function(){
	Java.enumerateLoadedClasses(callback);
});
