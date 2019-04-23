# Frida Java API

Due to privacy, i will redact the actual app name with APP

The following is written by refering the Javascript API from [here](https://www.frida.re/docs/javascript-api/#java).

## Usage of callbacks

*Template of callback*

```javascript
var callback = { 
	'onMatch': function(arg1){ 
		console.log(arg1); 
	}, 
	'onComplete': function() {
		console.log("done"); 
	},
	'onError': function(){
		console.log("There is error");
	}
};

```
The above is how you can define a callback javascript object. The number of arguments passed does not matter. If the API invoke does not use up till the second / third /... parameter, those parameters will return as undefine.

## JVM Thread

Running most of frida's Java API code will require us to obtain the thread that has access to the VM.
There is a wrapper Java API that helps us achieve that.

```javascript
Java.perform(function(){
        //put what ever you would like to execute inside here.
});
```

With these, we can start enumerating the classes from our android app.

## Example

### Enumerating classes being loaded on runtime.

*enumclasses.js*
```javascript
var callback = {
	'onMatch': function(cname){
		//lets just print out the class name.
		console.log(cname);
	},
	'onComplete': function() {
		console.log("done");
	},
	'onError': function(){
		console.log("There is error");
	}
};

Java.perform(function(){
	Java.enumerateLoadedClasses(callback);	//onMatch: function (className)
});
```
The above will print out class names from the application.

```sh
-> % frida -U -f APP --no-pause -l enumclasses.js
     ____
    / _  |   Frida 12.4.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Spawned `APP`. Resuming main thread!
[Genymotion APP-PT8.0::APP]-> org.apache.http.ProtocolVersion
org.apache.http.HttpResponse
org.apache.http.message.AbstractHttpMessage
org.apache.http.HttpHost
org.apache.http.conn.params.ConnPerRoute
org.apache.http.impl.conn.tsccm.RefQueueWorker
org.apache.http.conn.params.ConnManagerParams
org.apache.http.params.AbstractHttpParams
org.apache.http.impl.conn.IdleConnectionHandler
org.apache.http.conn.ConnectionReleaseTrigger
org.apache.http.HttpRequestInterceptor
org.apache.commons.logging.impl.WeakHashtable
org.apache.commons.logg......
....
```
Awesome! We can access class names. With this, we can start building on more actions we would like to take with the class name.

Note that the classes dumped are classes accessible by class loader during runtime.
Java uses lazy class loading which means that classes are only loaded when first encountered.
Hence, if an activity does not get executed, classes that are not yet encountered will not be dumped.

## Changing a class's method implementation

Supposed there is a method from a package ( `com.scottyab.rootbeer`) that check if a phone has been rooted using a method call ( `RootBeer.isRooted()` ).

Main idea:
1. We can access the class directly using its full name obtained by decompiling the apk.
2. Modify the implementation.
3. Trigger the correct Activity and appropriate sequence of actions to reach the code we are targetting --> the invocation will run our implementation instead of the actual compiled byte code.
( See others.md for starting hidden activities )

*BypassRoot.js*
```javascript
Java.perform(function(){
	//The Java "use" helps us load the class into memory --> return a javascript wrapper of the class.
	//we can access methods using dot notation and overwrite its implementation.
	var RootBeer = Java.use("com.scottyab.rootbeer.RootBeer");
	RootBeer.isRooted.implementation = function(){
		console.log("RootBeer isRooted returns false");
		return false;
	}

});
```
Basically, we are overwriting the method isRooted() to always return false.

```sh
-> % frida -U -p 6713 -l bypassrootcheck.js --no-pause 
     ____
    / _  |   Frida 12.4.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
                                                                                
[Genymotion APP-PT8.0::PID::6713]-> RootBeer isRooted returns false
RootBeer isRooted returns false
[Genymotion APP-PT8.0::PID::6713]->
```
The app Activity was started and frida was used to hook onto the specific running process via pid.
After performing the action that trigger the root check, we see that our console printed out "RootBeer isRooted returns false".

