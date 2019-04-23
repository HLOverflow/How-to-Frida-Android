# Frida Android Set up 101

## Short Summary
Given a process, frida allows us to intercept the memory of the process.
We can dump classes/modules/functions.
We can intercept functions/method invocation to read arguments / return values.
We can modify these arguments / return values --> allow us to do cool bypasses without having to recompile the target binary/application (oh no... all the packaging and jar signing nightmares...).

## Set Up
1. Install genymotion.
2. Install the app in genymotion
3. Check if device is accessible

```sh
-> % adb devices
List of devices attached
192.168.56.101:5555	device
```
This means that the device is successfully connected via USB.

4. Shell access

```sh
-> % adb shell
vbox86p:/ #
```
Ok, we have shell access. Genymotion comes with root by default. Yay, no jail breaking needed!

5. Set up frida server inside android. It has to be inside android because we are going to intercept target process.

```sh
-> % frida-ps -U
Failed to enumerate processes: unable to connect to remote frida-server: closed
```
The above is what you get when frida server is not running.


Firstly, check your host's frida version. 
```sh
-> % frida --version
12.4.8
```

Secondly, check the architecture of the android with the adb shell like the following.
```sh
vbox86p:/tmp # uname -a
Linux localhost 4.4.34-genymotion #4 SMP PREEMPT Mon Oct 1 15:25:53 CEST 2018 i686
```

Taking note of the above frida version and the target architecture, we have to find the correct binary from [here](https://github.com/frida/frida/releases). I chosed `frida-server-12.4.8-android-x86.xz`, you have to choose the correct one depending on the above checks.

6. Extract with 7z and upload the file to android.

```sh
-> % adb push frida-server-12.4.8-android-x86 /tmp
frida-server-12.4.8-android-x86: 1 file pushed. 79.4 MB/s (32873600 bytes in 0.395s)
```


7. Run the frida server inside adb shell

```sh
vbox86p:/tmp # chmod +x frida-server-12.4.8-android-x86
vbox86p:/tmp # ./fri
frida-server                          frida-server-12.4.8-android-x86
vbox86p:/tmp # ./frida-server-12.4.8-android-x86 -l 0.0.0.0 -D
vbox86p:/tmp # ps -A | grep frida
root          4186     1   97064  56356 poll_schedule_timeout e85e1ba9 S frida-server-12.4.8-android-x86
root          4190  4186   13272   4720 poll_schedule_timeout ec079ba9 S frida-helper-32
```

8. Test if frida server is set up properly.

```sh
-> % frida-ls-devices
Id                   Type    Name
-------------------  ------  --------------------------
local                local   Local System
192.168.56.101:5555  usb     Genymotion APP-PT8.0
tcp                  remote  Local TCP

-> % frida-ps -U
 PID  Name
----  -----------------------------------------------
 154  adbd
 373  android.hardware.camera.provider@2.4-service
 374  android.hardware.configstore@1.0-service
 399  android.hardware.gnss@1.0-service
 375  android.hardware.graphics.allocator@2.0-service
 139  android.hardware.keymaster@3.0-service
 376  android.hardware.sensors@1.0-service
....
....

```

Cool. We're done with set up.

## View installed Apps

```sh
-> % frida-ps -Uai
 PID  Name                                           Identifier
----  ---------------------------------------------  ----------------------------------------------
 614  Android Keyboard (AOSP)                        com.android.inputmethod.latin
 504  Android System                                 android
1427  Blocked Numbers Storage                        com.android.providers.blockednumber
 504  Call Management                                com.android.server.telecom
2643  ConfigUpdater                                  com.google.android.configupdater
1427  Contacts Storage                               com.android.providers.contacts
 504  Fused Location                                 com.android.location.fused
2591  Google Partner Setup                           com.goog.............
```
I like to use this to find out the name of the app and its identifier.

## To launch an app

We can use the app's identifier as the filename to frida.

```sh
-> % frida -U -f com.android.calculator2 --no-pause
     ____
    / _  |   Frida 12.4.8 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Spawned `com.android.calculator2`. Resuming main thread!
[Genymotion CENTURION-PT8.0::com.android.calculator2]->
```
We should see a calculator pop up inside genymotion. The above is a frida console shell that accept frida's javascript. This console is useful because of the autocomplete feature. We can use this console to help us build our frida javascript scripts.




