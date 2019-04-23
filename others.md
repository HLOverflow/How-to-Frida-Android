# Non-frida notes

## Finding hidden Activity

Sometimes, an app has hidden activity that is not reachable from MAIN LAUNCHER.
We need to take a look at AndroidManifest.xml file to find all activities defined.

It is possible to draw a transition diagram to map out the transitions of the activities where the activities not found reachable by transitions are considered hidden ones.

## Accessing hidden Activity

Using Drozer shell, we can do a few cool tricks.

### Drozer Server

Like Frida server, our drozer server has to be on the android phone. Instead of command-line, drozer is a mobile app. Launching drozer will open up a random port that our drozer client can connect to. The APK can be downloaded from [here](https://labs.mwrinfosecurity.com/tools/drozer/).

### Connecting Drozer

```sh
-> % drozer console connect --server 192.168.56.101:31415
:0: UserWarning: You do not have a working installation of the service_identity module: 'No module named service_identity'.  Please install it from <https://pypi.python.org/pypi/service_identity> and make sure all of its dependencies are satisfied.  Without the service_identity module, Twisted can perform only rudimentary TLS client hostname verification.  Many valid certificate/hostname mappings may be rejected.
Selecting bb136700a5ee361e (Genymotion APP-PT8.0 8.0.0)

            ..                    ..:.
           ..o..                  .r..
            ..a..  . ....... .  ..nd
              ro..idsnemesisand..pr
              .otectorandroidsneme.
           .,sisandprotectorandroids+.
         ..nemesisandprotectorandroidsn:.
        .emesisandprotectorandroidsnemes..
      ..isandp,..,rotectorandro,..,idsnem.
      .isisandp..rotectorandroid..snemisis.
      ,andprotectorandroidsnemisisandprotec.
     .torandroidsnemesisandprotectorandroid.
     .snemisisandprotectorandroidsnemesisan:
     .dprotectorandroidsnemesisandprotector.

drozer Console (v2.4.4)
dz> help

drozer: Android Security Assessment Framework

Type `help COMMAND` for more information on a particular command, or `help
MODULE` for a particular module.

Commands:

cd     contributors  env   help  load    permissions  set    unset
clean  echo          exit  list  module  run          shell

Miscellaneous help topics:

intents

dz> list
app.activity.forintent                  Find activities that can handle the given intent                          
app.activity.info                       Gets information about exported activities.                               
app.activity.start                      Start an Activity                                                         
app.broadcast.info                      Get information about broadcast receivers                                 
app.broadcast.send                      Send broadcast using an intent                                            
app.broadcast.sniff                     Register a broadcast receiver that can sniff particular intents           
app.package.attacksurface               Get attack surface of package                                             
app.package.backup                      Lists packages that use the backup API (returns true on FLAG_ALLOW_BACKUP)
app.package.debuggable                  Find debuggable packages                                                  
app.package.info                        Get informa..........
...............

```

By looking at the commands listed above, we can see that drozer can be used for information gathering / sending intents without having to build an app / starting activities...


### Some Drozer Commands

Showing permissions
```sh
dz> run app.package.info -f <app name>
```

Find out exported activities
```sh
dz> run app.activity.info -a <app identifier>
```

Start the exported activity
```sh
dz> run app.activity.start --component <app identifier> <activity full qualified name>
```

Finding attack surface
```sh
run app.package.attacksurface
```


