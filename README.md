# :joystick: apk.sh
apk.sh is a Bash script that makes reverse engineering Android apps easier, automating some repetitive tasks like pulling, decoding, rebuilding and patching an APK.


## Features
apk.sh basically uses [apktool](https://ibotpeaches.github.io/Apktool/) to disassemble, decode and rebuild resources and some bash to automate the [frida](https://https://frida.re/) gadget injection process.
It also supports app bundles/split APKs. 

 -  :mushroom: Patching APKs to load frida-gadget.so on start.
 -  :new: Support for app bundles/split APKs.
 -  :wrench: Disassembling resources to nearly original form with apktool.
 -  :nut_and_bolt: Rebuilding decoded resources back to binary APK/JAR with apktool.
 -  :old_key: Code signing the apk with apksigner.
 -  :desktop_computer: Multiple arch support (arm, arm64, x86, x86_64). 
 -  :no_mobile_phones: No rooted Android device needed.


## Getting started
:arrow_left: Pulling an APK from a device is simple as running `./apk.sh pull <package_name>`

:wrench: Decoding an APK is simple as running `./apk.sh decode <apk_name>`

:nut_and_bolt: Rebuilding an APK is simple as running  `./apk.sh build <apk_dir>`


## apk.sh pull
`apk.sh pull` pull an APK from a device.
It supports app bundles/split APKs, which means that split APKs will be joined in a single APK (this is useful for patching). 
If the package is an app bundle/split APK, apk.sh will combine the APKs into a single APK, fixing all public resource identifiers.


## apk.sh patch
`apk.sh patch` patch an APK to load [frida-gadget.so](https://frida.re/docs/gadget/) on start.

frida-gadget.so is a Frida's shared library meant to be loaded by programs to be instrumented (when the Injected mode of operation isn’t suitable). By simply loading the library it will allow you to interact with it using existing Frida-based tools like frida-trace. It also supports a fully autonomous approach where it can run scripts off the filesystem without any outside communication.

Patching an APK is simple as running  `./apk.sh patch <apk_name> --arch arm`.

You can calso specify a Frida gadget configuration in a json `./apk.sh patch <apk_name> --arch arm --gadget-conf <config.json>`

## :mushroom: Frida's Gadget configurations
In the default interaction, Frida Gadget exposes a frida-server compatible interface, listening on localhost:27042 by default. In order to achieve early instrumentation Frida let Gadget’s constructor function block until you either `attach()` to the process, or call `resume()` after going through the usual `spawn()` -> `attach()` -> `...apply instrumentation...` steps.

If you don’t want this blocking behavior and want to let the program boot right up, or you’d prefer it listening on a different interface or port, you can customize this through a json configuration file.

The default configuration is:
```json
{
  "interaction": {
    "type": "listen",
    "address": "127.0.0.1",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```

You can pass the gadget configuration file to `apk.sh` with the `--gadget-conf` option.

A typically suggested configuration might be:
```json
{
  "interaction": {
    "type": "script",
    "path": "/data/local/tmp/script.js",
    "on_change":"reload"
  }
}
```

script.js could be something like:

```javascript
var android_log_write = new NativeFunction(
    Module.getExportByName(null, '__android_log_write'),
    'int',
    ['int', 'pointer', 'pointer']
);

var tag = Memory.allocUtf8String("[frida-sript][ax]");



var work = function() {
    setTimeout(function() {
        android_log_write(3, tag, Memory.allocUtf8String("ping @ " + Date.now()));
        work();
    }, 1000);
}
work();

// console.log does not seems to work. see: https://github.com/frida/frida/issues/382
console.log("console.log");
console.error("console.error");
console.warn("WARN");
android_log_write(3, tag, Memory.allocUtf8String(">--(O.o)-<)");
```
`adb push script.js /data/local/tmp`
`./apk.sh patch <apk_name> --arch arm --gadget-conf <config.json>`
`adb install file.gadget.apk`

## Requirements

- apktool
- apksigner
- unxz
- zipalign
- aapt
- adb


## :page_with_curl: Links of Interest
https://frida.re/docs/gadget/

https://lief-project.github.io/doc/latest/tutorials/09_frida_lief.html

https://koz.io/using-frida-on-android-without-root/

https://github.com/sensepost/objection/

https://github.com/NickstaDB/patch-apk/

https://neo-geo2.gitbook.io/adventures-on-security/frida-scripting-guide/frida-scripting-guide
