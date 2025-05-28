function fartOnDexclassloader() {
    Java.perform(function () {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        var ActivityThread = Java.use("android.app.ActivityThread");

        DexClassLoader.$init.overload(
            'java.lang.String',     // dexPath
            'java.lang.String',     // optimizedDirectory
            'java.lang.String',     // librarySearchPath
            'java.lang.ClassLoader' // parent
        ).implementation = function (dexPath, optimizedDirectory, libPath, parent) {
            console.log("[+] DexClassLoader created:");
            console.log("    |- dexPath: " + dexPath);
            console.log("    |- optimizedDirectory: " + optimizedDirectory);
            console.log("    |- libPath: " + libPath);

            var cl = this.$init(dexPath, optimizedDirectory, libPath, parent);

            // 调用 fart 方法
            try {
                console.log("[*] Calling fartWithClassLoader...");
                ActivityThread.fartwithClassloader(this);
                console.log("[+] fartWithClassLoader finished.");
            } catch (e) {
                console.error("[-] Error calling fartWithClassLoader:", e);
            }

            return cl;
        };
    });
}


setImmediate(fartOnDexclassloader)


// frida -H 127.0.0.1:1234 -l fart_on_dexclassloader.js -f com.cyrus.example