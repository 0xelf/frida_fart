// 前缀过滤逻辑
function shouldSkipClass(name) {
    return name.startsWith("androidx.") ||
        name.startsWith("android.") ||
        name.startsWith("org.jetbrains.") ||
        name.startsWith("kotlinx.") ||
        name.startsWith("kotlin.") ||
        name.startsWith("org.intellij.");
}

function hookLoadClassAndInvoke() {
    const ActivityThread = Java.use('android.app.ActivityThread');

    if (ActivityThread.dispatchClassTask) {
        ActivityThread.dispatchClassTask.implementation = function (classloader, className, method) {
            if (shouldSkipClass(className)) {
                console.log('[skip] dispatchClassTask: ' + className);
                return; // 不调用原函数
            }

            console.log('[load] dispatchClassTask: ' + className);
            return this.dispatchClassTask(classloader, className, method); // 正常调用
        };
    } else {
        console.log('[-] ActivityThread.dispatchClassTask not found');
    }
}

function fartOnDexclassloader() {
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

        // 调用 startCodeInspection 方法
        try {
            console.log("[*] Calling fartWithClassLoader...");
            ActivityThread.startCodeInspectionWithCL(this);
            console.log("[+] fartWithClassLoader finished.");
        } catch (e) {
            console.error("[-] Error calling fartWithClassLoader:", e);
        }

        return cl;
    };
}


setImmediate(function () {
    Java.perform(function () {
        hookLoadClassAndInvoke()
        fartOnDexclassloader()
    })
})


// frida -H 127.0.0.1:1234 -l fart_loadClassAndInvoke_filter.js -f com.cyrus.example -o log.txt