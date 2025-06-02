// 前缀过滤逻辑
function shouldLoadClass(name) {
    return name.startsWith("ff.")
}

function hookLoadClassAndInvoke() {
    const ActivityThread = Java.use('android.app.ActivityThread');

    if (ActivityThread.dispatchClassTask) {
        ActivityThread.dispatchClassTask.implementation = function (classloader, className, method) {
            if (shouldLoadClass(className)) {
                console.log('[load] dispatchClassTask: ' + className);
                return this.dispatchClassTask(classloader, className, method); // 正常调用
            }
            console.log('[skip] dispatchClassTask: ' + className);
            return; // 不调用原函数
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

function invokeAllClassloaders() {
    try {
        // 获取 ActivityThread 类
        var ActivityThread = Java.use("android.app.ActivityThread");

        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    // 过滤掉 BootClassLoader
                    if (loader.toString().includes("BootClassLoader")) {
                        console.log("[-] 跳过 BootClassLoader");
                        return;
                    }

                    // 调用 fartWithClassLoader
                    console.log("[*] 调用 startCodeInspectionWithCL -> " + loader);
                    ActivityThread.startCodeInspectionWithCL(loader);
                } catch (e) {
                    console.error("[-] 调用失败: " + e);
                }
            },
            onComplete: function () {
                console.log("[*] 枚举并调用完毕");
            }
        });
    } catch (err) {
        console.error("[-] 脚本执行异常: " + err);
    }
}


setImmediate(function () {
    Java.perform(function () {
        // 过滤不需要主动调用的类
        hookLoadClassAndInvoke()
        // 解决局部变量的 ClassLoader 枚举不出来问题
        fartOnDexclassloader()
        // 解决非双亲委派关系下动态加载的 dex 脱壳问题
        invokeAllClassloaders()
    })
})

// frida -H 127.0.0.1:1234 -F -l fart_filter.js -o log.txt