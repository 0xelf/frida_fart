function findClassLoader(targetClassName) {
    let foundLoader = null;

    try {
        Java.enumerateClassLoaders({
            onMatch: function (loader) {
                try {
                    const clazz = loader.loadClass(targetClassName);
                    if (clazz) {
                        console.log("[+] Found class in loader: " + loader.toString());
                        foundLoader = loader;
                        throw "found"; // 快速退出枚举
                    }
                } catch (e) {
                    // Ignore: class not found in this loader
                }
            },
            onComplete: function () {
            }
        });
    } catch (e) {
        if (e !== "found") {
            console.log("[-] ClassLoader enumeration error: " + e);
        }
    }

    if (!foundLoader) {
        console.log("[-] Could not find class: " + targetClassName);
    }

    return foundLoader
}

function findDumpMethodCodeMethod(){

    let dumpMethodCodeMethod = null;

    // 反射获取 nativeDumpCode 方法
    try {
        const DexFile = Java.use("dalvik.system.DexFile");
        const dexFileClazz = DexFile.class;
        const declaredMethods = dexFileClazz.getDeclaredMethods();

        for (let i = 0; i < declaredMethods.length; i++) {
            const m = declaredMethods[i];
            if (m.getName().toString() === "nativeDumpCode") {
                m.setAccessible(true);
                dumpMethodCodeMethod = m;
                break;
            }
        }

        if (!dumpMethodCodeMethod) {
            console.log("[-] nativeDumpCode not found in DexFile");
            return;
        }

        console.log("[+] nativeDumpCode Method: " + dumpMethodCodeMethod.toString());

    } catch (err) {
        console.log("[-] Exception: " + err);
    }

    return dumpMethodCodeMethod
}

function invokeClass(targetClassName, dumpMethodCodeMethod) {

    let foundLoader = findClassLoader(targetClassName)

    const ActivityThread = Java.use("android.app.ActivityThread");

    // 调用 ActivityThread.dispatchClassTask(loader, className, dumpMethodCodeMethod)
    if (ActivityThread.dispatchClassTask) {
        console.log('[load] dispatchClassTask: ' + targetClassName);
        ActivityThread.dispatchClassTask(foundLoader, targetClassName, dumpMethodCodeMethod);
    } else {
        console.log("[-] ActivityThread.dispatchClassTask not found");
    }
}


setImmediate(function () {
    Java.perform(function () {

        let dumpMethodCodeMethod = findDumpMethodCodeMethod()

        // TODO: 替换为你的目标类
        invokeClass("com.cyrus.example.plugin.FartTest", dumpMethodCodeMethod)
    })
})

// frida -H 127.0.0.1:1234 -F -l fart_invoke_class.js