function invokeAllClassloaders() {
    Java.perform(function () {
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
    });
}


setImmediate(invokeAllClassloaders)


// frida -H 127.0.0.1:1234 -F -l fart_invoke_all_classloaders.js
