function listActivityThreadMethods() {
    Java.perform(function () {
        try {
            var ActivityThread = Java.use("android.app.ActivityThread");
            console.log("[+] ActivityThread 类已找到");

            var methods = ActivityThread.class.getDeclaredMethods();
            for (var i = 0; i < methods.length; i++) {
                console.log("[+] " + methods[i].toString());
            }
        } catch (e) {
            console.error("[-] ActivityThread 类未加载或方法不存在: " + e);
        }
    });
}


// 调用
// mkdir("/sdcard/startCodeInspection/com.cyrus.example");
function mkdir(path) {
    const libc = Module.findExportByName(null, "mkdir");
    if (!libc) {
        console.error("[-] Cannot find mkdir symbol.");
        return;
    }

    const mkdirNative = new NativeFunction(libc, 'int', ['pointer', 'int']);

    const pathStr = Memory.allocUtf8String(path);
    const mode = 0o777; // 权限

    const result = mkdirNative(pathStr, mode);
    if (result === 0) {
        console.log("[+] mkdir success:", path);
    } else {
        const errnoLocation = Module.findExportByName(null, "__errno");
        if (errnoLocation) {
            const errnoPtr = new NativeFunction(errnoLocation, 'pointer', []);
            const errnoValue = Memory.readU32(errnoPtr());
            console.error("[-] mkdir failed errno:", errnoValue);
        } else {
            console.error("[-] mkdir failed");
        }
    }
}
