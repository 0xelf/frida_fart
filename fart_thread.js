function fartThread() {
    Java.perform(function () {
        const ActivityThread = Java.use('android.app.ActivityThread')

        // 修改 dumpEnabled 为 true
        const Cyrus = Java.use('android.app.Cyrus')
        if (Cyrus) {
            console.log("[*] Cyrus.isDumpEnabled() before: " + Cyrus.isDumpEnabled());

            // 使用 Java 反射修改 private static 字段 dumpEnabled
            var clazz = Cyrus.class;
            var field = clazz.getDeclaredField("dumpEnabled");
            field.setAccessible(true);
            field.setBoolean(null, true);

            console.log("[*] Cyrus.isDumpEnabled() after: " + Cyrus.isDumpEnabled());
        }

        // Context
        var app = ActivityThread.currentApplication();
        console.log("Current Application: " + app);

        // 启动脱壳线程
        ActivityThread.launchInspectorThread(app)
    })
}

setImmediate(fartThread)

// frida -H 127.0.0.1:1234 -F -l fart_thread.js