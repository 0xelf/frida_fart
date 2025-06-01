function fartThread() {
    Java.perform(function () {
        const ActivityThread = Java.use('android.app.ActivityThread')
        ActivityThread.launchInspectorThread()
    })
}

setImmediate(fartThread)

// frida -H 127.0.0.1:1234 -F -l fart_thread.js