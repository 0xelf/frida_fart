> 版权归作者所有，如有转发，请注明文章出处：<https://cyrus-studio.github.io/blog/>

# FART 和 Frida 结合会发生什么？



对 FART 进一步增强：

1. 增强 FART 的脱壳能力：解决对抗 FART 的壳、动态加载的 dex 的 dump 和修复；

1. 控制 FART 主动调用的范围，让 FART 更精细化，比如按需进行类甚至是函数的修复。



# 非双亲委派关系下动态加载的 dex 脱壳问题



由于动态加载的 dex  没有取改变 android 中 ClassLoader 双亲委派关系，所以动态加载的 dex 没有自动脱壳。



相关文章：

- [Android 下的 ClassLoader 与 双亲委派机制](https://cyrus-studio.github.io/blog/posts/android-%E4%B8%8B%E7%9A%84-classloader-%E4%B8%8E-%E5%8F%8C%E4%BA%B2%E5%A7%94%E6%B4%BE%E6%9C%BA%E5%88%B6/)

- [Android 加壳应用运行流程 与 生命周期类处理方案](https://cyrus-studio.github.io/blog/posts/android-%E5%8A%A0%E5%A3%B3%E5%BA%94%E7%94%A8%E8%BF%90%E8%A1%8C%E6%B5%81%E7%A8%8B-%E4%B8%8E-%E7%94%9F%E5%91%BD%E5%91%A8%E6%9C%9F%E7%B1%BB%E5%A4%84%E7%90%86%E6%96%B9%E6%A1%88/)



在 android studio 中创建一个 plugin module 其中包含一个 FartTest 类源码如下：

```
package com.cyrus.example.plugin

import android.util.Log

class FartTest {

    fun test(): String {
        Log.d("FartTest", "call FartTest test().")
        return "String from FartTest."
    }

}
```


把 plugin-debug.apk push 到 files 目录下

```
adb push "D:\Projects\AndroidExample\plugin\build\intermediates\apk\debug\plugin-debug.apk" /sdcard/Android/data/com.cyrus.example/files/plugin-debug.apk
```


ls 一下 files 目录是否存在 plugin-debug.apk

```
adb shell ls /sdcard/Android/data/com.cyrus.example/files
```


在 app 动态加载 files 目录下的 plugin-debug.apk 并调用 FartTest 的 test 方法

```
val apkPath = "/sdcard/Android/data/com.cyrus.example/files/plugin-debug.apk"

// 创建 DexClassLoader 加载 sdcard 上的 apk
val classLoader = DexClassLoader(
    apkPath,
    null,
    this@FartActivity.packageResourcePath,
    classLoader // parent 设为当前 context 的类加载器
)

// classLoader 加载 com.cyrus.example.plugin.FartTest 类并通过反射调用 test 方法
val pluginClass = classLoader.loadClass("com.cyrus.example.plugin.FartTest")
val constructor = pluginClass.getDeclaredConstructor()
constructor.isAccessible = true
val instance = constructor.newInstance()
val method = pluginClass.getDeclaredMethod("test")
method.isAccessible = true
val result = method.invoke(instance) as? String

log("动态加载：${apkPath}\n\ncall ${method}\n\nreuslt=${result}")

mClassLoader = classLoader
```


脱壳完成，但是没有对 plugin-debug.apk 中的目标类 FartTest 发起主动调用



![word/media/image1.png](https://gitee.com/cyrus-studio/images/raw/master/28fbaf505896574e2a43e6961c368c74.png)


这时候 frida 就派上用场了，因为 frida 本身具有枚举所有 ClassLoader 的能力。



# Frida + FART 脱壳动态加载的 dex



枚举出所有 ClassLoader 后，再结合 FART 的 api 就可以实现动态加载 dex 的脱壳。 

```
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
                        console.log("[*] 调用 fartwithClassloader -> " + loader);
                        ActivityThread.fartwithClassloader(loader);
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
```


把 log 导出到 txt

```
adb logcat -v time > logcat.txt
```


打开 app 后执行脚本

```
frida -H 127.0.0.1:1234 -F -l fart_invoke_all_classloaders.js
```


从输出日志可以看到已经成功对 FartTest 类中方法发起主动调用



![word/media/image2.png](https://gitee.com/cyrus-studio/images/raw/master/f1ba3766affe115ef82fc6ae5ac4cded.png)


# 局部变量的 ClassLoader 枚举不出来



但还有一个问题呢：局部变量的 ClassLoader 枚举不出来。



因为：

- enumerateClassLoaders() 只枚举当前 VM 中可访问的、被 GC Root 持有的 ClassLoader；

- 如果 DexClassLoader 作为临时变量创建后，没有被保存，就会被 GC 回收或无法遍历到。



比如，下面的 Kotlin 代码中，当 DexClassLoader 为局部变量时就没有枚举出这个 DexClassLoader 。

```
/**
 * 局部变量的 ClassLoader
 */
fun onLocalClassLoaderClicked(log: (String) -> Unit) {

    val apkPath = "/sdcard/Android/data/com.cyrus.example/files/plugin-debug.apk"

    // 创建 DexClassLoader 加载 sdcard 上的 apk
    val classLoader = DexClassLoader(
        apkPath,
        null,
        this@FartActivity.packageResourcePath,
        classLoader // parent 设为当前 context 的类加载器
    )

    // classLoader 加载 com.cyrus.example.plugin.FartTest 类并通过反射调用 test 方法
    val pluginClass = classLoader.loadClass("com.cyrus.example.plugin.FartTest")
    val constructor = pluginClass.getDeclaredConstructor()
    constructor.isAccessible = true
    val instance = constructor.newInstance()
    val method = pluginClass.getDeclaredMethod("test")
    method.isAccessible = true
    val result = method.invoke(instance) as? String

    log("局部变量的 ClassLoader 动态加载：${apkPath}\n\ncall ${method}\n\nreuslt=${result}\n\n")
}
```


# 在构造 ClassLoader 时脱壳



所以，为了解决这种情况，我们 hook DexClassLoader 构造函数去调用 FART 脱壳 就可以解决了。 

```
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
```


启动 app 并执行脚本

```
frida -H 127.0.0.1:1234 -l fart_on_dexclassloader.js -f com.cyrus.example
```


frida 日志如下：

```
Spawned `com.cyrus.example`. Use %resume to let the main thread start executing!
[Remote::com.cyrus.example]-> %resume
[Remote::com.cyrus.example]-> [+] DexClassLoader created:
    |- dexPath: /sdcard/Android/data/com.cyrus.example/files/plugin-debug.apk
    |- optimizedDirectory: null
    |- libPath: /data/app/com.cyrus.example-DjrDTvMGrC1TBVLehVPmHQ==/base.apk
[*] Calling fartWithClassLoader...
[+] fartWithClassLoader finished.
```
可以看到成功 hook 到 局部变量的 DexClassLoader 构造函数



 从 logcat 可以看到正在对 ClassLoader 中的类方法发起主动调用



![word/media/image3.png](https://gitee.com/cyrus-studio/images/raw/master/18a2676ef445ec5705a93d77653adc7f.png)


等调用完成，进入 fart 目录下可以看到脱壳下来的文件

```
wayne:/sdcard/Android/data/com.cyrus.example/fart # ls
12968_class_list.txt            17104392_ins_7079.bin        400440_class_list_execute.txt 54120_dex_file.dex
12968_class_list_execute.txt    17268924_class_list.txt      400440_dex_file_execute.dex   54120_ins_7079.bin
12968_dex_file.dex              17268924_dex_file.dex        4461704_class_list.txt        66552_class_list_execute.txt
12968_dex_file_execute.dex      17268924_ins_7079.bin        4461704_dex_file.dex          66552_dex_file_execute.dex
12968_ins_7079.bin              20996_class_list_execute.txt 4461704_ins_7079.bin          9085048_class_list_execute.txt
16800_class_list_execute.txt    20996_dex_file_execute.dex   536008_class_list.txt         9085048_dex_file_execute.dex
16800_dex_file_execute.dex      21024_class_list_execute.txt 536008_class_list_execute.txt 9248236_class_list.txt
17104392_class_list.txt         21024_dex_file_execute.dex   536008_dex_file.dex           9248236_class_list_execute.txt
17104392_class_list_execute.txt 33196_class_list.txt         536008_dex_file_execute.dex   9248236_dex_file.dex
17104392_dex_file.dex           33196_dex_file.dex           536008_ins_7079.bin           9248236_dex_file_execute.dex
17104392_dex_file_execute.dex   33196_ins_7079.bin           54120_class_list.txt          9248236_ins_7079.bin
```


# 控制 FART 主动调用的范围



FART 中添加的 api 天生为脱壳而生，比如 fartwithClassLoader，loadClassAndInvoke，dumpArtMethod 等等这些接口都可以由 Frida 进行主动调用来控制脱壳精细度。



## 1. 过滤某些主动调用



hook loadClassAndInvoke 过滤掉某些 class  的主动调用，加快脱壳进程。



比如：过滤掉 androidx.* 、org.jetbrains.* 、kotlinx.* 、org.intellij.* 相关的主动调用

```
// 前缀过滤逻辑
function shouldSkipClass(name) {
    return name.startsWith("androidx.") ||
        name.startsWith("android.") ||
        name.startsWith("com.google.android.") ||
        name.startsWith("org.jetbrains.") ||
        name.startsWith("kotlinx.") ||
        name.startsWith("kotlin.") ||
        name.startsWith("org.intellij.");
}

function hookLoadClassAndInvoke() {
    const ActivityThread = Java.use('android.app.ActivityThread');

    if (ActivityThread.loadClassAndInvoke) {
        ActivityThread.loadClassAndInvoke.implementation = function (classloader, className, method) {
            if (shouldSkipClass(className)) {
                console.log('[skip] loadClassAndInvoke: ' + className);
                return; // 不调用原函数
            }

            console.log('[load] loadClassAndInvoke: ' + className);
            return this.loadClassAndInvoke(classloader, className, method); // 正常调用
        };
    } else {
        console.log('[-] ActivityThread.loadClassAndInvoke not found');
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
}


setImmediate(function () {
    Java.perform(function () {
        hookLoadClassAndInvoke()
        fartOnDexclassloader()
    })
})
```


执行脚本并输出日志到 log.txt

```
frida -H 127.0.0.1:1234 -l fart_loadClassAndInvoke_filter.js -f com.cyrus.example -o log.txt
```


输出日志如下：



![word/media/image4.png](https://gitee.com/cyrus-studio/images/raw/master/12fa2f8ed91f18831f82115c70e8155b.png)


## 2. fart thread 调用



由于每个 app 启动都会自动调用 fartthread，有点影响手机性能。



先去掉 ActivityThread.java 中 fartthread 调用



![word/media/image5.png](https://gitee.com/cyrus-studio/images/raw/master/7fcc38615c2100a650607122b71bdf62.png)
路径：frameworks/base/core/java/android/app/ActivityThread.java



通过 frida 调用 fartthread：

```
function fartThread() {
    Java.perform(function () {
        const ActivityThread = Java.use('android.app.ActivityThread')
        ActivityThread.fartthread()
    })
}

setImmediate(fartThread)
```


执行脚本针对当前前台应用启动 fart thread 开始脱壳

```
frida -H 127.0.0.1:1234 -F -l fart_thread.js
```


执行效果如下：



![word/media/image6.png](https://gitee.com/cyrus-studio/images/raw/master/487b3bd82bad64444458aa5e5c12f86a.png)


## 3. 对某个类发起主动调用



如果我们只想单独对某个类发起主动调用。



通过反射拿到 dumpMethodCode

```
function findDumpMethodCodeMethod(){

    let dumpMethodCodeMethod = null;

    // 反射获取 dumpMethodCode 方法
    try {
        const DexFile = Java.use("dalvik.system.DexFile");
        const dexFileClazz = DexFile.class;
        const declaredMethods = dexFileClazz.getDeclaredMethods();

        for (let i = 0; i < declaredMethods.length; i++) {
            const m = declaredMethods[i];
            if (m.getName().toString() === "dumpMethodCode") {
                m.setAccessible(true);
                dumpMethodCodeMethod = m;
                break;
            }
        }

        if (!dumpMethodCodeMethod) {
            console.log("[-] dumpMethodCode not found in DexFile");
            return;
        }

        console.log("[+] dumpMethodCode Method: " + dumpMethodCodeMethod.toString());

    } catch (err) {
        console.log("[-] Exception: " + err);
    }

    return dumpMethodCodeMethod
}
```


调用 LoadClassAndInvoke 对指定类发起主动调用

```
function invokeClass(targetClassName, dumpMethodCodeMethod) {

    let foundLoader = findClassLoader(targetClassName)

    const ActivityThread = Java.use("android.app.ActivityThread");

    // 调用 ActivityThread.loadClassAndInvoke(loader, className, dumpMethodCodeMethod)
    if (ActivityThread.loadClassAndInvoke) {
        console.log('[load] loadClassAndInvoke: ' + targetClassName);
        ActivityThread.loadClassAndInvoke(foundLoader, targetClassName, dumpMethodCodeMethod);
    } else {
        console.log("[-] ActivityThread.loadClassAndInvoke not found");
    }
}
```


完整源码如下：

```
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

    // 反射获取 dumpMethodCode 方法
    try {
        const DexFile = Java.use("dalvik.system.DexFile");
        const dexFileClazz = DexFile.class;
        const declaredMethods = dexFileClazz.getDeclaredMethods();

        for (let i = 0; i < declaredMethods.length; i++) {
            const m = declaredMethods[i];
            if (m.getName().toString() === "dumpMethodCode") {
                m.setAccessible(true);
                dumpMethodCodeMethod = m;
                break;
            }
        }

        if (!dumpMethodCodeMethod) {
            console.log("[-] dumpMethodCode not found in DexFile");
            return;
        }

        console.log("[+] dumpMethodCode Method: " + dumpMethodCodeMethod.toString());

    } catch (err) {
        console.log("[-] Exception: " + err);
    }

    return dumpMethodCodeMethod
}

function invokeClass(targetClassName, dumpMethodCodeMethod) {

    let foundLoader = findClassLoader(targetClassName)

    const ActivityThread = Java.use("android.app.ActivityThread");

    // 调用 ActivityThread.loadClassAndInvoke(loader, className, dumpMethodCodeMethod)
    if (ActivityThread.loadClassAndInvoke) {
        console.log('[load] loadClassAndInvoke: ' + targetClassName);
        ActivityThread.loadClassAndInvoke(foundLoader, targetClassName, dumpMethodCodeMethod);
    } else {
        console.log("[-] ActivityThread.loadClassAndInvoke not found");
    }
}


setImmediate(function () {
    Java.perform(function () {

        let dumpMethodCodeMethod = findDumpMethodCodeMethod()

        // TODO: 替换为你的目标类
        invokeClass("com.cyrus.example.plugin.FartTest", dumpMethodCodeMethod)
    })
})
```


执行脚本，附近到当前前台应用

```
frida -H 127.0.0.1:1234 -F -l fart_invoke_class.js
```


输入如下：

```
[+] dumpMethodCode Method: private static native void dalvik.system.DexFile.dumpMethodCode(java.lang.Object)
[+] Found class in loader: dalvik.system.DexClassLoader[DexPathList[[zip file "/sdcard/Android/data/com.cyrus.example/files/plugin-debug.apk"],nativeLibraryDirectories=[/data/app/com.cyrus.example-DjrDTvMGrC1TBVLehVPmHQ==/base.apk, /system/lib64, /system/product/lib64]]]
[load] loadClassAndInvoke: com.cyrus.example.plugin.FartTest
```


在 Logcat 中可以看到只对指定的类进行了主动加载和调用



![word/media/image7.png](https://gitee.com/cyrus-studio/images/raw/master/e8688453238598645a9970539683c726.png)


# 代码与功能整合



整合代码实现如下功能：

- 过滤不需要主动调用的类

- 解决局部变量的 ClassLoader 枚举不出来问题

- 解决非双亲委派关系下动态加载的 dex 脱壳问题



完整代码如下：

```
// 前缀过滤逻辑
function shouldSkipClass(name) {
    return name.startsWith("androidx.") ||
        name.startsWith("android.") ||
        name.startsWith("com.google.android.") ||
        name.startsWith("org.jetbrains.") ||
        name.startsWith("kotlinx.") ||
        name.startsWith("kotlin.") ||
        name.startsWith("org.intellij.");
}

function hookLoadClassAndInvoke() {
    const ActivityThread = Java.use('android.app.ActivityThread');

    if (ActivityThread.loadClassAndInvoke) {
        ActivityThread.loadClassAndInvoke.implementation = function (classloader, className, method) {
            if (shouldSkipClass(className)) {
                console.log('[skip] loadClassAndInvoke: ' + className);
                return; // 不调用原函数
            }

            console.log('[load] loadClassAndInvoke: ' + className);
            return this.loadClassAndInvoke(classloader, className, method); // 正常调用
        };
    } else {
        console.log('[-] ActivityThread.loadClassAndInvoke not found');
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
                    console.log("[*] 调用 fartwithClassloader -> " + loader);
                    ActivityThread.fartwithClassloader(loader);
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
```


启动 app 执行脚本，并输出日志到 log.txt

```
frida -H 127.0.0.1:1234 -l fart.js -f com.cyrus.example -o log.txt
```
或者 hook 当前前台 app ，并输出日志到 log.txt

```
frida -H 127.0.0.1:1234 -F -l fart.js -o log.txt
```


输出日志如下：



![word/media/image8.png](https://gitee.com/cyrus-studio/images/raw/master/6a9e4aaeb91eb7d4ade1008675e62718.png)


在 /sdcard/Android/data/com.cyrus.example/fart 下可以找到脱壳文件



![word/media/image9.png](https://gitee.com/cyrus-studio/images/raw/master/0221a755689eb87ddcf591275957afae.png)


FART 脱壳结束得到的文件列表（分 Execute 与 主动调用两类）：

1. Execute 脱壳点得到的 dex (*_dex_file_execute.dex）和 dex 中的所有类列表（ txt 文件）

1. 主动调用时 dump 得到的 dex (*_dex_file.dex）和此时 dex 中的所有类列表，以及该 dex 中所有函数的 CodeItem（ bin 文件）



# 完整源码



开源地址：

- Android 示例代码：[https://github.com/CYRUS-STUDIO/AndroidExample](https://github.com/CYRUS-STUDIO/AndroidExample)

- Frida 脚本源码：[https://github.com/CYRUS-STUDIO/frida_fart](https://github.com/CYRUS-STUDIO/frida_fart)

- FART源码：[https://github.com/CYRUS-STUDIO/FART](https://github.com/CYRUS-STUDIO/FART)



相关文章：

- [FART 自动化脱壳框架简介与脱壳点的选择](https://cyrus-studio.github.io/blog/posts/fart-%E8%87%AA%E5%8A%A8%E5%8C%96%E8%84%B1%E5%A3%B3%E6%A1%86%E6%9E%B6%E7%AE%80%E4%BB%8B%E4%B8%8E%E8%84%B1%E5%A3%B3%E7%82%B9%E7%9A%84%E9%80%89%E6%8B%A9/)

- [FART 主动调用组件设计和源码分析](https://cyrus-studio.github.io/blog/posts/fart-%E4%B8%BB%E5%8A%A8%E8%B0%83%E7%94%A8%E7%BB%84%E4%BB%B6%E8%AE%BE%E8%AE%A1%E5%92%8C%E6%BA%90%E7%A0%81%E5%88%86%E6%9E%90/)

- [移植 FART 到 Android 10 实现自动化脱壳](https://cyrus-studio.github.io/blog/posts/%E7%A7%BB%E6%A4%8D-fart-%E5%88%B0-android-10-%E5%AE%9E%E7%8E%B0%E8%87%AA%E5%8A%A8%E5%8C%96%E8%84%B1%E5%A3%B3/)

- [FART 自动化脱壳框架一些 bug 修复记录](https://cyrus-studio.github.io/blog/posts/fart-%E8%87%AA%E5%8A%A8%E5%8C%96%E8%84%B1%E5%A3%B3%E6%A1%86%E6%9E%B6%E4%B8%80%E4%BA%9B-bug-%E4%BF%AE%E5%A4%8D%E8%AE%B0%E5%BD%95/)





