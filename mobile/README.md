# Mozunitor Mobile

Mozunitor 的 Android 入口启动器：读取面板的服务清单，在应用内 WebView 打开。
凭据与面板节点一致（username 可见、password 可控制），会话 Cookie 存 30 天。

## 构建

```powershell
flutter pub get
flutter build apk --release
```

产物在 `build/app/outputs/flutter-apk/app-release.apk`。

## 首次配置

打开应用 → 配置 → 填面板地址（例如 `http://192.0.2.10:8090`）与用户名/密码。
示例地址只是占位，请改成你自己的面板地址。
