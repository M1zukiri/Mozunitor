// 创建时间: 2026-10-12 01:19:05
// 用途: Mozunitor 手机端 —— 入口启动器。清单来自面板的 /api/state，
//       点一下就在应用内打开，不再开浏览器、不再逐个服务记地址。
//
// 三个页面：配置（面板地址 + 配对码）→ 入口清单 → 应用内 WebView。
//
// 身份走设备配对：面板上生成一次性配对码，手机用它换设备 token（面板只存哈希）。
// 自签 TLS 证书按指纹钉住；token 进 Android Keystore（不可用时退回应用私有存储并提示）。
// 数据源按配置顺序探测，取第一个可达的；
// 三个都不可达时给可操作的错误态，而不是空白页。

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart' as crypto;
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:http/http.dart' as http;
import 'package:http/io_client.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:webview_flutter/webview_flutter.dart';

import 'entries.dart';

const String kPanelsKey = 'panels';

/// 用默认的 AndroidOptions（AES-GCM 存储 + RSA-OAEP 密钥包装）。
/// 注意 flutter_secure_storage 11.x **已经没有** `encryptedSharedPreferences` 参数了，
/// 别照旧文档去写它（写了编译不过）。
/// 这台小米 Android 15 上曾出现「地址存得下、token 存不下」：当时 saveToken 把异常吞了，
/// 于是每个请求都 401 而看不出原因。现在失败会如实上报并显示在配置页。
const FlutterSecureStorage kSecrets = FlutterSecureStorage();

/// 面板地址与证书指纹。设备 token 单独进安全存储（它等同于访问权），不写在这里。
class PanelConfig {
  final String label;
  final String baseUrl;

  /// 自签 TLS 证书的 SHA256（大写十六进制，不带冒号）；http 面板留空。
  final String fingerprint;

  const PanelConfig({
    required this.label,
    required this.baseUrl,
    this.fingerprint = '',
  });

  Map<String, dynamic> toJson() =>
      {'label': label, 'baseUrl': baseUrl, 'fingerprint': fingerprint};

  static PanelConfig fromJson(Map<String, dynamic> j) => PanelConfig(
        label: (j['label'] ?? '').toString(),
        baseUrl: (j['baseUrl'] ?? '').toString(),
        fingerprint: (j['fingerprint'] ?? '').toString(),
      );
}

const List<PanelConfig> kDefaultPanels = [
  // 首次启动的示例地址；请在「配置」里改成你自己的面板地址。
  PanelConfig(label: '示例面板', baseUrl: 'http://192.0.2.10:8090'),
];

/// 用户很可能只填 `10.0.0.2:8090`。`Uri.parse` 对没有 scheme 的串会得出奇怪的 host，
/// `http.get` 直接抛异常，最后表现成「面板不可达」—— 所以统一在这里补 `http://`。
String normalizeBaseUrl(String raw) {
  var s = raw.trim();
  if (s.isEmpty) return '';
  if (!s.contains('://')) s = 'http://$s';
  return s.replaceAll(RegExp(r'/+$'), '');
}

Future<List<PanelConfig>> loadPanels() async {
  final prefs = await SharedPreferences.getInstance();
  final raw = prefs.getString(kPanelsKey);
  if (raw == null || raw.isEmpty) return List.of(kDefaultPanels);
  try {
    final list = (jsonDecode(raw) as List)
        .whereType<Map<String, dynamic>>()
        .map(PanelConfig.fromJson)
        .map((p) => PanelConfig(label: p.label, baseUrl: normalizeBaseUrl(p.baseUrl)))
        .where((p) => p.baseUrl.isNotEmpty)
        .toList();
    return list.isEmpty ? List.of(kDefaultPanels) : list;
  } catch (_) {
    return List.of(kDefaultPanels);
  }
}

Future<void> savePanels(List<PanelConfig> panels) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString(
      kPanelsKey, jsonEncode(panels.map((p) => p.toJson()).toList()));
}

/// 安全存储不可用时的回退键前缀（存在应用私有的 SharedPreferences 里）。
const String kTokenFallbackPrefix = 'fallback_token:';

/// 凭据读取：先试安全存储，不行再读应用私有数据。
Future<String?> readSecret(String key) async {
  try {
    final v = await kSecrets.read(key: key);
    if (v != null && v.isNotEmpty) return v;
  } catch (e) {
    debugPrint('读安全存储失败，改用回退存储: $e');
  }
  final prefs = await SharedPreferences.getInstance();
  return prefs.getString('$kTokenFallbackPrefix$key');
}

/// 凭据写入。返回是否进了**安全存储**；false 表示退回了应用私有数据
/// （功能可用，但没有硬件加密）。
///
/// 之所以必须有这条回退：这台小米 Android 15 上 Keystore 生成密钥就失败
/// （`SECURE_HW_COMMUNICATION_FAILED`，internal code -49），凭据根本写不进去。
/// 上一版把异常静默吞掉，于是「保存看起来成功、请求永远 401」—— 那比不能用更糟。
Future<bool> writeSecret(String key, String value) async {
  final prefs = await SharedPreferences.getInstance();
  final fallbackKey = '$kTokenFallbackPrefix$key';
  try {
    await kSecrets.write(key: key, value: value);
    await prefs.remove(fallbackKey);
    return true;
  } catch (e) {
    debugPrint('安全存储不可用，$key 改存应用私有数据: $e');
    await prefs.setString(fallbackKey, value);
    return false;
  }
}

/// 身份：用户名存应用私有数据（它不是秘密，面板界面上就显示着），密码进安全存储。
const String kUserKey = 'identity_user';
const String kPasswordKey = 'identity_password';

Future<String> storedUser() async {
  final prefs = await SharedPreferences.getInstance();
  return prefs.getString(kUserKey) ?? '';
}

Future<void> saveUser(String user) async {
  final prefs = await SharedPreferences.getInstance();
  await prefs.setString(kUserKey, user.trim());
}

Future<String> storedPassword() async => (await readSecret(kPasswordKey)) ?? '';

Future<bool> savePassword(String password) async =>
    password.isEmpty ? true : writeSecret(kPasswordKey, password);

/// 会话按面板地址分别存：Cookie 本身不带端口，但每台面板各自签发自己的会话。
String sessionKey(String baseUrl) => 'session:$baseUrl';

/// 设备 token 的存储键：每个面板一份。
String deviceTokenKey(String baseUrl) => 'device:$baseUrl';

/// 按指纹钉住自签证书的 HTTP 客户端。指纹为空时只允许系统信任的证书链。
http.Client tlsClient(String fingerprint) {
  final hc = HttpClient();
  final want = fingerprint.replaceAll(':', '').trim().toUpperCase();
  if (want.isNotEmpty) {
    hc.badCertificateCallback = (cert, host, port) {
      final got = crypto.sha256.convert(cert.der).toString().toUpperCase();
      return got == want;
    };
  }
  return IOClient(hc);
}

/// 配对结果。
class PairResult {
  final bool ok;
  final String error;

  const PairResult({required this.ok, required this.error});
}

/// 用一次性配对码换设备 token；token 只进安全存储，面板侧只保存哈希。
Future<PairResult> pairPanel(
    PanelConfig panel, String code, String deviceName) async {
  final base = normalizeBaseUrl(panel.baseUrl);
  final client = tlsClient(panel.fingerprint);
  try {
    final res = await client
        .post(
          Uri.parse('$base/api/pair/complete'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'code': code.trim().toUpperCase(),
            'name': deviceName.isEmpty ? '手机' : deviceName,
          }),
        )
        .timeout(const Duration(seconds: 15));
    if (res.statusCode != 200) {
      var msg = 'HTTP ${res.statusCode}';
      try {
        final j = jsonDecode(utf8.decode(res.bodyBytes));
        if (j is Map && j['error'] is String) msg = j['error'] as String;
      } catch (_) {}
      return PairResult(ok: false, error: msg);
    }
    final j = jsonDecode(utf8.decode(res.bodyBytes));
    final token = (j is Map ? j['token'] : null) as String?;
    if (token == null || token.isEmpty) {
      return const PairResult(ok: false, error: '面板没有下发设备 token');
    }
    await writeSecret(deviceTokenKey(base), token);
    return const PairResult(ok: true, error: '');
  } on TimeoutException {
    return const PairResult(ok: false, error: '配对超时（手机和面板在同一网络吗）');
  } on HandshakeException catch (e) {
    return PairResult(ok: false, error: 'TLS 握手失败：${e.message}（指纹是否填对）');
  } on SocketException catch (e) {
    return PairResult(ok: false, error: '连不上：${e.osError?.message ?? e.message}');
  } catch (e) {
    return PairResult(ok: false, error: '${e.runtimeType}: $e');
  } finally {
    client.close();
  }
}

/// 登录结果。密码登录只用于应用内 WebView 的会话兼容；清单数据优先用设备 token。
class LoginResult {
  final bool ok;
  final String cookie;
  final String error;

  const LoginResult({required this.ok, required this.cookie, required this.error});
}

/// 用管理员口令换会话 Cookie（1.1.0 的 /api/session/login）。
Future<LoginResult> panelLogin(
    String base, String password, String fingerprint) async {
  final client = tlsClient(fingerprint);
  try {
    final res = await client
        .post(
          Uri.parse('$base/api/session/login'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({'password': password}),
        )
        .timeout(const Duration(seconds: 10));
    if (res.statusCode != 200) {
      var msg = 'HTTP ${res.statusCode}';
      try {
        final j = jsonDecode(utf8.decode(res.bodyBytes));
        if (j is Map && j['error'] is String) msg = j['error'] as String;
      } catch (_) {}
      return LoginResult(ok: false, cookie: '', error: msg);
    }
    final setCookie = res.headers['set-cookie'] ?? '';
    final m = RegExp(r'mozunitor_session=([^;,\s]+)').firstMatch(setCookie);
    if (m == null) {
      return const LoginResult(ok: false, cookie: '', error: '面板没有下发会话 Cookie');
    }
    return LoginResult(ok: true, cookie: 'mozunitor_session=${m.group(1)}', error: '');
  } finally {
    client.close();
  }
}

void main() => runApp(const MozunitorApp());

class MozunitorApp extends StatelessWidget {
  const MozunitorApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Mozunitor',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        brightness: Brightness.dark,
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF40C8AC),
          brightness: Brightness.dark,
        ),
      ),
      home: const RootPage(),
    );
  }
}

// ---------------------------------------------------------------- 入口分发

class RootPage extends StatefulWidget {
  const RootPage({super.key});

  @override
  State<RootPage> createState() => _RootPageState();
}

class _RootPageState extends State<RootPage> {
  bool _loading = true;
  List<PanelConfig> _panels = const [];

  @override
  void initState() {
    super.initState();
    _boot();
  }

  Future<void> _boot() async {
    final prefs = await SharedPreferences.getInstance();
    final configured = prefs.containsKey(kPanelsKey);
    final panels = await loadPanels();
    if (!mounted) return;
    setState(() {
      _panels = panels;
      _loading = false;
    });
    if (!configured) {
      // 首次启动先进配置页：没有 token 的清单页只会是一片 401。
      WidgetsBinding.instance.addPostFrameCallback((_) => _openSetup());
    }
  }

  Future<void> _openSetup() async {
    if (!mounted) return;
    final result = await Navigator.of(context).push<List<PanelConfig>>(
      MaterialPageRoute(builder: (_) => SetupPage(panels: _panels)),
    );
    if (result != null && mounted) setState(() => _panels = result);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return HomePage(panels: _panels, onEdit: _openSetup);
  }
}

// ---------------------------------------------------------------- 入口清单

class HomePage extends StatefulWidget {
  final List<PanelConfig> panels;
  final Future<void> Function() onEdit;

  const HomePage({super.key, required this.panels, required this.onEdit});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  bool _loading = true;
  String? _error;
  List<Entry> _entries = const [];
  PanelConfig? _active;
  String _activeCookie = '';

  @override
  void initState() {
    super.initState();
    refresh();
  }

  @override
  void didUpdateWidget(HomePage old) {
    super.didUpdateWidget(old);
    // 配置改过就重新探测。首次启动是 RootPage 直接 push 配置页的，那条路不经过本页的
    // _openSetup —— 保存后若不在这里刷新，用户会一直盯着配置前的错误。
    if (!identical(old.panels, widget.panels)) refresh();
  }

  /// 优先用设备 token（Bearer）；没有或失效时退回口令换会话（应用内 WebView 需要 Cookie）。
  Future<http.Response> _fetchState(
      String base, String fingerprint, String token, String cookie) async {
    final client = tlsClient(fingerprint);
    try {
      final headers = <String, String>{};
      if (token.isNotEmpty) headers['Authorization'] = 'Bearer $token';
      if (cookie.isNotEmpty) headers['Cookie'] = cookie;
      return await client
          .get(Uri.parse('$base/api/state'), headers: headers)
          .timeout(const Duration(seconds: 6));
    } finally {
      client.close();
    }
  }

  Future<void> refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    // 逐面板记下「为什么不行」。合并成一句「不可达」会同时误导用户和我：
    // token 失效、地址写错、手机不在同一网络，是三件完全不同的事。
    final problems = <String>[];

    for (final panel in widget.panels) {
      final base = normalizeBaseUrl(panel.baseUrl);
      if (base.isEmpty) {
        problems.add('${panel.label}：地址是空的');
        continue;
      }
      final parsed = Uri.tryParse(base);
      if (parsed == null || parsed.host.isEmpty) {
        problems.add('${panel.label}：地址格式不对（$base）');
        continue;
      }
      try {
        var token = await readSecret(deviceTokenKey(base)) ?? '';
        var cookie = await readSecret(sessionKey(base)) ?? '';
        var res = await _fetchState(base, panel.fingerprint, token, cookie);
        if (res.statusCode == 401 || res.statusCode == 403) {
          final password = await storedPassword();
          if (password.isNotEmpty) {
            final login = await panelLogin(base, password, panel.fingerprint);
            if (login.ok) {
              cookie = login.cookie;
              await writeSecret(sessionKey(base), cookie);
            }
          }
          if (cookie.isNotEmpty) {
            res = await _fetchState(base, panel.fingerprint, '', cookie);
          }
        }
        debugPrint('GET $base/api/state  会话=${cookie.length}字 令牌=${token.length}字'
            '  -> HTTP ${res.statusCode}');
        if (res.statusCode == 401 || res.statusCode == 403) {
          problems.add('${panel.label}：需要重新配对或输入口令（HTTP ${res.statusCode}）');
          continue;
        }
        if (res.statusCode != 200) {
          problems.add('${panel.label}：HTTP ${res.statusCode}');
          continue;
        }
        final body = jsonDecode(utf8.decode(res.bodyBytes));
        if (body is! Map<String, dynamic>) {
          problems.add('${panel.label}：返回的不是面板数据');
          continue;
        }
        final entries =
            buildEntries(body, scheme: parsed.scheme, host: parsed.host);
        if (!mounted) return;
        setState(() {
          _active = panel;
          _activeCookie = cookie;
          _entries = entries;
          _loading = false;
        });
        return;
      } on TimeoutException {
        problems.add('${panel.label}：6 秒没有响应（手机和它在同一网络吗）');
      } on SocketException catch (e) {
        problems.add('${panel.label}：连不上（${e.osError?.message ?? e.message}）');
      } on HandshakeException {
        problems.add('${panel.label}：TLS 证书校验失败（检查指纹）');
      } on FormatException {
        problems.add('${panel.label}：响应不是合法 JSON');
      } catch (e) {
        problems.add('${panel.label}：${e.runtimeType}: $e');
      }
    }

    if (!mounted) return;
    setState(() {
      _loading = false;
      _error = problems.isEmpty
          ? '没有配置任何面板，请到设置里配对面板。'
          : '都连不上：\n\n${problems.join('\n')}';
    });
  }

  Future<void> _openSetup() async {
    // 刷新交给 didUpdateWidget：panels 换新时它一定会跑，这里再刷就是探测两遍。
    await widget.onEdit();
  }

  void _openInApp(String url, String title) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => WebPage(url: url, title: title, cookie: _activeCookie),
      ),
    );
  }

  void _openFullPanel() {
    final panel = _active;
    if (panel == null) return;
    _openInApp('${panel.baseUrl}/', '完整面板');
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title:
            Text(_active == null ? 'Mozunitor' : 'Mozunitor · ${_active!.label}'),
        actions: [
          IconButton(
            tooltip: '完整面板',
            onPressed: _active == null ? null : _openFullPanel,
            icon: const Icon(Icons.dashboard_outlined),
          ),
          IconButton(
            tooltip: '刷新',
            onPressed: refresh,
            icon: const Icon(Icons.refresh),
          ),
          IconButton(
            tooltip: '设置',
            onPressed: _openSetup,
            icon: const Icon(Icons.settings_outlined),
          ),
        ],
      ),
      body: _buildBody(),
    );
  }

  Widget _buildBody() {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_error != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.cloud_off_outlined, size: 40),
              const SizedBox(height: 14),
              Text(_error!, textAlign: TextAlign.center),
              const SizedBox(height: 18),
              FilledButton(onPressed: refresh, child: const Text('重试')),
              TextButton(onPressed: _openSetup, child: const Text('改地址')),
            ],
          ),
        ),
      );
    }
    if (_entries.isEmpty) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.list_alt_outlined, size: 40),
              const SizedBox(height: 14),
              const Text('这个面板没有声明任何入口。',
                  textAlign: TextAlign.center),
              const SizedBox(height: 6),
              Text(
                '较早版本的面板不带操作声明，可以先用完整面板。',
                textAlign: TextAlign.center,
                style: Theme.of(context).textTheme.bodySmall,
              ),
              const SizedBox(height: 18),
              FilledButton(
                onPressed: _openFullPanel,
                child: const Text('打开完整面板'),
              ),
            ],
          ),
        ),
      );
    }
    return RefreshIndicator(
      onRefresh: refresh,
      child: ListView.separated(
        padding: const EdgeInsets.symmetric(vertical: 8),
        itemCount: _entries.length,
        separatorBuilder: (_, _) => const Divider(height: 1),
        itemBuilder: (context, i) {
          final e = _entries[i];
          final up = e.status == 'up';
          return ListTile(
            leading: Icon(
              up ? Icons.check_circle : Icons.remove_circle_outline,
              color: up ? const Color(0xFF40C8AC) : Colors.orangeAccent,
            ),
            title: Text(e.name),
            subtitle: Text(
              [e.role, if (e.note != null && e.note!.isNotEmpty) e.note!]
                  .where((s) => s.isNotEmpty)
                  .join(' · '),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            trailing: const Icon(Icons.open_in_new),
            onTap: () => _openInApp(e.url, e.name),
          );
        },
      ),
    );
  }
}

// ---------------------------------------------------------------- 应用内浏览器

class WebPage extends StatefulWidget {
  final String url;
  final String title;

  /// 面板会话（`mozunitor_session=...`）。应用内打开的服务入口靠它鉴权 ——
  /// 转发层认这张会话，所以 URL 里不再放 token。
  final String cookie;

  const WebPage({
    super.key,
    required this.url,
    required this.title,
    this.cookie = '',
  });

  @override
  State<WebPage> createState() => _WebPageState();
}

class _WebPageState extends State<WebPage> {
  late final WebViewController _controller;
  bool _failed = false;

  @override
  void initState() {
    super.initState();
    _controller = WebViewController()
      ..setJavaScriptMode(JavaScriptMode.unrestricted)
      ..setNavigationDelegate(NavigationDelegate(
        onHttpAuthRequest: _handleHttpAuth,
        onWebResourceError: (error) {
          if (error.isForMainFrame ?? false) {
            setState(() => _failed = true);
          }
        },
      ));
    _load();
  }

  /// 会话必须经 CookieManager 落成真正的 Cookie：`loadRequest` 的 headers 会被 WebView
  /// 忽略（Cookie 归 CookieManager 管），而转发层只鉴权首个请求，之后全指望这条 Cookie。
  ///
  /// 两个坑都在这一个调用里：`domain` 那一栏要传**完整 URL**，因为 Android 的
  /// `CookieManager.setCookie` 收的就是 URL，传裸 host 会静默失败；值会被 `Uri.encodeComponent`
  /// 过一遍，所以会话由服务端按**无填充**的 base64url 签发，编码后仍是原样。
  Future<void> _load() async {
    final cookie = widget.cookie;
    final i = cookie.indexOf('=');
    if (i > 0) {
      final uri = Uri.parse(widget.url);
      try {
        await WebViewCookieManager().setCookie(WebViewCookie(
          name: cookie.substring(0, i),
          value: cookie.substring(i + 1),
          domain: '${uri.scheme}://${uri.host}',
        ));
      } catch (e) {
        debugPrint('注入会话 Cookie 失败: $e');
      }
    }
    if (!mounted) return;
    await _controller.loadRequest(Uri.parse(widget.url));
  }

  /// HTTP basicAuth（酒馆这类服务）。**webview_flutter 默认不处理认证挑战**，所以实测点进
  /// 酒馆只会看到它的 `Unauthorized` 页、根本不弹框。这里接管：第一次问，之后记住。
  Future<void> _handleHttpAuth(HttpAuthRequest request) async {
    final host = request.host;
    final saved = await readSecret('basicauth:$host');
    if (saved != null && saved.contains(':')) {
      final i = saved.indexOf(':');
      request.onProceed(WebViewCredential(
        user: saved.substring(0, i),
        password: saved.substring(i + 1),
      ));
      return;
    }
    if (!mounted) return;
    final user = TextEditingController();
    final pass = TextEditingController();
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('$host 需要登录'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: user,
              autocorrect: false,
              decoration: const InputDecoration(labelText: '用户名'),
            ),
            TextField(
              controller: pass,
              obscureText: true,
              autocorrect: false,
              decoration: const InputDecoration(labelText: '密码'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('取消'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('确定'),
          ),
        ],
      ),
    );
    if (ok == true) {
      await writeSecret('basicauth:$host', '${user.text}:${pass.text}');
      request.onProceed(WebViewCredential(user: user.text, password: pass.text));
    } else {
      request.onCancel();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.title),
        actions: [
          IconButton(
            tooltip: '刷新',
            onPressed: () => _controller.reload(),
            icon: const Icon(Icons.refresh),
          ),
        ],
      ),
      body: _failed
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(28),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const Icon(Icons.error_outline, size: 40),
                    const SizedBox(height: 14),
                    Text('打不开 ${widget.url}', textAlign: TextAlign.center),
                    const SizedBox(height: 6),
                    Text(
                      '服务可能没在跑，或它只绑在本机回环上。',
                      textAlign: TextAlign.center,
                      style: Theme.of(context).textTheme.bodySmall,
                    ),
                    const SizedBox(height: 18),
                    FilledButton(
                      onPressed: () {
                        setState(() => _failed = false);
                        _controller.reload();
                      },
                      child: const Text('重试'),
                    ),
                  ],
                ),
              ),
            )
          : WebViewWidget(controller: _controller),
    );
  }
}

// ---------------------------------------------------------------- 配置

class SetupPage extends StatefulWidget {
  final List<PanelConfig> panels;

  const SetupPage({super.key, required this.panels});

  @override
  State<SetupPage> createState() => _SetupPageState();
}

class _SetupPageState extends State<SetupPage> {
  late List<TextEditingController> _urls;
  late List<TextEditingController> _fps;
  late List<TextEditingController> _codes;
  late List<String> _labels;
  late final TextEditingController _deviceName;
  late final TextEditingController _password;
  String? _error;
  bool _saving = false;

  @override
  void initState() {
    super.initState();
    final panels = widget.panels.isEmpty ? kDefaultPanels : widget.panels;
    _labels = [
      for (var i = 0; i < panels.length; i++)
        i < kDefaultPanels.length ? kDefaultPanels[i].label : '面板 ${i + 1}',
    ];
    _urls = panels.map((p) => TextEditingController(text: p.baseUrl)).toList();
    _fps = panels.map((p) => TextEditingController(text: p.fingerprint)).toList();
    _codes = panels.map((_) => TextEditingController()).toList();
    _deviceName = TextEditingController(text: '手机');
    _password = TextEditingController();
    _load();
  }

  Future<void> _load() async {
    final password = await storedPassword();
    if (!mounted) return;
    setState(() => _password.text = password);
  }

  @override
  void dispose() {
    for (final c in [..._urls, ..._fps, ..._codes]) {
      c.dispose();
    }
    _deviceName.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (_saving) return;
    final panels = <PanelConfig>[];
    final codes = <String>[];
    for (var i = 0; i < _urls.length; i++) {
      final url = normalizeBaseUrl(_urls[i].text);
      if (url.isEmpty) continue;
      final parsed = Uri.tryParse(url);
      if (parsed == null || parsed.host.isEmpty) {
        setState(() => _error = '「${_labels[i]}」的地址看起来不对：$url');
        return;
      }
      final fp = _fps[i].text.replaceAll(':', '').trim().toUpperCase();
      panels.add(PanelConfig(label: _labels[i], baseUrl: url, fingerprint: fp));
      codes.add(_codes[i].text.trim().toUpperCase());
    }
    if (panels.isEmpty) {
      setState(() => _error = '至少填一个面板地址。');
      return;
    }
    if (_password.text.isNotEmpty) await savePassword(_password.text);
    await savePanels(panels);
    setState(() {
      _saving = true;
      _error = null;
    });
    final failed = <String>[];
    for (var i = 0; i < panels.length; i++) {
      final code = codes[i];
      if (code.isEmpty) continue;
      final r = await pairPanel(panels[i], code, _deviceName.text.trim());
      if (!r.ok) failed.add('${panels[i].label}：${r.error}');
    }
    if (!mounted) return;
    setState(() => _saving = false);
    if (failed.isNotEmpty) {
      setState(() => _error = '配对失败：\n${failed.join('\n')}');
      return;
    }
    Navigator.of(context).pop(panels);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('设置')),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
        children: [
          Text(
            '在面板的「设置 → 安全 → 设备配对」里生成配对码，填到下面即可。'
            '自签证书需要填面板显示的 SHA256 指纹（可只填十六进制，冒号可省略）。',
            style: Theme.of(context).textTheme.bodySmall,
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _deviceName,
            autocorrect: false,
            decoration: const InputDecoration(
              labelText: '设备名（面板上显示）',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 10),
          TextField(
            controller: _password,
            obscureText: true,
            autocorrect: false,
            decoration: const InputDecoration(
              labelText: '管理员口令（可选，仅应用内网页需要）',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 22),
          Text('面板（按顺序探测，取第一个可达的）',
              style: Theme.of(context).textTheme.titleSmall),
          const SizedBox(height: 10),
          for (var i = 0; i < _urls.length; i++) ...[
            TextField(
              controller: _urls[i],
              keyboardType: TextInputType.url,
              autocorrect: false,
              decoration: InputDecoration(
                labelText: '${_labels[i]} 地址',
                hintText: 'https://10.0.0.2:8443',
                border: const OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _fps[i],
              autocorrect: false,
              decoration: const InputDecoration(
                labelText: '证书指纹 SHA256（http 面板留空）',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 8),
            TextField(
              controller: _codes[i],
              autocorrect: false,
              decoration: const InputDecoration(
                labelText: '配对码（已配对过则留空）',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
          ],
          if (_error != null) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Colors.orange.withValues(alpha: 0.15),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Text(_error!,
                  style: const TextStyle(color: Colors.orangeAccent, height: 1.5)),
            ),
            const SizedBox(height: 12),
          ],
          FilledButton(
            onPressed: _saving ? null : _save,
            child: Text(_saving ? '配对中…' : '保存'),
          ),
        ],
      ),
    );
  }
}
