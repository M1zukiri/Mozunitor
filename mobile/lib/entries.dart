// 创建时间: 2026-10-12 01:16:20
// 用途: 把面板 /api/state 的快照翻译成手机上的入口清单。纯函数，便于单元测试。
//
// 拼装规则与面板前端保持一致（static/app.js:785-790）：
//   - 只认 ops[].kind == "link"，即服务在 services.json 里声明的「打开一个地址」；
//   - 该服务有 fwd_port 时，地址改写成「面板 host + fwd_port」—— op.url 指的是服务
//     自己的回环地址（127.0.0.1:8001 之类），手机根本点不开，而面板已经替它开了
//     局域网入口（forwards 那段配置）；
//   - 入口的鉴权走登录会话：会话 Cookie 由 WebView 自己带上，URL 里不再放任何凭据，
//     所以这里没有「哪种 host 要附 token、哪种不要」的分支；
//   - 快照里没有 ops 就返回空清单：对端可能还在 v2.0.0，界面据此显示降级说明，
//     而不是抛异常。

/// 手机上一个可打开的入口。
class Entry {
  final String id;
  final String name;
  final String role;
  final String url;
  final String status;
  final String? note;

  const Entry({
    required this.id,
    required this.name,
    required this.role,
    required this.url,
    required this.status,
    this.note,
  });
}

/// 面板已替回环服务开好的局域网入口。
String buildForwardUrl({
  required String scheme,
  required String host,
  required int fwdPort,
}) =>
    '$scheme://$host:$fwdPort/';

List<Entry> buildEntries(
  Map<String, dynamic> state, {
  required String scheme,
  required String host,
}) {
  final out = <Entry>[];
  final groups = state['groups'];
  if (groups is! List) return out;

  for (final group in groups) {
    if (group is! Map) continue;
    final items = group['items'];
    if (items is! List) continue;

    for (final item in items) {
      if (item is! Map) continue;
      final ops = item['ops'];
      if (ops is! List) continue;
      final fwd = item['fwd_port'];
      final access = item['access'];
      final note = (access is Map) ? access['note']?.toString() : null;

      for (final op in ops) {
        if (op is! Map) continue;
        if (op['kind'] != 'link') continue;
        final raw = op['url'];
        if (raw is! String || raw.isEmpty) continue;

        final url = (fwd is int)
            ? buildForwardUrl(scheme: scheme, host: host, fwdPort: fwd)
            : raw;

        out.add(Entry(
          id: '${item['id']}:${op['id']}',
          name: (item['name'] ?? item['id'] ?? '').toString(),
          role: (item['role'] ?? '').toString(),
          url: url,
          status: (item['status'] ?? 'unknown').toString(),
          note: note,
        ));
      }
    }
  }
  return out;
}
