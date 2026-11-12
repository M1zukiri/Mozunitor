// 创建时间: 2026-10-12 01:24:50
// 用途: 入口清单拼装的单元测试（SPEC-app-shell.md §6.4）。四条判据：
//   ① 只挑 ops[].kind == "link"；② 有 fwd_port 就改写成局域网入口；
//   ③ 没有 fwd_port 用 op 自己的地址；④ 快照没有 ops（对端仍是 v2.0.0）时给空清单。
// 这些都不需要 Android SDK，`flutter test` 直接在 Dart VM 上跑。

import 'package:flutter_test/flutter_test.dart';
import 'package:mozunitor_mobile/entries.dart';

/// 一份最简 /api/state 快照：一个分组、两个服务。
Map<String, dynamic> snapshot({required bool withOps, required bool withFwd}) => {
      'node': {'id': 'local-node', 'name': '本机'},
      'groups': [
        {
          'id': 'local',
          'title': '本机 · 自建服务',
          'items': [
            {
              'id': 'sillytavern',
              'name': 'SillyTavern 酒馆',
              'role': '手机端 LLM 前端',
              'status': 'up',
              'access': {'note': 'basicAuth'},
              if (withFwd) 'fwd_port': 8103,
              if (withOps)
                'ops': [
                  {'id': 'open', 'label': '打开', 'kind': 'link', 'url': 'http://127.0.0.1:8001/'},
                  {'id': 'logs', 'label': '日志', 'kind': 'view', 'source': 'logs'},
                ],
            },
            {
              'id': 'plain',
              'name': '无入口的服务',
              'role': '只有视图',
              'status': 'down',
              if (withOps)
                'ops': [
                  {'id': 'params', 'label': '启动参数', 'kind': 'view', 'source': 'restart'},
                ],
            },
          ],
        },
      ],
    };

void main() {
  group('buildEntries', () {
    test('只挑 kind == link 的操作，view 不进来', () {
      final entries = buildEntries(snapshot(withOps: true, withFwd: false),
          scheme: 'http', host: '192.0.2.10');
      expect(entries.length, 1);
      expect(entries.first.id, 'sillytavern:open');
      expect(entries.first.name, 'SillyTavern 酒馆');
      expect(entries.first.note, 'basicAuth');
    });

    test('有 fwd_port 时改写成「面板 host + fwd_port」，URL 里不带凭据', () {
      final entries = buildEntries(snapshot(withOps: true, withFwd: true),
          scheme: 'http', host: '192.0.2.10');
      expect(entries.single.url, 'http://192.0.2.10:8103/');
    });

    test('没有 fwd_port 时用 op 自己的地址', () {
      final entries = buildEntries(snapshot(withOps: true, withFwd: false),
          scheme: 'http', host: '192.0.2.10');
      expect(entries.single.url, 'http://127.0.0.1:8001/');
    });

    test('快照里没有 ops（对端仍是 v2.0.0）时返回空清单，不抛异常', () {
      final entries = buildEntries(snapshot(withOps: false, withFwd: true),
          scheme: 'http', host: '192.0.2.11');
      expect(entries, isEmpty);
    });

    test('groups 缺失或形状不对时也返回空清单', () {
      expect(buildEntries(const {}, scheme: 'http', host: 'h'), isEmpty);
      expect(buildEntries(const {'groups': 'nope'}, scheme: 'http', host: 'h'), isEmpty);
    });
  });

  group('buildForwardUrl', () {
    test('拼成「面板 host + 转发端口」，不带任何查询参数', () {
      expect(
        buildForwardUrl(scheme: 'http', host: '192.0.2.10', fwdPort: 8102),
        'http://192.0.2.10:8102/',
      );
    });

    test('https 与 MagicDNS 主机名同样处理 —— 鉴权走会话，不再有 host 例外', () {
      expect(
        buildForwardUrl(scheme: 'https', host: 'panel.example.ts.net', fwdPort: 8102),
        'https://panel.example.ts.net:8102/',
      );
    });
  });
}
