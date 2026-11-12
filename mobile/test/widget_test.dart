// 创建时间: 2026-10-12 01:26:10
// 用途: 配置页的渲染冒烟测试。它同时也是「安全存储不可用时界面仍可用」这条的回归 ——
// 测试环境没有平台通道，正好覆盖设备读不到凭据的情形。

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mozunitor_mobile/main.dart';

void main() {
  testWidgets('配置页渲染出三个面板槽位与保存按钮', (WidgetTester tester) async {
    // 默认 800×600 的测试视口装不下三组输入框：ListView 是懒构建的，
    // 视口外的「保存」按钮压根不会被创建，断言会假失败。
    tester.view.physicalSize = const Size(1200, 2400);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      const MaterialApp(home: SetupPage(panels: kDefaultPanels)),
    );
    await tester.pump();

    expect(find.text('示例面板'), findsOneWidget);
    expect(find.text('保存'), findsOneWidget);
    // 用户名 + 密码 + 三个地址槽位
    expect(find.byType(TextField), findsNWidgets(5));
  });

  testWidgets('配置页在安全存储读不到值时不抛异常', (WidgetTester tester) async {
    await tester.pumpWidget(
      const MaterialApp(home: SetupPage(panels: kDefaultPanels)),
    );
    await tester.pumpAndSettle();
    expect(tester.takeException(), isNull);
  });

  group('normalizeBaseUrl', () {
    test('没写 scheme 时补 http://', () {
      expect(normalizeBaseUrl('192.0.2.10:8090'), 'http://192.0.2.10:8090');
    });

    test('保留已有的 scheme', () {
      expect(normalizeBaseUrl('http://10.0.0.2:8090'), 'http://10.0.0.2:8090');
      expect(normalizeBaseUrl('https://panel.example.ts.net'), 'https://panel.example.ts.net');
    });

    test('去掉首尾空白与末尾斜杠', () {
      expect(normalizeBaseUrl('  10.0.0.2:8090/  '), 'http://10.0.0.2:8090');
    });

    test('空白串仍是空串', () {
      expect(normalizeBaseUrl('   '), '');
    });
  });
}
