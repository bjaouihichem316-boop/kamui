import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/main.dart';

void main() {
  testWidgets('Kamui app renders without crashing', (WidgetTester tester) async {
    await tester.pumpWidget(const KamuiApp());
    expect(find.text('KAMUI'), findsOneWidget);
  });
}
