import 'package:flutter_test/flutter_test.dart';
import 'package:local_biometric_auth/local_biometric_auth_platform_interface.dart';
import 'package:local_biometric_auth/local_biometric_auth_method_channel.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

class MockLocalBiometricAuthPlatform
    with MockPlatformInterfaceMixin
    implements LocalBiometricAuthPlatform {
  @override
  Future<String?> getPlatformVersion() => Future.value('42');
}

void main() {
  final LocalBiometricAuthPlatform initialPlatform =
      LocalBiometricAuthPlatform.instance;

  test('$MethodChannelLocalBiometricAuth is the default instance', () {
    expect(initialPlatform, isInstanceOf<MethodChannelLocalBiometricAuth>());
  });
}
