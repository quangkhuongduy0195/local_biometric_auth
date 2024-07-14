import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'local_biometric_auth_platform_interface.dart';

/// An implementation of [LocalBiometricAuthPlatform] that uses method channels.
class MethodChannelLocalBiometricAuth extends LocalBiometricAuthPlatform {
  /// The method channel used to interact with the native platform.
  @visibleForTesting
  final methodChannel = const MethodChannel('local_biometric_auth');

  @override
  Future<String?> getPlatformVersion() async {
    final version = await methodChannel.invokeMethod<String>('getPlatformVersion');
    return version;
  }
}
