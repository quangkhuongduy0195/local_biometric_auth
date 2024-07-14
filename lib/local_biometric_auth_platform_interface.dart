import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'local_biometric_auth_method_channel.dart';

abstract class LocalBiometricAuthPlatform extends PlatformInterface {
  /// Constructs a LocalBiometricAuthPlatform.
  LocalBiometricAuthPlatform() : super(token: _token);

  static final Object _token = Object();

  static LocalBiometricAuthPlatform _instance = MethodChannelLocalBiometricAuth();

  /// The default instance of [LocalBiometricAuthPlatform] to use.
  ///
  /// Defaults to [MethodChannelLocalBiometricAuth].
  static LocalBiometricAuthPlatform get instance => _instance;

  /// Platform-specific implementations should set this with their own
  /// platform-specific class that extends [LocalBiometricAuthPlatform] when
  /// they register themselves.
  static set instance(LocalBiometricAuthPlatform instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<String?> getPlatformVersion() {
    throw UnimplementedError('platformVersion() has not been implemented.');
  }
}
