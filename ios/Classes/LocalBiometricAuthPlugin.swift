import Flutter
import UIKit

public class LocalBiometricAuthPlugin: NSObject, FlutterPlugin {
    
    private let impl = BiometricStorageImpl(storageError: { (code, message, details) -> Any in
        FlutterError(code: code, message: message, details: details)
      }, storageMethodNotImplemented: FlutterMethodNotImplemented)
    
  public static func register(with registrar: FlutterPluginRegistrar) {
    let channel = FlutterMethodChannel(name: "local_biometric_auth", binaryMessenger: registrar.messenger())
    let instance = LocalBiometricAuthPlugin()
    registrar.addMethodCallDelegate(instance, channel: channel)
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
      impl.handle(StorageMethodCall(method: call.method, arguments: call.arguments), result: result)
  }
}
