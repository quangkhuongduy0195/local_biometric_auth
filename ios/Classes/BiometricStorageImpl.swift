//
//  BiometricStorageImpl.swift
//  local_biometric_auth
//
//  Created by Quảng Khương Duy on 12/7/24.
//

import Foundation
import LocalAuthentication


typealias StorageCallback = (Any?) -> Void
typealias StorageError = (String, String?, Any?) -> Any

struct StorageMethodCall {
  let method: String
  let arguments: Any?
}

class InitOptions {
  init(params: [String: Any]) {
    darwinTouchIDAuthenticationAllowableReuseDuration = params["drawinTouchIDAuthenticationAllowableReuseDurationSeconds"] as? Int
    darwinTouchIDAuthenticationForceReuseContextDuration = params["darwinTouchIDAuthenticationForceReuseContextDurationSeconds"] as? Int
    authenticationRequired = params["authenticationRequired"] as? Bool
    darwinBiometricOnly = params["darwinBiometricOnly"] as? Bool
  }
  let darwinTouchIDAuthenticationAllowableReuseDuration: Int?
  let darwinTouchIDAuthenticationForceReuseContextDuration: Int?
  let authenticationRequired: Bool!
  let darwinBiometricOnly: Bool!
}

class IOSPromptInfo {
  init(params: [String: Any]) {
    saveTitle = params["saveTitle"] as? String
    accessTitle = params["accessTitle"] as? String
  }
  let saveTitle: String!
  let accessTitle: String!
}

private func hpdebug(_ message: String) {
  print(message);
}

class BiometricStorageImpl {
  
  init(storageError: @escaping StorageError, storageMethodNotImplemented: Any) {
    self.storageError = storageError
    self.storageMethodNotImplemented = storageMethodNotImplemented
  }
  
  private let storageError: StorageError
  private let storageMethodNotImplemented: Any

  private func storageError(code: String, message: String?, details: Any?) -> Any {
    return storageError(code, message, details)
  }

  public func handle(_ call: StorageMethodCall, result: @escaping StorageCallback) {
    
    func requiredArg<T>(_ key: String, _ cb: (T) -> Void) {
      guard let args = call.arguments as? Dictionary<String, Any> else {
        result(storageError(code: "InvalidArguments", message: "Invalid arguments \(String(describing: call.arguments))", details: nil))
        return
      }
      guard let value = args[key] else {
        result(storageError(code: "InvalidArguments", message: "Missing argument \(key)", details: nil))
        return
      }
      guard let valueTyped = value as? T else {
        result(storageError(code: "InvalidArguments", message: "Invalid argument for \(key): expected \(T.self) got \(value)", details: nil))
        return
      }
      cb(valueTyped)
      return
    }
    
    if ("canAuthenticate" == call.method) {
        canAuthenticate(result: result)
    } else if ("init" == call.method) {
//        canAuthenticate(result: result)
//       _ =  KeychainManager.shared.encrypt(name: "DUYQK11", publicKey: "DUYQK")
        BiometricAuthManager.shared.authenticateWithBiometrics { r, err in
            result(r)
        }
    } else if ("dispose" == call.method) {
      
      result(true)
    } else if ("read" == call.method) {
        requiredArg("name") { name  in
            requiredArg("content") { value in
                showBiometricVerify { success, err in
                    if success {
                        let resultValue = CryptographyManager.shared.decrypt(secretKeyName: name, value: value)
                         result(resultValue)
                    } else {
                        return result(nil)
                    }
                }
            }
        }
    } else if ("write" == call.method) {
        requiredArg("name") { name  in
            requiredArg("content") { value in
                showBiometricVerify { success, err in
                    if success {
                        let resultValue = CryptographyManager.shared.encrypt(secretKeyName: name, plainText: value)
                         result(resultValue)
                    } else {
                        return result(nil)
                    }
                }
            }
        }
    } else if ("delete" == call.method) {
        requiredArg("name") { name  in
            CryptographyManager.shared.delete(secretKeyName: name)
        }
    } else {
      result(storageMethodNotImplemented)
    }
  }
    
    private func showBiometricVerify(callBack : @escaping (_ success : Bool, _ err : Error?) -> Void) {
        let biometricManager = BiometricAuthManager.shared
        biometricManager.authenticateWithBiometrics { success, error in
            
            callBack(success, error)
            if success {
                
            } else if let error = error {
                // Handle authentication failure or errors
                // For example, show an error message to the user
                print("Biometric authentication failed with error: \(error.localizedDescription)")
            } else {
                // Biometric authentication was canceled or failed
                // Handle the case where the user cancels or the authentication fails
                print("Biometric authentication was canceled or failed")
            }
        }
    }
    
    private func handleOSStatusError(_ status: OSStatus, _ result: @escaping StorageCallback, _ message: String) {
        var errorMessage: String? = nil
        if #available(iOS 11.3, OSX 10.12, *) {
          errorMessage = SecCopyErrorMessageString(status, nil) as String?
        }
        let code: String
        switch status {
        case errSecUserCanceled:
          code = "AuthError:UserCanceled"
        default:
          code = "SecurityError"
        }
        
        result(storageError(code, "Error while \(message): \(status): \(errorMessage ?? "Unknown")", nil))
      }

  

  private func canAuthenticate(result: @escaping StorageCallback) {
    var error: NSError?
    let context = LAContext()
    if context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) {
      result("Success")
      return
    }
    guard let err = error else {
      result("ErrorUnknown")
      return
    }
    let laError = LAError(_nsError: err)
    NSLog("LAError: \(laError)");
    switch laError.code {
    case .touchIDNotAvailable:
      result("ErrorHwUnavailable")
      break;
    case .passcodeNotSet:
      result("ErrorPasscodeNotSet")
      break;
    case .touchIDNotEnrolled:
      result("ErrorNoBiometricEnrolled")
      break;
    case .invalidContext: fallthrough
    default:
      result("ErrorUnknown")
      break;
    }
  }
}

typealias StoredContext = (context: LAContext, expireAt: Date)


class BiometricAuthManager {
    static let shared = BiometricAuthManager()
    
    // UserDefaults key for the switch state
    private let biometricSwitchKey = "biometricSwitchState"
    
    private init() {}
    
    // Function to set the state of the biometric switch
    func setBiometricSwitchState(isOn: Bool) {
        UserDefaults.standard.set(isOn, forKey: biometricSwitchKey)
    }
    
    // Function to get the state of the biometric switch
    func isBiometricSwitchOn() -> Bool {
        return UserDefaults.standard.bool(forKey: biometricSwitchKey)
    }
    
    func canUseBiometricAuthentication() -> Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    func getBiometricType() -> LABiometryType {
        let context = LAContext()
        return context.biometryType
    }
    func authenticateWithBiometrics(completion: @escaping (Bool, Error?) -> Void) {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: "Authenticate using Face ID or Touch ID") { success, error in
            DispatchQueue.main.async {
                completion(success, error)
            }
        }
    }
    func showBiometricsSettingsAlert(_ controller: UIViewController) {
        let alertController = UIAlertController(
            title: "Enable Face ID/Touch ID",
            message: "To use biometric authentication, you need to enable Face ID/Touch ID for this app in your device settings.",
            preferredStyle: .alert
        )
        let settingsAction = UIAlertAction(title: "Go to Settings", style: .default) { _ in
            if let settingsURL = URL(string: UIApplication.openSettingsURLString) {
                UIApplication.shared.open(settingsURL, options: [:], completionHandler: nil)
            }
        }
        alertController.addAction(settingsAction)
        let cancelAction = UIAlertAction(title: "Cancel", style: .cancel, handler: nil)
        alertController.addAction(cancelAction)
        controller.present(alertController, animated: true, completion: nil)
    }
}
