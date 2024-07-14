package com.duyqk.local_biometric_auth

import CryptographyManager
import android.app.Activity
import android.content.Context
import android.os.*
import android.util.Base64
import android.util.Log
import androidx.annotation.AnyThread
import androidx.annotation.UiThread
import androidx.annotation.WorkerThread
import androidx.biometric.*
import androidx.biometric.BiometricManager.Authenticators.*
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
//import androidx.fragment.app.FragmentActivity
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.*
import io.flutter.plugin.common.*
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.plugin.common.MethodChannel.Result
import io.github.oshai.kotlinlogging.KotlinLogging
import java.io.PrintWriter
import java.io.StringWriter
import java.nio.Buffer
import java.nio.charset.Charset
import java.security.SecureRandom
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors


private val logger = KotlinLogging.logger {}

enum class CipherMode {
  Encrypt,
  Decrypt,
}

data class AndroidPromptInfo(
  val title: String,
  val subtitle: String?,
  val description: String?,
  val negativeButton: String,
  val confirmationRequired: Boolean
)

typealias ErrorCallback = (errorInfo: AuthenticationErrorInfo) -> Unit

class MethodCallException(
  val errorCode: String,
  val errorMessage: String?,
  val errorDetails: Any? = null
) : Exception(errorMessage ?: errorCode)

@Suppress("unused")
enum class CanAuthenticateResponse(val code: Int) {
  Success(BiometricManager.BIOMETRIC_SUCCESS),
  ErrorHwUnavailable(BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE),
  ErrorNoBiometricEnrolled(BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED),
  ErrorNoHardware(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE),
  ErrorStatusUnknown(BiometricManager.BIOMETRIC_STATUS_UNKNOWN),
  ErrorPasscodeNotSet(-99),
  ;

  override fun toString(): String {
    return "CanAuthenticateResponse.${name}: $code"
  }
}

@Suppress("unused")
enum class AuthenticationError(vararg val code: Int) {
  Canceled(BiometricPrompt.ERROR_CANCELED),
  Timeout(BiometricPrompt.ERROR_TIMEOUT),
  UserCanceled(BiometricPrompt.ERROR_USER_CANCELED, BiometricPrompt.ERROR_NEGATIVE_BUTTON),
  Unknown(-1),

  /** Authentication valid, but unknown */
  Failed(-2),
  ;

  companion object {
    fun forCode(code: Int) =
      values().firstOrNull { it.code.contains(code) } ?: Unknown
  }
}

data class AuthenticationErrorInfo(
  val error: AuthenticationError,
  val message: CharSequence,
  val errorDetails: String? = null
) {
  constructor(
    error: AuthenticationError,
    message: CharSequence,
    e: Throwable
  ) : this(error, message, e.toCompleteString())
}

private fun Throwable.toCompleteString(): String {
  val out = StringWriter().let { out ->
    printStackTrace(PrintWriter(out))
    out.toString()
  }
  return "$this\n$out"
}


/** LocalBiometricAuthPlugin */
class LocalBiometricAuthPlugin: FlutterPlugin, ActivityAware, MethodCallHandler {

  companion object {
    const val PARAM_NAME = "name"
    const val PARAM_WRITE_CONTENT = "content"
    const val PARAM_ANDROID_PROMPT_INFO = "androidPromptInfo"
  }
  private var secretKeyName = "biometric_encryption_key"
  private val executor: ExecutorService by lazy { Executors.newSingleThreadExecutor() }
  private val handler: Handler by lazy { Handler(Looper.getMainLooper()) }
  private var attachedActivity: FragmentActivity? = null
  private val biometricManager by lazy { BiometricManager.from(applicationContext) }

  private lateinit var applicationContext: Context
  private lateinit var channel : MethodChannel
//  private lateinit var biometricPrompt: BiometricPrompt
  private lateinit var cryptographyManager: CryptographyManager
  private var readyToEncrypt: Boolean = false
//  private lateinit var ciphertext:ByteArray

  override fun onAttachedToEngine(flutterPluginBinding: FlutterPlugin.FlutterPluginBinding) {
    this.applicationContext = flutterPluginBinding.applicationContext
    channel = MethodChannel(flutterPluginBinding.binaryMessenger, "local_biometric_auth")
    channel.setMethodCallHandler(this)
    cryptographyManager = CryptographyManager()
  }

  override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
    channel.setMethodCallHandler(null)
    executor.shutdown()
  }

  override fun onMethodCall(call: MethodCall, result: Result) {
    logger.trace { "onMethodCall(${call.method})" }
    try {
      fun <T> requiredArgument(name: String) =
        call.argument<T>(name) ?: throw MethodCallException(
          "MissingArgument",
          "Missing required argument '$name'"
        )

      // every method call requires the name of the stored file.
      val getName = { requiredArgument<String>(PARAM_NAME) }
      val getAndroidPromptInfo = {
        requiredArgument<Map<String, Any>>(PARAM_ANDROID_PROMPT_INFO).let {
          AndroidPromptInfo(
            title = it["title"] as String,
            subtitle = it["subtitle"] as String?,
            description = it["description"] as String?,
            negativeButton = it["negativeButton"] as String,
            confirmationRequired = it["confirmationRequired"] as Boolean,
          )
        }
      }



      val resultError: ErrorCallback = { errorInfo ->
        result.error(
          "AuthError:${errorInfo.error}",
          errorInfo.message.toString(),
          errorInfo.errorDetails
        )
        logger.error { "AuthError: $errorInfo" }

      }

      when (call.method) {
        "getPlatformVersion" -> result.success("Android ${android.os.Build.VERSION.RELEASE}")
        "canAuthenticate" -> result.success(canAuthenticate().name)
        "init" -> {
          secretKeyName = requiredArgument<String>(PARAM_NAME)
          result.success(canAuthenticate() == CanAuthenticateResponse.Success)
        }
        "dispose" -> {}
        "read" -> {
          val canAuth = canAuthenticate()
          if(canAuth == CanAuthenticateResponse.Success) {
            secretKeyName = requiredArgument<String>(PARAM_NAME)
            readyToEncrypt = false
//          if (BiometricManager.from(applicationContext).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager
//              .BIOMETRIC_SUCCESS)
              val data = requiredArgument<String>(PARAM_WRITE_CONTENT)
              val ciphertext = Base64.decode(data, Base64.DEFAULT)

              val iv = ByteArray(16)
              System.arraycopy(ciphertext, 0, iv, 0, 16)
              val cipher = cryptographyManager.getInitializedCipherForDecryption(secretKeyName,iv)
              val biometricPrompt = createBiometricPrompt(data, result)

              if(biometricPrompt !=null) {
                val promptInfo = createPromptInfo(getAndroidPromptInfo())
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
              } else {
                result.error("biometric_fail", "fail", "")
              }
          } else {
            result.success(canAuth.name)
          }

        }
        "delete" -> {
          cryptographyManager.delete(secretKeyName)
          result.success(true)
        }
        "write" ->{
          val canAuth = canAuthenticate()
          if(canAuth == CanAuthenticateResponse.Success) {
            readyToEncrypt = true
            secretKeyName = requiredArgument<String>(PARAM_NAME)
//          if (BiometricManager.from(applicationContext).canAuthenticate() == BiometricManager
//              .BIOMETRIC_SUCCESS)

              val iv = ByteArray(16)
              val secureRandom = SecureRandom()
              secureRandom.nextBytes(iv)


              val cipher = cryptographyManager.getInitializedCipherForEncryption(secretKeyName, iv)
              val password = requiredArgument<String>(PARAM_WRITE_CONTENT)
              val biometricPrompt = createBiometricPrompt(password, result)
              if (biometricPrompt != null) {
                val promptInfo = createPromptInfo(getAndroidPromptInfo())
                biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
              } else {
                result.success(CanAuthenticateResponse.ErrorStatusUnknown)
              }
          } else {
            result.success(canAuth.name)
          }
        }
        else -> result.notImplemented()
      }
    } catch (e: MethodCallException) {
      logger.error(e) { "Error while processing method call ${call.method}" }
      result.error(e.errorCode, e.errorMessage, e.errorDetails)
    } catch (e: Exception) {
      logger.error(e) { "Error while processing method call '${call.method}'" }
      result.error("Unexpected Error", e.message, e.toCompleteString())
    }
  }

  private fun createBiometricPrompt(password: String, result: MethodChannel.Result): BiometricPrompt? {
    val executor = ContextCompat.getMainExecutor(applicationContext)

    val callback = object : BiometricPrompt.AuthenticationCallback() {
      override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
        super.onAuthenticationError(errorCode, errString)
//        if(errorCode == 7){
//          result.error("AuthError:Block", errString.toString(), null)
//        } else {
//          result.error("AuthError:$errorCode", errString.toString(), null)
//        }

        result.success(null)
      }

      override fun onAuthenticationFailed() {
        super.onAuthenticationFailed()
//        result.error("error", null, null)
      }

      override fun onAuthenticationSucceeded(biometricResult: BiometricPrompt.AuthenticationResult) {
        super.onAuthenticationSucceeded(biometricResult)
          val value = processData(biometricResult.cryptoObject, password)
          result.success(value)
      }
    }

    //The API requires the client/Activity context for displaying the prompt view
    if(attachedActivity != null) {
      val biometricPrompt = attachedActivity?.let { BiometricPrompt(it, executor, callback) }
      return biometricPrompt
    }
    return null
  }

  private fun processData(cryptoObject: BiometricPrompt.CryptoObject?, password : String) : String {
    val data = if (readyToEncrypt) {
      val encryptedData = password.let { cryptographyManager.encryptData(it, cryptoObject?.cipher!!) }
      val ciphertext = encryptedData.ciphertext
      Base64.encodeToString(ciphertext, Base64.DEFAULT);
    } else {
      val ciphertext = Base64.decode(password, Base64.DEFAULT)
      cryptographyManager.decryptData(ciphertext, cryptoObject?.cipher!!)
    }
    return  data
  }

  private fun createPromptInfo(promptInfo: AndroidPromptInfo): BiometricPrompt.PromptInfo {
    return BiometricPrompt.PromptInfo.Builder()
      .setTitle(promptInfo.title)
      .setSubtitle(promptInfo.subtitle)
      .setDescription(promptInfo.description)
      .setConfirmationRequired(false)
      .setNegativeButtonText("Use Account Password")
      .build()
  }

  private fun canAuthenticate(): CanAuthenticateResponse {
    val credentialsResponse = biometricManager.canAuthenticate(DEVICE_CREDENTIAL)
    logger.debug { "canAuthenticate for DEVICE_CREDENTIAL: $credentialsResponse" }
    if (credentialsResponse == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED) {
      return CanAuthenticateResponse.ErrorNoBiometricEnrolled
    }

    val response = biometricManager.canAuthenticate(
      BIOMETRIC_STRONG or BIOMETRIC_WEAK
    )
    return CanAuthenticateResponse.values().firstOrNull { it.code == response }
      ?: throw Exception(
        "Unknown response code {$response} (available: ${
          CanAuthenticateResponse
            .values()
            .contentToString()
        }"
      )
  }

  override fun onDetachedFromActivity() {
    logger.trace { "onDetachedFromActivity" }
    attachedActivity = null
  }

  override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
  }

  override fun onAttachedToActivity(binding: ActivityPluginBinding) {
    logger.debug { "Attached to new activity." }
    updateAttachedActivity(binding.activity)
  }

  override fun onDetachedFromActivityForConfigChanges() {
  }

  private fun updateAttachedActivity(activity: Activity) {
    if (activity !is FragmentActivity) {
      logger.error { "Got attached to activity which is not a FragmentActivity: $activity" }
      return
    }
    attachedActivity = activity
  }

}