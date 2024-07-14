import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'dart:async';

import 'package:local_biometric_auth/local_biometric_auth.dart';
import 'package:logging/logging.dart';
import 'package:logging_appenders/logging_appenders.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: ExampleScreen(),
    );
  }
}

class ExampleScreen extends StatefulWidget {
  const ExampleScreen({super.key});

  @override
  State<ExampleScreen> createState() => _ExampleScreenState();
}

final MemoryAppender logMessages = MemoryAppender();
final _logger = Logger('main');

class _ExampleScreenState extends State<ExampleScreen> {
  // final _localBiometricAuthPlugin = LocalBiometricAuth();
  final String baseName = 'default';

  @override
  void initState() {
    super.initState();
    logMessages.log.addListener(_logChanged);
    _logger.onRecord.listen(logMessages.handle);
    _checkAuthenticate();
  }

  Future<CanAuthenticateResponse> _checkAuthenticate() async {
    final response = await LocalBiometricAuth().canAuthenticate();
    _logger.info('checked if authentication was possible: $response');
    return response;
  }

  void _logChanged() => setState(() {});
  final TextEditingController _writeController =
      TextEditingController(text: 'Lorem Ipsum');

  BiometricStorage? _authStorage;
  static String data = '';

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Plugin example app'),
      ),
      body: Column(
        children: [
          const Text('Methods:'),
          ElevatedButton(
            child: const Text('init'),
            onPressed: () async {
              _logger.finer('Initializing $baseName');
              final authenticate = await _checkAuthenticate();
              if (authenticate == CanAuthenticateResponse.unsupported) {
                _logger.severe(
                    'Unable to use authenticate. Unable to get storage.');
                return;
              }
              _authStorage = await LocalBiometricAuth().init("auth");
              _logger.info('initiailzed $baseName');
            },
          ),
          ...?_appArmorButton(),
          ...(_authStorage == null
              ? []
              : [
                  Row(
                    mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                    children: [
                      ElevatedButton(
                        child: const Text('read'),
                        onPressed: () async {
                          try {
                            final result =
                                await _authStorage?.decryptData(data);
                            _logger.info('read: {$result}');
                          } on AuthException catch (e) {
                            _logger.info(e.code);
                          }
                        },
                      ),
                      ElevatedButton(
                        child: const Text('write'),
                        onPressed: () async {
                          _logger.fine('Going to write...');
                          try {
                            data = await _authStorage?.encryptData(
                                    '[${DateTime.now()}] DuyQK') ??
                                '';
                            _logger.info('Written content.');
                          } on AuthException catch (e) {
                            _logger.info(e.code);
                          }
                        },
                      ),
                      ElevatedButton(
                        child: const Text('delete'),
                        onPressed: () async {
                          _logger.fine('deleting...');
                          await _authStorage?.delete();
                          _logger.info('Deleted.');
                        },
                      ),
                    ],
                  )
                ]),
          const Divider(),
          TextField(
            decoration: const InputDecoration(
              labelText: 'Example text to write',
            ),
            controller: _writeController,
          ),
          Expanded(
            child: Container(
              color: Colors.white,
              constraints: const BoxConstraints.expand(),
              child: SingleChildScrollView(
                reverse: true,
                child: Container(
                  padding: const EdgeInsets.all(16),
                  child: Text(
                    logMessages.log.toString(),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    logMessages.log.removeListener(_logChanged);
    super.dispose();
  }

  List<Widget>? _appArmorButton() => kIsWeb || !Platform.isLinux
      ? null
      : [
          ElevatedButton(
            child: const Text('Check App Armor'),
            onPressed: () async {
              _logger.info('all good.');
            },
          )
        ];
}

class StringBufferWrapper with ChangeNotifier {
  final StringBuffer _buffer = StringBuffer();

  void writeln(String line) {
    _buffer.writeln(line);
    notifyListeners();
  }

  @override
  String toString() => _buffer.toString();
}

class ShortFormatter extends LogRecordFormatter {
  @override
  StringBuffer formatToStringBuffer(LogRecord rec, StringBuffer sb) {
    sb.write(
        '${rec.time.hour}:${rec.time.minute}:${rec.time.second} ${rec.level.name} '
        '${rec.message}');

    if (rec.error != null) {
      sb.write(rec.error);
    }
    // ignore: avoid_as
    final stackTrace = rec.stackTrace ??
        (rec.error is Error ? (rec.error as Error).stackTrace : null);
    if (stackTrace != null) {
      sb.write(stackTrace);
    }
    return sb;
  }
}

class MemoryAppender extends BaseLogAppender {
  MemoryAppender() : super(ShortFormatter());

  final StringBufferWrapper log = StringBufferWrapper();

  @override
  void handle(LogRecord record) {
    log.writeln(formatter.format(record));
  }
}
