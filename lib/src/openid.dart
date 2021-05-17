library steam_login.openid;

import 'dart:io';

import 'package:http/http.dart' as http;
import 'exceptions.dart';

class OpenId {
  final _steam_login = 'https://steamcommunity.com/openid/login';

  final _openId_mode = 'checkid_setup';
  final _openId_ns = 'http://specs.openid.net/auth/2.0';
  final _openId_identifier =
      'http://specs.openid.net/auth/2.0/identifier_select';

  final RegExp _validation_regexp =
      RegExp(r'^https://steamcommunity.com/openid/id/(7[0-9]{15,25})$');

  String? _host;
  String? _returnUrl;
  late Map<String, String> _data;

  /// [OpenId] constructor, requires the current [HttpRequest],
  /// The [_host] and [_returnUrl] are taken from the [HttpRequest.requestedUri],
  /// [_returnUrl] is usually the current URL.
  OpenId(HttpRequest request) {
    _host = '${request.requestedUri.scheme}://${request.requestedUri.host}';
    _returnUrl = '$_host${request.requestedUri.path}';
    _data = request.uri.queryParameters;
  }

  /// Return the authUrl
  Uri authUrl() {
    final data = {
      'openid.claimed_id': _openId_identifier,
      'openid.identity': _openId_identifier,
      'openid.mode': _openId_mode,
      'openid.ns': _openId_ns,
      'openid.realm': _host,
      'openid.return_to': _returnUrl
    };

    Uri uri = _host!.startsWith('https')
        ? Uri.https('steamcommunity.com', '/openid/login', data)
        : Uri.http('steamcommunity.com', '/openid/login', data);
    return uri;
  }

  /// Must be called only when mode is 'id_res' or an [OpenIdException] will be thrown.
  /// Validates the authentication and return a [Future] string with the user's steamid64.
  Future<String?> validate() async {
    if (mode != 'id_res') {
      throw OpenIdException(
          OpenIdFailReason.param, 'must be equal to "id_res".', 'openid.mode');
    }

    if (_data['openid.return_to'] != _returnUrl) {
      throw OpenIdException(OpenIdFailReason.param,
          'must match the url of the current request.', 'openid.return_to');
    }

    Map<String, String?> params = {
      'openid.assoc_handle': _data['openid.assoc_handle'],
      'openid.signed': _data['openid.signed'],
      'openid.sig': _data['openid.sig'],
      'openid.ns': _data['openid.ns']
    };

    if (params.containsValue(null) || _data['openid.signed'] == null) {
      throw OpenIdException(OpenIdFailReason.params, 'Invalid OpenID params!');
    }

    List<String> split = _data['openid.signed']!.split(',');
    for (var part in split) {
      params['openid.$part'] = _data['openid.$part'];
    }
    params['openid.mode'] = 'check_authentication';

    var resp = await http.post(Uri.parse(_steam_login), body: params);

    split = resp.body.split('\n');
    if (split[0] != 'ns:$_openId_ns')
      throw OpenIdException(
          OpenIdFailReason.invalid, 'Wrong ns in the response');

    if (split[1].endsWith('false')) {
      throw OpenIdException(
          OpenIdFailReason.invalid, 'Unable to validate openId');
    }

    var openIdUrl = _data['openid.claimed_id']!;
    if (!_validation_regexp.hasMatch(openIdUrl)) {
      throw OpenIdException(
          OpenIdFailReason.pattern, 'Invalid steam id pattern');
    }

    return _validation_regexp.firstMatch(openIdUrl)!.group(1);
  }

  /// Current [host].
  String? get host => _host;

  /// Current [returnUrl]
  String? get returnUrl => _returnUrl;

  /// Current [mode] (or an empty string if no mode is set).
  String get mode => _data['openid.mode'] ?? '';
}
