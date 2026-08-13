import pytest
import sys
import os
import io
import importlib.util

from bottle import Bottle, response, request, static_file, redirect

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

spec = importlib.util.spec_from_file_location(
    'openvpn_monitor',
    os.path.join(os.path.dirname(__file__), '..', 'openvpn-monitor.py'))
ovpn = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ovpn)

ovpn.Bottle = Bottle
ovpn.response = response
ovpn.request = request
ovpn.static_file = static_file
ovpn.redirect = redirect
ovpn.wsgi = True
ovpn.wsgi_output = ''

if not hasattr(ovpn, 'args'):
    class _Args(object):
        debug = False
        config = './openvpn-monitor.conf'
    ovpn.args = _Args()

ConfigLoader = ovpn.ConfigLoader
monitor_wsgi = ovpn.monitor_wsgi


def _write_config(tmp_path, username=None, password=None, secret=None):
    lines = ['[openvpn-monitor]\n', 'site=TestSite\n']
    if username is not None:
        lines += ['username={0}\n'.format(username)]
    if password is not None:
        lines += ['password={0}\n'.format(password)]
    if secret is not None:
        lines += ['secret={0}\n'.format(secret)]
    lines += ['[VPN1]\n', 'host=localhost\n', 'port=5555\n']
    cfg_file = str(tmp_path / 'openvpn-monitor.conf')
    with open(cfg_file, 'w') as f:
        f.writelines(lines)
    return cfg_file


def _build_app(tmp_path, username=None, password=None, secret=None):
    ovpn.wsgi_output = ''
    cfg_file = _write_config(tmp_path, username, password, secret)
    ovpn.args.config = cfg_file
    return monitor_wsgi()


def _call_app(app, env):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured['status'] = status
        captured['headers'] = headers
        return lambda *a: None

    body = b''.join(app(env, start_response))
    return captured.get('status', ''), captured.get('headers', []), body


def _make_env(method='GET', path='/', body=None, cookie=''):
    body_bytes = body.encode('utf-8') if body else b''
    env = {'REQUEST_METHOD': method,
           'PATH_INFO': path,
           'QUERY_STRING': '',
           'SCRIPT_NAME': '',
           'SERVER_NAME': 'localhost',
           'SERVER_PORT': '80',
           'SERVER_PROTOCOL': 'HTTP/1.1',
           'HTTP_HOST': 'localhost',
           'wsgi.version': (1, 0),
           'wsgi.url_scheme': 'http',
           'wsgi.errors': io.StringIO(),
           'wsgi.input': io.BytesIO(body_bytes),
           'wsgi.multithread': False,
           'wsgi.multiprocess': False,
           'wsgi.run_once': False}
    if cookie:
        env['HTTP_COOKIE'] = cookie
    if body:
        env['CONTENT_TYPE'] = 'application/x-www-form-urlencoded'
        env['CONTENT_LENGTH'] = str(len(body_bytes))
    return env


def _login(app, username='admin', password='secret'):
    """POST /login with correct credentials; returns (status, headers)."""
    body = 'username={0}&password={1}'.format(username, password)
    return _call_app(app, _make_env('POST', '/login', body))


def _set_cookie(headers):
    """Extract the session cookie from a Set-Cookie header value."""
    for name, value in headers:
        if name.lower() == 'set-cookie':
            return value.split(';')[0]
    return ''


class TestLoginRequired:
    def test_redirects_to_login_when_credentials_configured(self, tmp_path):
        app = _build_app(tmp_path, username='admin', password='secret', secret='s3cr3t')
        status, headers, _ = _call_app(app, _make_env('GET', '/'))
        assert status.startswith('303') or status.startswith('302')
        assert (dict(headers).get('Location') or '').endswith('/login')

    def test_no_redirect_when_no_credentials(self, tmp_path):
        app = _build_app(tmp_path)
        status, _, _ = _call_app(app, _make_env('GET', '/'))
        assert status.startswith('200')

    def test_login_page_returns_200(self, tmp_path):
        app = _build_app(tmp_path, username='admin', password='secret', secret='s3cr3t')
        status, _, body = _call_app(app, _make_env('GET', '/login'))
        assert status.startswith('200')
        html = body.decode('utf-8')
        assert 'Login' in html
        assert 'username' in html
        assert 'password' in html

    def test_wrong_password_rejected(self, tmp_path):
        app = _build_app(tmp_path, username='admin', password='secret', secret='s3cr3t')
        body = 'username=admin&password=wrong'
        status, _, resp_body = _call_app(app, _make_env('POST', '/login', body))
        assert status.startswith('200')
        html = resp_body.decode('utf-8')
        assert 'Login' in html

    def test_correct_password_grants_access(self, tmp_path):
        app = _build_app(tmp_path, username='admin', password='secret', secret='s3cr3t')
        status, headers, _ = _login(app)
        assert status.startswith('303') or status.startswith('302')
        assert (dict(headers).get('Location') or '').endswith('/')
        assert 'openvpn-monitor-session' in _set_cookie(headers)

    def test_session_cookie_opens_status_page(self, tmp_path):
        app = _build_app(tmp_path, username='admin', password='secret', secret='s3cr3t')
        _, headers, _ = _login(app)
        cookie = _set_cookie(headers)
        status, _, body = _call_app(app, _make_env('GET', '/', cookie=cookie))
        assert status.startswith('200')
        assert 'OpenVPN' in body.decode('utf-8')

    def test_logout_clears_session(self, tmp_path):
        app = _build_app(tmp_path, username='admin', password='secret', secret='s3cr3t')
        _, headers, _ = _login(app)
        cookie = _set_cookie(headers)
        status, headers, _ = _call_app(app, _make_env('GET', '/logout', cookie=cookie))
        assert status.startswith('303') or status.startswith('302')
        assert (dict(headers).get('Location') or '').endswith('/login')
        # logout clears the cookie client-side (expiry in the past)
        set_cookie = ''
        for name, value in headers:
            if name.lower() == 'set-cookie':
                set_cookie = value
        assert 'openvpn-monitor-session' in set_cookie
        assert '01 jan 1970' in set_cookie.lower() or 'max-age=0' in set_cookie.lower() or 'max-age=-1' in set_cookie.lower()
