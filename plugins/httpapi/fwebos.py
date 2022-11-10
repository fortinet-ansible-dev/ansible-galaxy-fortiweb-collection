# (c) 2018 Red Hat Inc.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
---
author:
httpapi : fwebos
short_description: HttpApi Plugin for FortiWeb devices
description:
  - This HttpApi plugin provides methods to connect to FortiWeb
    devices over a HTTP(S)-based api.
version_added: "2.8"
"""

import json
import os
import re
import base64

from ansible.module_utils.basic import to_text
from ansible.errors import AnsibleConnectionFailure
from ansible.module_utils.six.moves.urllib.error import HTTPError
from ansible.plugins.httpapi import HttpApiBase
from ansible.module_utils.connection import ConnectionError

BASE_HEADERS = {
    'Content-Type': 'application/json',
}

FROM_HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded'
}


class HttpApi(HttpApiBase):
    def login(self, username, password):
        if username:
            if password is None:
                password = ''
            payload = {'username': str(username), 'password': str(password)}
#           url = '/api/user/login'
            # url = '/logincheck'
            # response, response_data = self.send_request(url, payload)
            # data = json.dumps(payload) if payload else '{}'
            data = 'ajax=1&username=admin&secretkey=a'

        else:
            raise AnsibleConnectionFailure('Username and password are required for login')

        try:
            # self._display_request()
            # response, rep_payload = self.connection.send(url, data, method='POST', headers=BASE_HEADERS)

            # value = self._get_response_value(rep_payload)
            # response_data = self._response_to_json(value)
            # cookie = response.info().get('Set-Cookie')
            # self.connection._auth = {'Authorization': 'Bearer ' + response_data['token'], 'Cookie': cookie}

            userPswd_dict = {"username": str(username), "password": str(password)}
            userPswd = json.dumps(payload)
            auth = base64.b64encode(userPswd.encode(encoding='utf-8'))
            self.connection._auth = {'Authorization': auth}
        except KeyError:
            raise ConnectionError(
                'Server returned response without token info during connection authentication: %s' % response)

    def logout(self):
        url = '/api/user/logout'

        response, dummy = self.send_request(url, None, method_req='GET')

    def change_auth_for_vdom(self, vdom):
        userPswd_dict = {
            "username": str(self.connection.get_option('remote_user')),
            "password": str(self.connection.get_option('password')),
            "vdom": vdom,
        }
        userPswd = json.dumps(userPswd_dict)
        auth = base64.b64encode(userPswd.encode(encoding='utf-8'))
        self.connection._auth = {'Authorization': auth}
        return auth

    def get_session_uid(self):
        return self.connection._session_uid

    def send_request(self, path, body_params, method_req='POST'):
        data = json.dumps(body_params) if body_params else '{}'

        try:
            # self._display_request()
            response, response_data = self.connection.send(path, data, method=method_req, headers=BASE_HEADERS)
            value = self._get_response_value(response_data)

            return response.getcode(), self._response_to_json(value)
        except AnsibleConnectionFailure as e:
            return 404, 'Object not found'
        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error

    def send_url_request(self, path, body_params, method_req='POST', headers=BASE_HEADERS):

        try:
            response, response_data = self.connection.send(path, body_params, method=method_req, headers=headers)
            value = self._get_response_value(response_data)

            return response.getcode(), self._response_to_json(value)
        except AnsibleConnectionFailure as e:
            return 404, 'Object not found'
        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error

    def send_non_json_request(self, path, body_params, method_req='POST'):
        data = body_params

        try:
            # self._display_request()
            response, response_data = self.connection.send(path, data, method=method_req, headers=FROM_HEADERS)
            value = self._get_response_value(response_data)

            return response.getcode(), self._response_to_json(value)
        except AnsibleConnectionFailure as e:
            return 404, 'Object not found'
        except HTTPError as e:
            error = json.loads(e.read())
            return e.code, error

    def download_file(self, from_url, to_path, path_params=None):
        filename = ''
        url = from_url  # construct_url_path(from_url, path_params=path_params)
        response, response_data = self.connection.send(url, data=None, method='GET', headers=BASE_HEADERS)

        if os.path.isdir(to_path):
            content_header_regex = r'attachment; ?filename="?([^"]+)'
            match = re.match(content_header_regex, response.info().get('Content-Disposition'))
            filename = match.group(1)
            to_path = os.path.join(to_path, filename)

        with open(to_path, "wb") as output_file:
            output_file.write(response_data.getvalue())

        return filename

    # def _display_request(self):
        # self.connection.queue_message('vvvv', 'Web Services: %s %s' % ('POST', self.connection._url))

    def _get_response_value(self, response_data):
        return to_text(response_data.getvalue())

    def _response_to_json(self, response_text):
        try:
            return json.loads(response_text) if response_text else {}
        # JSONDecodeError only available on Python 3.5+
        except ValueError:
            raise ConnectionError('Invalid JSON response: %s' % response_text)
