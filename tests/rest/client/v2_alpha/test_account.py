# -*- coding: utf-8 -*-
# Copyright 2019 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

from synapse.rest import admin
from synapse.rest.client.v1 import login
from synapse.rest.client.v2_alpha import account

from tests import unittest


class DeactivateTestCase(unittest.HomeserverTestCase):

    servlets = [
        admin.register_servlets_for_client_rest_resource,
        login.register_servlets,
        account.register_servlets,
    ]

    def make_homeserver(self, reactor, clock):
        hs = self.setup_test_homeserver()
        return hs

    def test_deactivate_account(self):
        user_id = self.register_user("kermit", "test")
        tok = self.login("kermit", "test")

        request_data = json.dumps({
            "auth": {
                "type": "m.login.password",
                "user": user_id,
                "password": "test",
            },
            "erase": False,
        })
        request, channel = self.make_request(
            "POST",
            "account/deactivate",
            request_data,
            access_token=tok,
        )
        self.render(request)
        self.assertEqual(request.code, 200)

        store = self.hs.get_datastore()

        # Check that the user has been marked as deactivated.
        self.assertTrue(self.get_success(store.get_user_deactivated_status(user_id)))

        # Check that this access token has been invalidated.
        request, channel = self.make_request("GET", "account/whoami")
        self.render(request)
        self.assertEqual(request.code, 401)
