# -*- coding: utf-8 -*-
# Copyright 2016 OpenMarket Ltd
# Copyright 2019 New Vector Ltd
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

import mock

import signedjson.key as key
import signedjson.sign as sign

from twisted.internet import defer

import synapse.api.errors
import synapse.handlers.e2e_keys
import synapse.storage
from synapse.api import errors

from tests import unittest, utils


class E2eKeysHandlerTestCase(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(E2eKeysHandlerTestCase, self).__init__(*args, **kwargs)
        self.hs = None  # type: synapse.server.HomeServer
        self.handler = None  # type: synapse.handlers.e2e_keys.E2eKeysHandler

    @defer.inlineCallbacks
    def setUp(self):
        self.hs = yield utils.setup_test_homeserver(
            self.addCleanup, handlers=None, federation_client=mock.Mock()
        )
        self.handler = synapse.handlers.e2e_keys.E2eKeysHandler(self.hs)

    @defer.inlineCallbacks
    def test_query_local_devices_no_devices(self):
        """If the user has no devices, we expect an empty list.
        """
        local_user = "@boris:" + self.hs.hostname
        res = yield self.handler.query_local_devices({local_user: None})
        self.assertDictEqual(res, {local_user: {}})

    @defer.inlineCallbacks
    def test_reupload_one_time_keys(self):
        """we should be able to re-upload the same keys"""
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {
            "alg1:k1": "key1",
            "alg2:k2": {"key": "key2", "signatures": {"k1": "sig1"}},
            "alg2:k3": {"key": "key3"},
        }

        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1, "alg2": 2}})

        # we should be able to change the signature without a problem
        keys["alg2:k2"]["signatures"]["k1"] = "sig2"
        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1, "alg2": 2}})

    @defer.inlineCallbacks
    def test_change_one_time_keys(self):
        """attempts to change one-time-keys should be rejected"""

        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {
            "alg1:k1": "key1",
            "alg2:k2": {"key": "key2", "signatures": {"k1": "sig1"}},
            "alg2:k3": {"key": "key3"},
        }

        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1, "alg2": 2}})

        try:
            yield self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg1:k1": "key2"}}
            )
            self.fail("No error when changing string key")
        except errors.SynapseError:
            pass

        try:
            yield self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg2:k3": "key2"}}
            )
            self.fail("No error when replacing dict key with string")
        except errors.SynapseError:
            pass

        try:
            yield self.handler.upload_keys_for_user(
                local_user, device_id, {"one_time_keys": {"alg1:k1": {"key": "key"}}}
            )
            self.fail("No error when replacing string key with dict")
        except errors.SynapseError:
            pass

        try:
            yield self.handler.upload_keys_for_user(
                local_user,
                device_id,
                {
                    "one_time_keys": {
                        "alg2:k2": {"key": "key3", "signatures": {"k1": "sig1"}}
                    }
                },
            )
            self.fail("No error when replacing dict key")
        except errors.SynapseError:
            pass

    @defer.inlineCallbacks
    def test_claim_one_time_key(self):
        local_user = "@boris:" + self.hs.hostname
        device_id = "xyz"
        keys = {"alg1:k1": "key1"}

        res = yield self.handler.upload_keys_for_user(
            local_user, device_id, {"one_time_keys": keys}
        )
        self.assertDictEqual(res, {"one_time_key_counts": {"alg1": 1}})

        res2 = yield self.handler.claim_one_time_keys(
            {"one_time_keys": {local_user: {device_id: "alg1"}}}, timeout=None
        )
        self.assertEqual(
            res2,
            {
                "failures": {},
                "one_time_keys": {local_user: {device_id: {"alg1:k1": "key1"}}},
            },
        )

    @defer.inlineCallbacks
    def test_replace_master_key(self):
        """uploading a new signing key should make the old signing key unavailable"""
        local_user = "@boris:" + self.hs.hostname
        keys1 = {
            "master_key": {
                # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk":
                    "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
                }
            }
        }
        yield self.handler.upload_signing_keys_for_user(local_user, keys1)

        keys2 = {
            "master_key": {
                # private key: 4TL4AjRYwDVwD3pqQzcor+ez/euOB1/q78aTJ+czDNs
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:Hq6gL+utB4ET+UvD5ci0kgAwsX6qP/zvf8v6OInU5iw":
                    "Hq6gL+utB4ET+UvD5ci0kgAwsX6qP/zvf8v6OInU5iw"
                }
            }
        }
        yield self.handler.upload_signing_keys_for_user(local_user, keys2)

        devices = yield self.handler.query_devices(
            {"device_keys": {local_user: []}}, 0
        )
        self.assertDictEqual(
            devices,
            {
                "failures": {},
                "device_keys": {local_user: {}},
                "master_keys": {
                    local_user: keys2["master_key"]
                },
                "self_signing_keys": {}
            },
        )

    @defer.inlineCallbacks
    def test_reupload_signatures(self):
        """re-uploading a signature should not fail"""
        local_user = "@boris:" + self.hs.hostname
        keys1 = {
            "master_key": {
                # private key: HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ":
                    "EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ",
                }
            },
            "self_signing_key": {
                # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
                "user_id": local_user,
                "usage": ["self_signing"],
                "keys": {
                    "ed25519:nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk":
                    "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
                }
            }
        }
        master_signing_key = key.decode_signing_key_base64(
            "ed25519", "EmkqvokUn8p+vQAGZitOk4PWjp7Ukp3txV2TbMPEiBQ",
            "HvQBbU+hc2Zr+JP1sE0XwBe1pfZZEYtJNPJLZJtS+F8"
        )
        sign.sign_json(keys1["self_signing_key"], local_user, master_signing_key)
        signing_key = key.decode_signing_key_base64(
            "ed25519", "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk",
            "2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0"
        )
        yield self.handler.upload_signing_keys_for_user(local_user, keys1)

        # upload two device keys, which will be signed later by the self-signing key
        device_key_1 = {
            "user_id": local_user,
            "device_id": "abc",
            "algorithms": ["m.olm.curve25519-aes-sha256", "m.megolm.v1.aes-sha"],
            "keys": {
                "ed25519:abc": "base64+ed25519+key",
                "curve25519:abc": "base64+curve25519+key"
            },
            "signatures": {
                local_user: {
                    "ed25519:abc": "base64+signature"
                }
            }
        }
        device_key_2 = {
            "user_id": local_user,
            "device_id": "def",
            "algorithms": ["m.olm.curve25519-aes-sha256", "m.megolm.v1.aes-sha"],
            "keys": {
                "ed25519:def": "base64+ed25519+key",
                "curve25519:def": "base64+curve25519+key"
            },
            "signatures": {
                local_user: {
                    "ed25519:def": "base64+signature"
                }
            }
        }

        yield self.handler.upload_keys_for_user(
            local_user, "abc", {"device_keys": device_key_1}
        )
        yield self.handler.upload_keys_for_user(
            local_user, "def", {"device_keys": device_key_2}
        )

        # sign the first device key and upload it
        del device_key_1["signatures"]
        sign.sign_json(device_key_1, local_user, signing_key)
        yield self.handler.upload_signatures_for_device_keys(
            local_user,
            {
                local_user: {
                    "abc": device_key_1
                }
            }
        )

        # sign the second device key and upload both device keys.  The server
        # should ignore the first device key since it already has a valid
        # signature for it
        del device_key_2["signatures"]
        sign.sign_json(device_key_2, local_user, signing_key)
        yield self.handler.upload_signatures_for_device_keys(
            local_user,
            {
                local_user: {
                    "abc": device_key_1,
                    "def": device_key_2
                }
            }
        )

        device_key_1["signatures"][local_user]["ed25519:abc"] = "base64+signature"
        device_key_2["signatures"][local_user]["ed25519:def"] = "base64+signature"
        devices = yield self.handler.query_devices(
            {"device_keys": {local_user: []}}, 0
        )
        del devices["device_keys"][local_user]["abc"]["unsigned"]
        del devices["device_keys"][local_user]["def"]["unsigned"]
        self.assertDictEqual(
            devices["device_keys"][local_user]["abc"],
            device_key_1
        )
        self.assertDictEqual(
            devices["device_keys"][local_user]["def"],
            device_key_2
        )

    @defer.inlineCallbacks
    def test_self_signing_key_doesnt_show_up_as_device(self):
        """signing keys should be hidden when fetching a user's devices"""
        local_user = "@boris:" + self.hs.hostname
        keys1 = {
            "master_key": {
                # private key: 2lonYOM6xYKdEsO+6KrC766xBcHnYnim1x/4LFGF8B0
                "user_id": local_user,
                "usage": ["master"],
                "keys": {
                    "ed25519:nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk":
                    "nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk"
                }
            }
        }
        yield self.handler.upload_signing_keys_for_user(local_user, keys1)

        res = None
        try:
            yield self.hs.get_device_handler().check_device_registered(
                user_id=local_user,
                device_id="nqOvzeuGWT/sRx3h7+MHoInYj3Uk2LD/unI9kDYcHwk",
                initial_device_display_name="new display name",
            )
        except errors.SynapseError as e:
            res = e.code
        self.assertEqual(res, 400)

        res = yield self.handler.query_local_devices({local_user: None})
        self.assertDictEqual(res, {local_user: {}})
