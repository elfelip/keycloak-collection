#!/usr/bin/python
# -*- coding: utf-8 -*-

from unittest import TestCase, mock
from ansible_collections.elfelip.keycloak.plugins.module_utils.keycloak import get_token, get_service_account_token, KeycloakAPI, isDictEquals, remove_arguments_with_value_none
from mock_keycloak_server import mocked_open_url, mock_json_load

import jwt


class KeycloakTestCase(TestCase):
    
    keycloak_url = "https://keycloak.server.url/auth"
    keycloak_auth_realm = "master"
    keycloak_auth_user = "monusername"
    keycloak_auth_password = "monmotdepasse"
    keycloak_auth_client_id = "monclientid"
    keycloak_auth_client_secret = "monclientsecret"
    jwt_secret = 'secret'
    jwt_algo = 'HS256'
    validate_certs = False
    
    @mock.patch('inspqcommun.identity.keycloak.open_url', side_effect=mocked_open_url)
    @mock.patch('inspqcommun.identity.keycloak.json.load', side_effect=mock_json_load)
    def testObtenirUnAccessTokenValide(self, mocked_open_url, mock_json_load):
        authorization_header = get_token(
            base_url=self.keycloak_url,
            auth_realm=self.keycloak_auth_realm,
            client_id=self.keycloak_auth_client_id,
            auth_username=self.keycloak_auth_user,
            auth_password=self.keycloak_auth_password,
            client_secret=self.keycloak_auth_client_secret,
            validate_certs=self.validate_certs)
        access_token = authorization_header['Authorization'].split(' ')[1]
        decoded_access_token = jwt.decode(access_token, self.jwt_secret, algorithms=[self.jwt_algo], verify=False)
        self.assertEqual(decoded_access_token["preferred_username"], self.keycloak_auth_user, "L'utilisateur authentifié n'est pas le bon: {}".format(decoded_access_token["preferred_username"]))
        
    @mock.patch('inspqcommun.identity.keycloak.open_url', side_effect=mocked_open_url)
    @mock.patch('inspqcommun.identity.keycloak.json.load', side_effect=mock_json_load)
    def testObtenirUnAccessTokenValideAvecUnComteDeService(self, mocked_open_url, mock_json_load):
        authorization_header = get_service_account_token(
            base_url=self.keycloak_url,
            auth_realm=self.keycloak_auth_realm,
            client_id=self.keycloak_auth_client_id,
            client_secret=self.keycloak_auth_client_secret,
            validate_certs=self.validate_certs)
        access_token = authorization_header['Authorization'].split(' ')[1]
        decoded_access_token = jwt.decode(access_token, self.jwt_secret, algorithms=[self.jwt_algo], verify=False)
        self.assertEqual(decoded_access_token["preferred_username"], self.keycloak_auth_user, "L'utilisateur authentifié n'est pas le bon: {}".format(decoded_access_token["preferred_username"]))

    @mock.patch('inspqcommun.identity.keycloak.open_url', side_effect=mocked_open_url)
    @mock.patch('inspqcommun.identity.keycloak.json.load', side_effect=mock_json_load)
    def testCreerUnObjetKeycloakAvecToken(self, mocked_open_url, mock_json_load):
        kc = KeycloakAPI(auth_keycloak_url=self.keycloak_url,
                 auth_client_id=self.keycloak_auth_client_id,
                 auth_username=self.keycloak_auth_user,
                 auth_password=self.keycloak_auth_password,
                 auth_realm=self.keycloak_auth_realm,
                 auth_client_secret=self.keycloak_auth_client_secret,
                 validate_certs=self.validate_certs)
        access_token = kc.restheaders['Authorization'].split(' ')[1]
        decoded_access_token = jwt.decode(access_token, self.jwt_secret, algorithms=[self.jwt_algo], verify=False)
        self.assertEqual(decoded_access_token["preferred_username"], self.keycloak_auth_user, "L'utilisateur authentifié n'est pas le bon: {}".format(decoded_access_token["preferred_username"]))
        
class KeycloakIsDictEqualsTestCase(TestCase):
    dict1 = dict(
        test1 = 'test1',
        test2 = dict(
            test1='test1',
            test2='test2'
            ),
        test3 = ['test1',dict(test='test1',test2='test2')]         
        )
    dict2 = dict(
        test1 = 'test1',
        test2 = dict(
            test1='test1',
            test2='test2',
            test3='test3'
            ),
        test3 = ['test1',dict(test='test1',test2='test2'),'test3'],
        test4 = 'test4'         
        )
    dict3 = dict(
        test1 = 'test1',
        test2 = dict(
            test1='test1',
            test2='test23',
            test3='test3'
            ),
        test3 = ['test1',dict(test='test1',test2='test23'),'test3'],
        test4 = 'test4'         
        )

    dict5 = dict(
        test1 = 'test1',
        test2 = dict(
            test1=True,
            test2='test23',
            test3='test3'
            ),
        test3 = ['test1',dict(test='test1',test2='test23'),'test3'],
        test4 = 'test4'         
        )

    dict6 = dict(
        test1 = 'test1',
        test2 = dict(
            test1='true',
            test2='test23',
            test3='test3'
            ),
        test3 = ['test1',dict(test='test1',test2='test23'),'test3'],
        test4 = 'test4'         
        )
    dict7 = [{'roles': ['view-clients', 'view-identity-providers', 'view-users', 'query-realms', 'manage-users'], 'clientid': 'master-realm'}, {'roles': ['manage-account', 'view-profile', 'manage-account-links'], 'clientid': 'account'}]
    dict8 = [{'roles': ['view-clients', 'query-realms', 'view-users'], 'clientid': 'master-realm'}, {'roles': ['manage-account-links', 'view-profile', 'manage-account'], 'clientid': 'account'}]

    def test_trivial(self):
        self.assertTrue(isDictEquals(self.dict1,self.dict1))

    def test_equals_with_dict2_bigger_than_dict1(self):
        self.assertTrue(isDictEquals(self.dict1,self.dict2))

    def test_not_equals_with_dict2_bigger_than_dict1(self):
        self.assertFalse(isDictEquals(self.dict2,self.dict1))

    def test_not_equals_with_dict1_different_than_dict3(self):
        self.assertFalse(isDictEquals(self.dict1,self.dict3))

    def test_equals_with_dict5_contain_bool_and_dict6_contain_true_string(self):
        self.assertFalse(isDictEquals(self.dict5,self.dict6))
        self.assertFalse(isDictEquals(self.dict6,self.dict5))

    def test_not_equals_dict7_dict8_compare_dict7_with_list_bigger_than_dict8_but_reverse_equals(self):
        self.assertFalse(isDictEquals(self.dict7,self.dict8))
        self.assertTrue(isDictEquals(self.dict8,self.dict7))
        
class KeycloakRemoveNoneValuesFromDictTest(TestCase):
    test1 = {
        "key1": "value1",
        "key2": None
        }
    expected1 = {
        "key1": "value1"
    }
    test2 = {
        "key1": "value1",
        "list1": [{
            "list1key1": None,
            "list1key2": "list1value2"
            }
        ]
    }
    expected2 = {
        "key1": "value1",
        "list1": [{
            "list1key2": "list1value2"
            }
        ]
    }
    test3 = {
        "key1": "value1",
        "list1": [{
            "list1key1": None,
            "list1key2": "list1value2",
            "list1list1": [{
                "list1list1key1": "list1list1value1",
                "list1list1key2": None
                }]
            },
            "list1value1",
            None
        ],
        "dict1": {
            "dict1key1": "dict1value1",
            "dict1key2": None,
            "dict1dict1": [{
                "dict1dict1key1": None,
                "dict1dict1key2": "dict1dict1Value2"
            }]
        }
    }
    expected3 = {
        "key1": "value1",
        "list1": [{
            "list1key2": "list1value2",
            "list1list1": [{
                "list1list1key1": "list1list1value1"
                }]
            },
            "list1value1",
        ],
        "dict1": {
            "dict1key1": "dict1value1",
            "dict1dict1": [{
                "dict1dict1key2": "dict1dict1Value2"
            }]
        }
    }
    def testSimpleDictWithOneNoneValue(self):
        result1 = remove_arguments_with_value_none(self.test1)
        self.assertDictEqual(result1, self.expected1, str(result1))

    def testDictWithListContainingOneNoneValue(self):
        result2 = remove_arguments_with_value_none(self.test2)
        self.assertDictEqual(result2, self.expected2, str(result2))

    def testDictWithListAndDictThreeLevel(self):
        result3 = remove_arguments_with_value_none(self.test3)
        self.assertDictEqual(result3, self.expected3, str(result3))
    
        