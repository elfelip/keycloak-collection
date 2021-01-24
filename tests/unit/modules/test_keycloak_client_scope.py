from plugins.module_utils.keycloak import isDictEquals, get_token
from plugins.modules import keycloak_client_scope
from tests.unit.module_utils.utils import AnsibleExitJson, AnsibleFailJson, ModuleTestCase, set_module_args
import requests
import json

class KeycloakClientScopeTestCase(ModuleTestCase):
    testClientScope = {
      "name": "newclientscope",
      "description": "New Client Scope",
      "protocol": "openid-connect",
      "attributes": {
        "include.in.token.scope": "true",
        "display.on.consent.screen": "true"
      },
      "protocolMappers": [
        {
          "name": "new-mapper-audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "consentRequired": False,
          "config": {
            "included.client.audience": "test",
            "id.token.claim": "true",
            "access.token.claim": "true"
          }
        }
      ]
    }

    testClientScopes = [
        {
            "name": "existingclientscope",
            "description": "Already existing Client Scope",
            "protocol": "openid-connect",
            "attributes": {
                "include.in.token.scope": "true",
                "display.on.consent.screen": "true"
            },
            "protocolMappers": [
                {
                    "name": "new-mapper-audience",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-mapper",
                    "consentRequired": False,
                    "config": {
                        "included.client.audience": "test",
                        "id.token.claim": "true",
                        "access.token.claim": "true"
                    }
                }
            ]
        }
    ]
    excudes = ["auth_keycloak_url","auth_username","auth_password","state","force","realm","composites","_ansible_keep_remote_files","_ansible_remote_tmp"]
    kc = None
    baseurl = "http://localhost:18081"
    def setUp(self):
        super(KeycloakClientScopeTestCase, self).setUp()
        username = "admin"
        password = "admin"
        self.clientScopesUrl = "{baseurl}/auth/admin/realms/master/client-scopes"
        self.clientScopeUrl = self.clientScopesUrl + "/{id}"
        self.clientScopeProtocolMappersBaseUrl = self.clientScopeUrl + "/protocol-mappers"
        self.clientScopeProtocolMapperAddModelsBaseUrl = self.clientScopeProtocolMappersBaseUrl + "/add-models"
        # Create Client scope
        self.headers = get_token(
            base_url=self.baseurl+'/auth',
            auth_realm="master",
            client_id="admin-cli",
            auth_username=username,
            auth_password=password,
            validate_certs=False,
            client_secret=None)
        
        for testClientScope in self.testClientScopes:
            getResponse = requests.get(
                self.clientScopesUrl.format(baseurl=self.baseurl),
                headers=self.headers)
            scopes = getResponse.json()
            scopeFound = False
            for scope in scopes:
                if scope['name'] == testClientScope['name']:
                    scopeFound = True
                    break
            if not scopeFound:
                data=json.dumps(testClientScope)
                postResponse = requests.post(
                    self.clientScopesUrl.format(baseurl=self.baseurl), 
                        headers=self.headers,
                        data=data)
                print("Status code: {0}".format(str(postResponse.status_code)))
    def tearDown(self):
        for testClientScope in self.testClientScopes:
            getResponse = requests.get(
                self.clientScopesUrl.format(baseurl=self.baseurl),
                headers=self.headers)
            scopes = getResponse.json()
            scopeFound = False
            for scope in scopes:
                if scope['name'] == testClientScope['name']:
                    scopeFound = True
                    break
            if scopeFound:
                id = scope['id']
                deleteResponse = requests.delete(
                    self.clientScopeUrl.format(baseurl=self.baseurl, id=id), 
                        headers=self.headers)
                print("Status code: {0}".format(str(deleteResponse.status_code)))


    def TestCreateNewClientScope(self):
        print("Test")
