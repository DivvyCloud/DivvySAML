# DivvyCloud SAML Authorization Plugin
Plugin provides a simple implementation of the SAML protocol, in python, as a DivvyCloud plugin.

This plugin is a thin wrapper around the [python-saml](https://github.com/onelogin/python-saml)
libary created and maintained by [OneLogin](https://www.onelogin.com/) for doing SAML2 authentication.

This libray works by configuring the json files used by `python-saml`, two example config files are 
included in this repository. For full reference to config options please reference the `python-saml`
project README.

## Dependencies:
DivvyCloud v17.01 or greater

Python SAML library maintained by OneLogin.com

https://github.com/onelogin/python-saml

## Installation:
### Ubuntu/Debian
```
sudo apt-get install libxml2-dev libxmlsec1-dev swig
sudo pip install python-saml
```
### CentOS
```
sudo yum -y install libxml2 libxml2-devel pyOpenSSL xmlsec1-openssl-devel xmlsec1-openssl libtool libtool-ltdl-devel swig patch python-devel python-pip
wget https://gist.githubusercontent.com/jborg/d50975951580c53322a0/raw/f260b788e4fa0bb6369523dba6954a3f74e9975a/gistfile1.diff
sudo patch -p1 /usr/bin/xmlsec1-config < gistfile1.diff
sudo easy_install pip
sudo pip install dm.xmlsec.binding
sudo env SWIG_FEATURES="-cpperraswarn -includeall -D__`uname -m`__ -I/usr/include/openssl"
pip install M2Crypto
sudo pip install python-saml
python -c 'from onelogin.saml2.auth import OneLogin_Saml2_Auth;print "foo"'
```
### Setup:

##### Copy plugin package into `plugins` directory
1. Copy the `saml` directory from the DivvySAML repo to your installations `plugins` directory.
2. Restart DivvyCloud `divvycloud --stop` then `divvycloud --start`.
3. To verify, login and select 'Plugins' link to go to Plugin Manager. Verify saml plugin is loaded on the interface server process.
4. Configuration files are read at run time so no restarts are required between config changes.

##### How to use local authentication during setup and while SAML in enabled
This plugin works by redirecting user into an authentication workflow. During setup
a button/link is provided on the SAML page to go to `(http://example.com)/local-auth`
which will allow you to login with the traditional username and password.

#### Config Files

This plugin is configured using two JSON files in the nested saml`DivvySAML/saml/config/settings.json` and
`DivvySAML/saml/config/advanced_settings.json`. These example configurations are the minimal set of properties
needed to run the plugin. However, detailed below are the full options for configuration.

##### Modify settings.json with the appropriate Identify Provider assertions and urls:
1. IDP Metadata Id url
2. IDP Sign Sign on Service URL
3. IDP Sign Logout Service URL. This is required but the plugin does not perform logout operations.
4. IDP x509 Public key. Value must have "\n" newline characters because JSON cannot have multiline strings.

##### Provide IDP with these settings:
1. SAML Audience = (http://example.com)/plugin/saml/metadata
2. SAML Recipient = (http://example.com)/plugin/saml/?acs
3. SAML Single Logout url = (http://example.com)/plugin/saml/?sls
4. Note: If using localhost:8000 or 127.0.0.1:8000, the domain set with the IDP must be the same as the
domain used in the browser. You cannot authenticate from localhost:8000 with IDP settings 127.0.0.1:8000.

```
{
    // If strict is True, then the Python Toolkit will reject unsigned
    // or unencrypted messages if it expects them to be signed or encrypted.
    // Also it will reject the messages if the SAML standard is not strictly
    // followed. Destination, NameId, Conditions ... are validated too.
    "strict": true,

    // Enable debug mode (outputs errors).
    "debug": true,

    // Service Provider Data that we are deploying.
    "sp": {
        // Identifier of the SP entity  (must be a URI)
        "entityId": "https://<sp_domain>/metadata",
        // Specifies info about where and how the <AuthnResponse> message MUST be
        // returned to the requester, in this case our SP.
        "assertionConsumerService": {
            // URL Location where the <Response> from the IdP will be returned
            "url": "https://<sp_domain>/?acs",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports this endpoint for the
            // HTTP-POST binding only.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        },
        // If you need to specify requested attributes, set a
        // attributeConsumingService. nameFormat, attributeValue and
        // friendlyName can be omitted
        "attributeConsumingService": {
                "serviceName": "SP test",
                "serviceDescription": "Test Service",
                "requestedAttributes": [
                    {
                        "name": "",
                        "isRequired": false,
                        "nameFormat": "",
                        "friendlyName": "",
                        "attributeValue": []
                    }
                ]
        },
        // Specifies info about where and how the <Logout Response> message MUST be
        // returned to the requester, in this case our SP.
        "singleLogoutService": {
            // URL Location where the <Response> from the IdP will be returned
            "url": "https://<sp_domain>/?sls",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports the HTTP-Redirect binding
            // only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        // Specifies the constraints on the name identifier to be used to
        // represent the requested subject.
        // Take a look on src/onelogin/saml2/constants.py to see the NameIdFormat that are supported.
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
        // Usually x509cert and privateKey of the SP are provided by files placed at
        // the certs folder. But we can also provide them with the following parameters
        "x509cert": "",
        "privateKey": ""

        /*
         * Key rollover
         * If you plan to update the SP x509cert and privateKey
         * you can define here the new x509cert and it will be 
         * published on the SP metadata so Identity Providers can
         * read them and get ready for rollover.
         */
        // 'x509certNew': '',
    },

    // Identity Provider Data that we want connected with our SP.
    "idp": {
        // Identifier of the IdP entity  (must be a URI)
        "entityId": "https://app.onelogin.com/saml/metadata/<onelogin_connector_id>",
        // SSO endpoint info of the IdP. (Authentication Request protocol)
        "singleSignOnService": {
            // URL Target of the IdP where the Authentication Request Message
            // will be sent.
            "url": "https://app.onelogin.com/trust/saml2/http-post/sso/<onelogin_connector_id>",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports the HTTP-Redirect binding
            // only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        // SLO endpoint info of the IdP.
        "singleLogoutService": {
            // URL Location of the IdP where SLO Request will be sent.
            "url": "https://app.onelogin.com/trust/saml2/http-redirect/slo/<onelogin_connector_id>",
            // SAML protocol binding to be used when returning the <Response>
            // message. OneLogin Toolkit supports the HTTP-Redirect binding
            // only for this endpoint.
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        },
        // Public x509 certificate of the IdP
        "x509cert": "<onelogin_connector_cert>"
        /*
         *  Instead of using the whole x509cert you can use a fingerprint in order to
         *  validate a SAMLResponse, but you will need it to validate LogoutRequest and LogoutResponse using the HTTP-Redirect binding.
         *
         *  (openssl x509 -noout -fingerprint -in "idp.crt" to generate it,
         *  or add for example the -sha256 , -sha384 or -sha512 parameter)
         *
         *  If a fingerprint is provided, then the certFingerprintAlgorithm is required in order to
         *  let the toolkit know which algorithm was used. Possible values: sha1, sha256, sha384 or sha512
         *  'sha1' is the default value.
         *
         *  Notice that if you want to validate any SAML Message sent by the HTTP-Redirect binding, you
         *  will need to provide the whole x509cert.
         */
        // 'certFingerprint': '',
        // 'certFingerprintAlgorithm': 'sha1',

        /* In some scenarios the IdP uses different certificates for
         * signing/encryption, or is under key rollover phase and
         * more than one certificate is published on IdP metadata.
         * In order to handle that the toolkit offers that parameter.
         * (when used, 'x509cert' and 'certFingerprint' values are
         * ignored).
         */
        // 'x509certMulti': {
        //      'signing': [
        //          '<cert1-string>'
        //      ],
        //      'encryption': [
        //          '<cert2-string>'
        //      ]
        // }
    }
}
```

In addition to the required settings data (idp, sp), extra settings can be defined in advanced_settings.json:

```
{
    // Security settings
    "security": {

        /** signatures and encryptions offered **/

        // Indicates that the nameID of the <samlp:logoutRequest> sent by this SP
        // will be encrypted.
        "nameIdEncrypted": false,

        // Indicates whether the <samlp:AuthnRequest> messages sent by this SP
        // will be signed.  [Metadata of the SP will offer this info]
        "authnRequestsSigned": false,

        // Indicates whether the <samlp:logoutRequest> messages sent by this SP
        // will be signed.
        "logoutRequestSigned": false,

        // Indicates whether the <samlp:logoutResponse> messages sent by this SP
        // will be signed.
        "logoutResponseSigned": false,

        /* Sign the Metadata
         false || true (use sp certs) || {
                                            "keyFileName": "metadata.key",
                                            "certFileName": "metadata.crt"
                                         }
        */
        "signMetadata": false,

        /** signatures and encryptions required **/

        // Indicates a requirement for the <samlp:Response>, <samlp:LogoutRequest>
        // and <samlp:LogoutResponse> elements received by this SP to be signed.
        "wantMessagesSigned": false,

        // Indicates a requirement for the <saml:Assertion> elements received by
        // this SP to be signed. [Metadata of the SP will offer this info]
        "wantAssertionsSigned": false,

        // Indicates a requirement for the <saml:Assertion>
        // elements received by this SP to be encrypted.
        "wantAssertionsEncrypted": false,

        // Indicates a requirement for the NameID element on the SAMLResponse
        // received by this SP to be present.
        "wantNameId": true,

        // Indicates a requirement for the NameID received by
        // this SP to be encrypted.
        "wantNameIdEncrypted": false,

        // Indicates a requirement for the AttributeStatement element
        "wantAttributeStatement": true,

        // Authentication context.
        // Set to false and no AuthContext will be sent in the AuthNRequest,
        // Set true or don't present this parameter and you will get an AuthContext 'exact' 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        // Set an array with the possible auth context values: array ('urn:oasis:names:tc:SAML:2.0:ac:classes:Password', 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509'),
        "requestedAuthnContext": true,
        // Allows the authn comparison parameter to be set, defaults to 'exact' if the setting is not present.
        "requestedAuthnContextComparison": "exact",

        // In some environment you will need to set how long the published metadata of the Service Provider gonna be valid.
        // is possible to not set the 2 following parameters (or set to null) and default values will be set (2 days, 1 week)
        // Provide the desired Timestamp, for example 2015-06-26T20:00:00Z
        "metadataValidUntil": null,
        // Provide the desired duration, for example PT518400S (6 days)
        "metadataCacheDuration": null,

        // Algorithm that the toolkit will use on signing process. Options:
        //    'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
        //    'http://www.w3.org/2000/09/xmldsig#dsa-sha1'
        //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
        //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384'
        //    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'
        "signatureAlgorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1",

        // Algorithm that the toolkit will use on digest process. Options:
        //    'http://www.w3.org/2000/09/xmldsig#sha1'
        //    'http://www.w3.org/2001/04/xmlenc#sha256'
        //    'http://www.w3.org/2001/04/xmldsig-more#sha384'
        //    'http://www.w3.org/2001/04/xmlenc#sha512'
        "digestAlgorithm": "http://www.w3.org/2000/09/xmldsig#sha1"
    },

    // Contact information template, it is recommended to supply
    // technical and support contacts.
    "contactPerson": {
        "technical": {
            "givenName": "technical_name",
            "emailAddress": "technical@example.com"
        },
        "support": {
            "givenName": "support_name",
            "emailAddress": "support@example.com"
        }
    },

    // Organization information template, the info in en_US lang is
    // recommended, add more if required.
    "organization": {
        "en-US": {
            "name": "sp_test",
            "displayname": "SP test",
            "url": "http://sp.example.com"
        }
    }
}

```


### Use:
1. Once setup is complete, when you logout you will be directed to the SAML auth page.
2. Click the Authenticate button to initiate.
3. NameID provided by the IDP is expected to be the username for an existing Divvy user account.
