# DivvyCloud SAML Authorization Plugin
Plugin provides a simple implementation of the SAML protocol, in python, as a DivvyCloud plugin. When attempting to access a

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
##### How to use local authentication during setup and while SAML in enabled
This plugin works by redirecting user into an authentication workflow. During setup
a button/link is provided on the SAML page to go to `(http://example.com)/local-auth`
which will allow you to login and configure the SAML plugin. Once configured the link will 
not appear and to authenticate locally the user must manually enter the url `(http://example.com)/local-auth`.

##### Copy plugin package into divvy/dev/run/plugins directory
1. Login to DivvyCloud console application
2. Select 'Plugins' link to go to Plugin Manager
3. Under 'Managed' section select 'SAML Authentication'

##### Modify settings.json with the appropriate Identify Provider assertions and urls:
1. IDP Metadata Id url
2. IDP Sign Sign on Service URL
3. IDP Sign Logout Service URL. This is required but the plugin does not perform logout operations.
4. IDP x509 Public key. Simply copy and paste, form will add "\n" newline characters upon save.

##### Provide IDP with these settings:
1. SAML Audience = (http://example.com)/plugin/saml/metadata
2. SAML Recipient = (http://example.com)/plugin/saml/?acs
3. SAML Single Logout url = (http://example.com)/plugin/saml/?sls
4. Note: If using localhost:8000 or 127.0.0.1:8000, the domain set with the IDP must be the same as the
domain used in the browser. You cannot authenticate from localhost:8000 with IDP settings 127.0.0.1:8000.

### Use:
1. Once setup is complete, when you logout you will be directed to the SAML auth page.
2. Click the Authenticate button to initiate.
3. NameID provided by the IDP is expected to be an email address for an existing Divvy user account.
