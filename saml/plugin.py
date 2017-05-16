import os
import logging

from flask import Blueprint, request, render_template, redirect, make_response
from sqlalchemy.orm.exc import NoResultFound
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from DivvyDb.DivvyCloudGatewayORM import DivvyCloudGatewayORM
from DivvyDb.DivvyDb import SharedSessionScope
from DivvyPermissions.SessionPermissions import SessionPermissions
from DivvyPlugins.hookpoints import hookpoint
from DivvyPlugins.plugin_helpers import register_api_blueprint, unregister_api_blueprints
from DivvyPlugins.plugin_metadata import PluginMetadata
from DivvyResource import ResourceIds
from DivvySession.DivvySession import create_session


logger = logging.getLogger("DivvyInterfaceServer")
saml_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'saml')
blueprint = Blueprint('saml', __name__, static_folder='html', template_folder='html')


class metadata(PluginMetadata):
    version = '2.0'
    last_updated_date = '2017-02-07'
    author = 'Divvy Cloud Corp.'
    nickname = 'SAML Authentication'
    default_language_description = 'Redirects Authentication attempts to a SAML Identification Provider'
    support_email = 'support@divvycloud.com'
    support_url = 'http://support.divvycloud.com'
    main_url = 'http://www.divvycloud.com'
    type = 'authentication'
    managed = True


def request_protocol(req):
    """ Only case we support for SSL is LB proxy. """
    return req.headers.get('X-Forwarded-Proto', 'http')


def redirect_url(proto, host, location=''):
    return '{0}://{1}/{2}'.format(proto, host, location)


def prepare_flask_request(req):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    # url_data = urlparse(request.url)
    # 'server_port': url_data.port,
    logger.info('SAML: Prepare Request: Protocol: %s, Host: %s', request_protocol(req), req.host)
    logger.error("Redirect URL")
    logger.error(req.form.copy())

    return {
        'https': 'on' if request_protocol(req) == 'https' or req.scheme == 'https' else 'off',
        'http_host': req.host + '/plugin/saml',
        'script_name': req.path,
        'get_data': req.args.copy(),
        'post_data': req.form.copy()
    }


def init_saml_auth(req):
    saml_req = prepare_flask_request(req)
    return OneLogin_Saml2_Auth(saml_req, custom_base_path=saml_path)


@hookpoint('divvycloud.auth.attempt')
def authenticate(req, response):
    try:
        auth = init_saml_auth(request)
        response.location = auth.login()
    except Exception:
        logger.exception("Error Initializing SAML SSO Request.")
        response.location = redirect_url(
            request_protocol(req), request.host, location='local-auth'
        )


@blueprint.route('/', methods=['POST'])
@SharedSessionScope(DivvyCloudGatewayORM)
def index():
    db = DivvyCloudGatewayORM()
    auth = init_saml_auth(request)
    errors = []
    not_auth_warn = False
    configured = True

    logger.info("Processing SAML 'acs' Response")
    auth.process_response()
    errors = auth.get_errors()
    not_auth_warn = not auth.is_authenticated()

    if errors:
        logger.error("SAML Response Errors: %s", errors)

    else:
        username = auth.get_nameid()
        logger.debug(
            "Attempting Authentication for NameID: %s", auth.get_nameid
        )

        try:
            session_data = db.LoginUser(username)
            logger.info("SAML: Found user with NameID")

            user_resource_id = ResourceIds.DivvyUser(user_id=session_data['user'].user_id)
            session_permissions = SessionPermissions.load_for_user(user_resource_id=user_resource_id)
            divvysession = create_session(session_permissions=session_permissions, **session_data)

            # After Success redirect to Console App
            response = redirect(
                auth.redirect_to(
                    redirect_url(
                        request_protocol(request),
                        request.host
                    )
                )
            )
            response.set_cookie('session_id', divvysession.session_id)

            return response

        except NoResultFound:
            logger.error("SAML: No User found with NameID. Create new user with SSO id as username.")
            errors.append("SAML: No User found with NameID. Create new user with SSO id as username.")

    return render_template(
        'index.html',
        errors=errors,
        configured=configured,
        domain=request.url_root,
        not_auth_warn=not_auth_warn)


@blueprint.route('/metadata/', methods=['GET'])
def saml_metadata():
    auth = init_saml_auth(request)
    settings = auth.get_settings()
    sp_metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(sp_metadata)

    if len(errors) == 0:
        resp = make_response(sp_metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(errors.join(', '), 500)
    return resp


def load():
    register_api_blueprint(blueprint)


def unload():
    unregister_api_blueprints()
