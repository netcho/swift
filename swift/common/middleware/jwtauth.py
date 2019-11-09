from jose import jwt
import json
import six
from swift.common.swob import wsgi_to_str
from swift.common.swob import HTTPBadRequest, HTTPForbidden, HTTPNotFound, \
    HTTPUnauthorized
from swift.common.request_helpers import get_sys_meta_prefix
from swift.proxy.controllers.base import get_account_info
from swift.common.middleware.acl import (
    clean_acl, parse_acl, referrer_allowed, acls_from_account_info)
from swift.common.utils import get_logger, register_swift_info


def extract_acl_and_report_errors(req):
    """
    Return a user-readable string indicating the errors in the input ACL,
    or None if there are no errors.
    """
    acl_header = 'x-account-access-control'
    acl_data = wsgi_to_str(req.headers.get(acl_header))
    result = parse_acl(version=2, data=acl_data)
    if result is None:
        return 'Syntax error in input (%r)' % acl_data

    tempauth_acl_keys = 'admin read-write read-only'.split()
    for key in result:
        # While it is possible to construct auth systems that collaborate
        # on ACLs, TempAuth is not such an auth system.  At this point,
        # it thinks it is authoritative.
        if key not in tempauth_acl_keys:
            return "Key %s not recognized" % json.dumps(key)

    for key in tempauth_acl_keys:
        if key not in result:
            continue
        if not isinstance(result[key], list):
            return "Value for key %s must be a list" % json.dumps(key)
        for grantee in result[key]:
            if not isinstance(grantee, six.string_types):
                return "Elements of %s list must be strings" % json.dumps(
                    key)

    # Everything looks fine, no errors found
    internal_hdr = get_sys_meta_prefix('account') + 'core-access-control'
    req.headers[internal_hdr] = req.headers.pop(acl_header)
    return None


class JWTAuth(object):
    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='jwt-auth')

    def __call__(self, env, start_response):
        token = env.get('HTTP_X_AUTH_TOKEN')
        if token:
            try:
                with open(self.conf['public_key'], 'rb') as pubkeyfile:
                    pubkey = pubkeyfile.read()
                    pubkeyfile.close()
                    payload = jwt.decode(token, pubkey, algorithms='RS256')
                    env['REMOTE_USER'] = payload['email'] + ', ' + payload['swift_groups']
                    env['swift.authorize'] = self.authorize
                    env['swift.clean_acl'] = clean_acl

                    if '.reseller_admin' in payload['swift_groups']:
                        env['reseller_request'] = True
            except jwt.JWTError:
                env['swift.authorize'] = self.denied_response
        else:
            # Not my token, not my account, I can't authorize this request,
            # deny all is a good idea if not already set...
            if 'swift.authorize' not in env:
                env['swift.authorize'] = self.denied_response

        return self.app(env, start_response)

    def account_acls(self, req):
        """
        Return a dict of ACL data from the account server via get_account_info.

        Auth systems may define their own format, serialization, structure,
        and capabilities implemented in the ACL headers and persisted in the
        sysmeta data.  However, auth systems are strongly encouraged to be
        interoperable with Tempauth.

        Account ACLs are set and retrieved via the header
           X-Account-Access-Control

        For header format and syntax, see:
         * :func:`swift.common.middleware.acl.parse_acl()`
         * :func:`swift.common.middleware.acl.format_acl()`
        """
        info = get_account_info(req.environ, self.app, swift_source='TA')
        try:
            acls = acls_from_account_info(info)
        except ValueError as e1:
            self.logger.warning("Invalid ACL stored in metadata: %r" % e1)
            return None
        except NotImplementedError as e2:
            self.logger.warning(
                "ACL version exceeds middleware version: %r"
                % e2)
            return None
        return acls

    def authorize(self, req):
        """
        Returns None if the request is authorized to continue or a standard
        WSGI response callable if not.
        """
        try:
            _junk, account, container, obj = req.split_path(1, 4, True)
        except ValueError:
            self.logger.increment('errors')
            return HTTPNotFound(request=req)

        # At this point, TempAuth is convinced that it is authoritative.
        # If you are sending an ACL header, it must be syntactically valid
        # according to TempAuth's rules for ACL syntax.
        acl_data = req.headers.get('x-account-access-control')
        if acl_data is not None:
            error = extract_acl_and_report_errors(req)
            if error:
                msg = 'X-Account-Access-Control invalid: %s\n\nInput: %s\n' % (
                    error, acl_data)
                headers = [('Content-Type', 'text/plain; charset=UTF-8')]
                return HTTPBadRequest(request=req, headers=headers, body=msg)

        user_groups = (req.remote_user or '').split(',')
        account_user = user_groups[1] if len(user_groups) > 1 else None

        if '.reseller_admin' in user_groups:
            req.environ['swift_owner'] = True
            self.logger.debug("User %s has reseller admin authorizing."
                              % account_user)
            return None

        if wsgi_to_str(account) in user_groups and \
                (req.method not in ('DELETE', 'PUT') or container):
            # The user is admin for the account and is not trying to do an
            # account DELETE or PUT
                req.environ['swift_owner'] = True
                self.logger.debug("User %s has admin authorizing."
                                  % account_user)
                return None

        if (req.environ.get('swift_sync_key')
                and (req.environ['swift_sync_key'] ==
                     req.headers.get('x-container-sync-key', None))
                and 'x-timestamp' in req.headers):
            self.logger.debug("Allow request with container sync-key: %s."
                              % req.environ['swift_sync_key'])
            return None

        if req.method == 'OPTIONS':
            # allow OPTIONS requests to proceed as normal
            self.logger.debug("Allow OPTIONS request.")
            return None

        referrers, groups = parse_acl(getattr(req, 'acl', None))

        if referrer_allowed(req.referer, referrers):
            if obj or '.rlistings' in groups:
                self.logger.debug("Allow authorizing %s via referer ACL."
                                  % req.referer)
                return None

        for user_group in user_groups:
            if user_group in groups:
                self.logger.debug("User %s allowed in ACL: %s authorizing."
                                  % (account_user, user_group))
                return None

        # Check for access via X-Account-Access-Control
        acct_acls = self.account_acls(req)
        if acct_acls:
            # At least one account ACL is set in this account's sysmeta data,
            # so we should see whether this user is authorized by the ACLs.
            user_group_set = set(user_groups)
            if user_group_set.intersection(acct_acls['admin']):
                req.environ['swift_owner'] = True
                self.logger.debug('User %s allowed by X-Account-Access-Control'
                                  ' (admin)' % account_user)
                return None
            if (user_group_set.intersection(acct_acls['read-write']) and
                    (container or req.method in ('GET', 'HEAD'))):
                # The RW ACL allows all operations to containers/objects, but
                # only GET/HEAD to accounts (and OPTIONS, above)
                self.logger.debug('User %s allowed by X-Account-Access-Control'
                                  ' (read-write)' % account_user)
                return None
            if (user_group_set.intersection(acct_acls['read-only']) and
                    req.method in ('GET', 'HEAD')):
                self.logger.debug('User %s allowed by X-Account-Access-Control'
                                  ' (read-only)' % account_user)
                return None

        return self.denied_response(req)

    def denied_response(self, req):
        """
        Returns a standard WSGI response callable with the status of 403 or 401
        depending on whether the REMOTE_USER is set or not.
        """
        if req.remote_user:
            self.logger.increment('forbidden')
            return HTTPForbidden(request=req)
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized(request=req)


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)
    register_swift_info('jwtauth', account_acls=True)

    def auth_filter(app):
        return JWTAuth(app, conf)

    return auth_filter
