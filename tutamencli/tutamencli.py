#!/usr/bin/env python3


### Imports ###

import sys
import os
import urllib.parse

import click

from pytutamen import config
from pytutamen import utilities
from pytutamen import accesscontrol
from pytutamen import storage


### Constants ###

_APP_NAME = 'tutamen-cli'


### CLI Root ###

@click.group()
@click.option('--srv_ac', default=None, help="Access Control Server Config Name")
@click.option('--srv_storage', default=None, help="Storage Server Config Name")
@click.option('--account_uid', default=None, type=click.UUID)
@click.option('--client_uid', default=None, type=click.UUID)
@click.option('--conf_path', default=None, help="Tutamen Client Config Directory",
              type=click.Path(resolve_path=True))
@click.pass_context
def cli(ctx, srv_ac, srv_storage, client_uid, account_uid, conf_path):
    """COG CLI"""

    # Setup Context
    ctx.obj = {}
    ctx.obj['conf'] = config.ClientConfig(conf_path=conf_path)
    if not srv_ac:
        srv_ac = ctx.obj['conf'].defaults_get_ac_server()
    ctx.obj['srv_ac'] = srv_ac
    if not srv_storage:
        srv_storage = ctx.obj['conf'].defaults_get_storage_server()
    ctx.obj['srv_storage'] = srv_storage
    if not account_uid:
        account_uid = ctx.obj['conf'].defaults_get_account_uid()
    ctx.obj['account_uid'] = account_uid
    if not client_uid:
        client_uid = ctx.obj['conf'].defaults_get_client_uid()
    ctx.obj['client_uid'] = client_uid


### Utility Commands ###

@cli.group(name='util')
@click.pass_context
def util(ctx):
    pass

@util.command(name='config_ac_server')
@click.argument('name', type=click.STRING)
@click.argument('url', type=click.STRING)
@click.pass_obj
def util_config_ac_server(obj, name, url):

    utilities.config_new_ac_server(name, url, conf=obj['conf'])

@util.command(name='config_storage_server')
@click.argument('name', type=click.STRING)
@click.argument('url', type=click.STRING)
@click.pass_obj
def util_config_storage_server(obj, name, url):

    utilities.config_new_storage_server(name, url, conf=obj['conf'])

@util.command(name='bootstrap_account')
@click.option('--country', default=None, type=click.STRING)
@click.option('--state', default=None, type=click.STRING)
@click.option('--locality', default=None, type=click.STRING)
@click.option('--email', default=None, type=click.STRING)
@click.option('--account_userdata', nargs=2, type=click.STRING, multiple=True)
@click.option('--client_userdata', nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def util_bootstrap_account(obj, country, state, locality, email,
                           account_userdata, client_userdata):

    account_userdata = dict(list(account_userdata))
    client_userdata = dict(list(client_userdata))
    ret = utilities.bootstrap_new_account(ac_server_name=obj['srv_ac'],
                                          country=country, state=state, locality=locality,
                                          email=email,
                                          account_userdata=dict(account_userdata),
                                          account_uid=obj['account_uid'],
                                          client_userdata=dict(client_userdata),
                                          client_uid=obj['client_uid'],
                                          conf=obj['conf'])

    account_uid, client_uid, client_cert = ret
    click.echo("Account UUID: {}".format(str(account_uid)))
    click.echo("Client UUID: {}".format(str(client_uid)))

@util.command(name='get_tokens')
@click.argument('objtype', type=click.STRING)
@click.argument('objperm', type=click.STRING)
@click.argument('objuid', required=False, default=None, type=click.UUID)
@click.pass_obj
def util_get_tokens(obj, objtype, objperm, objuid):

    tokens, errors = utilities.get_tokens(objtype, objperm, objuid=objuid,
                                          ac_server_names=[obj['srv_ac']],
                                          conf=obj['conf'],
                                          account_uid=obj['account_uid'],
                                          client_uid=obj['client_uid'])
    if tokens:
        click.echo("Got tokens '{}'".format(tokens))
    if errors:
        click.echo("Got errors '{}'".format(errors))

@util.command(name='setup_authenticators')
@click.argument('module_name', type=click.STRING)
@click.option('--module_arg', 'module_kwargs', nargs=2, type=click.STRING, multiple=True)
@click.option('--authn_userdata', nargs=2, type=click.STRING, multiple=True)
@click.option('--authn_uid', default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--verifier', 'verifiers', nargs=1, type=click.UUID, multiple=True)
@click.pass_obj
def util_setup_authenticators(obj, module_name, module_kwargs,
                              authn_userdata, authn_uid, tokens, verifiers):

    tokens = list(tokens)
    verifiers = list(verifiers)
    module_kwargs = dict(list(module_kwargs))
    authn_userdata = dict(list(authn_userdata))
    authenticators = utilities.setup_authenticators(module_name, module_kwargs=module_kwargs,
                                                    authn_userdata=authn_userdata,
                                                    authn_uid=authn_uid,
                                                    tokens=tokens, verifiers=verifiers,
                                                    ac_server_names=[obj['srv_ac']],
                                                    conf=obj['conf'],
                                                    account_uid=obj['account_uid'],
                                                    client_uid=obj['client_uid'])
    authenticators = [str(v) for v in authenticators]
    click.echo("Setup authenticators '{}'".format(authenticators))

@util.command(name='fetch_authenticators')
@click.argument('authn_uid', type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def util_fetch_authenticators(obj, authn_uid, tokens):

    tokens = list(tokens)
    authenticators, errors = utilities.fetch_authenticators(authn_uid,
                                                            tokens=tokens,
                                                            ac_server_names=[obj['srv_ac']],
                                                            conf=obj['conf'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'])
    for srv, error in errors.items():
        click.echo("{}: {}".format(srv, errors))

    for srv, authn in authenticators.items():
        click.echo("{}: {}".format(srv, authn))

@util.command(name='setup_verifiers')
@click.option('--verifier_uid', default=None, type=click.UUID)
@click.option('--account', 'accounts', nargs=1, type=click.UUID, multiple=True)
@click.option('--authenticator', 'authenticators', default=[], nargs=1, type=click.UUID, multiple=True)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def util_setup_verifiers(obj, verifier_uid, accounts, authenticators, tokens):

    accounts = list(accounts)
    tokens = list(tokens)
    verifiers = utilities.setup_verifiers(verifier_uid=verifier_uid,
                                          accounts=accounts, authenticators=authenticators,
                                          tokens=tokens,
                                          ac_server_names=[obj['srv_ac']],
                                          conf=obj['conf'],
                                          account_uid=obj['account_uid'],
                                          client_uid=obj['client_uid'])
    verfiers = [str(v) for v in verifiers]
    click.echo("Setup verifiers '{}'".format(verifiers))

@util.command(name='fetch_verifiers')
@click.argument('verifier_uid', type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def util_fetch_verifiers(obj, verifier_uid, tokens):

    tokens = list(tokens)
    verifiers, errors = utilities.fetch_verifiers(verifier_uid,
                                                  tokens=tokens,
                                                  ac_server_names=[obj['srv_ac']],
                                                  conf=obj['conf'],
                                                  account_uid=obj['account_uid'],
                                                  client_uid=obj['client_uid'])
    for srv, error in errors.items():
        click.echo("{}: {}".format(srv, errors))

    for srv, verifier in verifiers.items():
        click.echo("{}: {}".format(srv, verifier))

@util.command(name='setup_permissions')
@click.argument('objtype', type=click.STRING)
@click.argument('objuid', required=False, default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--verifier', 'verifiers', nargs=1, type=click.UUID, multiple=True)
@click.pass_obj
def util_setup_permissions(obj, objtype, objuid, tokens, verifiers):

    tokens = list(tokens)
    verifiers = list(verifiers)
    verifiers = utilities.setup_permissions(objtype, objuid=objuid, tokens=tokens,
                                            verifiers=verifiers,
                                            ac_server_names=[obj['srv_ac']],
                                            conf=obj['conf'],
                                            account_uid=obj['account_uid'],
                                            client_uid=obj['client_uid'])
    verfiers = [str(v) for v in verifiers]
    if objuid:
        msg = "Setup permissions for '{} {}'".format(objtype, objuid)
    else:
        msg = "Setup permissions for '{}'".format(objtype)
    msg += " using verifiers '{}'".format(verifiers)
    click.echo(msg)

@util.command(name='fetch_permissions')
@click.argument('objtype', type=click.STRING)
@click.argument('objuid', required=False, default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def util_fetch_permissions(obj, objtype, objuid, tokens):

    tokens = list(tokens)
    spermissions, errors = utilities.fetch_permissions(objtype, objuid=objuid, tokens=tokens,
                                                       ac_server_names=[obj['srv_ac']],
                                                       conf=obj['conf'],
                                                       account_uid=obj['account_uid'],
                                                       client_uid=obj['client_uid'])

    for srv, error in errors.items():
        click.echo("{}: {}".format(srv, errors))

    for srv, permissions in spermissions.items():
        click.echo("{}: {}".format(srv, permissions))

@util.command(name='setup_collection')
@click.option('--col_uid', default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--verifier', 'verifiers', nargs=1, type=click.UUID, multiple=True)
@click.pass_obj
def util_setup_collection(obj, col_uid, tokens, verifiers):

    tokens = list(tokens)
    verifiers = list(verifiers)
    col_uid, verifiers = utilities.setup_collection(col_uid=col_uid, tokens=tokens,
                                                    verifiers=verifiers,
                                                    conf=obj['conf'],
                                                    ac_server_names=[obj['srv_ac']],
                                                    storage_server_names=[obj['srv_storage']],
                                                    account_uid=obj['account_uid'],
                                                    client_uid=obj['client_uid'])
    verfiers = [str(v) for v in verifiers]
    click.echo("Setup collection '{}' using verifiers {}".format(col_uid, verifiers))

@util.command(name='store_secret')
@click.argument('data', type=click.STRING)
@click.option('--sec_uid', default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--col_uid', default=None, type=click.UUID)
@click.option('--verifier', 'verifiers', nargs=1,
              type=click.UUID, multiple=True)
@click.pass_obj
def util_store_secret(obj, data, sec_uid, tokens, col_uid, verifiers):

    tokens = list(tokens)
    verifiers = list(verifiers)
    sec_uid, col_uid, verifiers = utilities.store_secret(data, sec_uid=sec_uid, tokens=tokens,
                                                         col_uid=col_uid, verifiers=verifiers,
                                                         conf=obj['conf'],
                                                         ac_server_names=[obj['srv_ac']],
                                                         storage_server_names=[obj['srv_storage']],
                                                         account_uid=obj['account_uid'],
                                                         client_uid=obj['client_uid'])
    verfiers = [str(v) for v in verifiers]
    msg = "Stored secret '{}' ".format(sec_uid)
    msg += "in collection '{}' ".format(col_uid)
    msg += "using verifiers {}".format(verfiers)
    click.echo(msg)

@util.command(name='fetch_secret')
@click.argument('col_uid',  type=click.UUID)
@click.argument('sec_uid',  type=click.UUID)
@click.pass_obj
def util_fetch_secret(obj, col_uid, sec_uid):

    sec_data = utilities.fetch_secret(sec_uid, col_uid,
                                      conf=obj['conf'],
                                      ac_server_names=[obj['srv_ac']],
                                      storage_server_names=[obj['srv_storage']],
                                      account_uid=obj['account_uid'],
                                      client_uid=obj['client_uid'])
    click.echo(sec_data)


### Bootstrap Commands ###

@cli.group(name='bootstrap')
@click.pass_context
def bootstrap(ctx):

    obj = ctx.obj
    obj['ac_connection'] = accesscontrol.ACServerConnection(ac_server_name=obj['srv_ac'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'],
                                                            no_client_crt=True,
                                                            conf=obj['conf'])
    obj['client_bootstrap'] = accesscontrol.BootstrapClient(obj['ac_connection'])

# @bootstrap.command(name='account')
# @click.option('--account_userdata', default={}, nargs=2, type=click.STRING, multiple=True)
# @click.option('--account_uid', default=None, type=click.UUID)
# @click.option('--client_userdata', default={}, nargs=2, type=click.STRING, multiple=True)
# @click.option('--client_uid', default=None, type=click.UUID)
# @click.option('--key_file', default=None, help="Private Key File",
#             type=click.Path(resolve_path=True))
# @click.pass_obj
# def bootstrap_account(csr_path,
#                       account_userdata, account_uid,
#                       client_userdata, client_uid):

#     if len(country) != 2:
#         raise ValueError("Country must be 2-letter code")

#     if not key_file:
#         key_pem = crypto.gen_key()
#     else:
#         with open(key_file, 'r') as f:
#             key_pem = f.read()

#     with open("key.pem", 'w') as f:
#         f.write(key_pem)

#     csr_pem = crypto.gen_csr(key_pem, _CLIENT_CN, country, state, locality, organization, ou, email)

#     with open("csr.pem", 'w') as f:
#         f.write(csr_pem)

#     ret = obj['bootstrap_client'].account(account_userdata=dict(account_userdata),
#                                           account_uid=account_uid,
#                                           client_userdata=dict(client_userdata),
#                                           client_uid=client_uid,
#                                           client_csr=csr_pem)
#     account_uid, client_uid, client_cert = ret

#     # Save Files

#     click.echo("Account UUID: {}".format(str(account_uid)))
#     click.echo("Client UUID: {}".format(str(client_uid)))
#     click.echo("Client Cert: {}".format(client_cert))


### Authorizations Commands ###

@cli.group(name='authorizations')
@click.pass_context
def authorizations(ctx):

    obj = ctx.obj
    obj['ac_connection'] = accesscontrol.ACServerConnection(server_name=obj['srv_ac'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'],
                                                            conf=obj['conf'])
    obj['client_authorizations'] = accesscontrol.AuthorizationsClient(obj['ac_connection'])

@authorizations.command(name='request')
@click.argument('obj_type', type=click.STRING)
@click.argument('obj_perm', type=click.STRING)
@click.argument('obj_uid', required=False, default=None, type=click.UUID)
@click.option('--userdata', nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def authorizations_request(obj, obj_type, obj_perm, obj_uid, userdata):

    userdata = dict(list(userdata))
    with obj['ac_connection']:
        uid = obj['client_authorizations'].request(obj_type, obj_perm,
                                                   obj_uid=obj_uid, userdata=userdata)
    click.echo(uid)

@authorizations.command(name='fetch')
@click.argument('uid', type=click.UUID)
@click.pass_obj
def authorizations_fetch(obj, uid):

    with obj['ac_connection']:
        authz = obj['client_authorizations'].fetch(uid)
    click.echo(authz)

@authorizations.command(name='token')
@click.argument('uid', type=click.UUID)
@click.pass_obj
def authorizations_token(obj, uid):

    with obj['ac_connection']:
        token = obj['client_authorizations'].wait_token(uid)

    click.echo(token)

### Authenticators Commands ###

@cli.group(name='authenticators')
@click.pass_context
def authenticators(ctx):

    obj = ctx.obj
    obj['ac_connection'] = accesscontrol.ACServerConnection(server_name=obj['srv_ac'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'],
                                                            conf=obj['conf'])
    obj['authenticators'] = accesscontrol.AuthenticatorsClient(obj['ac_connection'])

@authenticators.command(name='create')
@click.argument('module_name', type=click.STRING)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--module_arg', 'module_kwargs', nargs=2, type=click.STRING, multiple=True)
@click.option('--uid', default=None, type=click.UUID)
@click.option('--userdata', nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def authenticators_create(obj, module_name, module_kwargs, tokens, uid, userdata):

    tokens = list(tokens)
    module_kwargs = dict(list(module_kwargs))
    userdata = dict(list(userdata))
    with obj['ac_connection']:
        uid = obj['authenticators'].create(tokens, module_name,
                                           module_kwargs=module_kwargs,
                                           uid=uid, userdata=userdata)
    click.echo(uid)

@authenticators.command(name='fetch')
@click.argument('uid', type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def authenticators_fetch(obj, uid, tokens):

    tokens = list(tokens)
    with obj['ac_connection']:
        authenticator = obj['authenticators'].fetch(tokens, uid)
    click.echo(authenticator)


### Verifiers Commands ###

@cli.group(name='verifiers')
@click.pass_context
def verifiers(ctx):

    obj = ctx.obj
    obj['ac_connection'] = accesscontrol.ACServerConnection(server_name=obj['srv_ac'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'],
                                                            conf=obj['conf'])
    obj['verifiers'] = accesscontrol.VerifiersClient(obj['ac_connection'])

@verifiers.command(name='create')
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--uid', default=None, type=click.UUID)
@click.option('--account', 'accounts', nargs=1, type=click.UUID, multiple=True)
@click.option('--authenticator', 'authenticators', nargs=1, type=click.UUID, multiple=True)
@click.option('--userdata', nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def verifiers_create(obj, tokens, uid, accounts, authenticators, userdata):

    tokens = list(tokens)
    accounts = list(accounts)
    authenticators = list(authenticators)
    userdata = dict(list(userdata))
    with obj['ac_connection']:
        uid = obj['verifiers'].create(tokens, uid=uid,
                                      accounts=accounts,
                                      authenticators=authenticators,
                                      userdata=userdata)
    click.echo(uid)

@verifiers.command(name='fetch')
@click.argument('uid', type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def verifiers_fetch(obj, uid, tokens):

    tokens = list(tokens)
    with obj['ac_connection']:
        verifiers = obj['verifiers'].fetch(tokens, uid)
    click.echo(verifiers)


### Permissions Commands ###

@cli.group(name='permissions')
@click.pass_context
def permissions(ctx):

    obj = ctx.obj
    obj['ac_connection'] = accesscontrol.ACServerConnection(server_name=obj['srv_ac'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'],
                                                            conf=obj['conf'])
    obj['permissions'] = accesscontrol.PermissionsClient(obj['ac_connection'])

@permissions.command(name='create')
@click.argument('objtype', type=click.STRING)
@click.argument('objuid', required=False, default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--v_create', 'v_create', nargs=1, type=click.UUID, multiple=True)
@click.option('--v_read', 'v_read', nargs=1, type=click.UUID, multiple=True)
@click.option('--v_modify', 'v_modify', nargs=1, type=click.UUID, multiple=True)
@click.option('--v_delete', 'v_delete', nargs=1, type=click.UUID, multiple=True)
@click.option('--v_perms', 'v_perms', nargs=1, type=click.UUID, multiple=True)
@click.option('--v_default', 'v_default', nargs=1, type=click.UUID, multiple=True)
@click.pass_obj
def permissions_create(obj, objtype, objuid, tokens,
                       v_create, v_read, v_modify, v_delete, v_perms, v_default):

    tokens = list(tokens)
    v_create = list(v_create)
    v_read = list(v_read)
    v_modify = list(v_modify)
    v_delete = list(v_delete)
    v_perms = list(v_perms)
    v_default = list(v_defaults)
    with obj['ac_connection']:
        objtype, objuid = obj['permissions'].create(tokens, objtype, objuid=objuid,
                                                    v_create=v_create,
                                                    v_read=v_read,
                                                    v_modify=v_modify,
                                                    v_delete=v_delete,
                                                    v_perms=v_perms,
                                                    v_default=v_default)
    click.echo("{} {}".format(objtype, objuid))

@permissions.command(name='fetch')
@click.argument('objtype', type=click.STRING)
@click.argument('objuid', required=False, default=None, type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def permissions_fetch(obj, objtype, objuid):

    tokens = list(tokens)
    with obj['ac_connection']:
        perms = obj['permissions'].fetch(tokens, objtype, objuid)
    click.echo(perms)


### Collection Storage Commands ###

@cli.group(name='collections')
@click.pass_context
def collections(ctx):

    obj = ctx.obj

    obj['storage_connection'] = storage.StorageServerConnection(
        server_name=obj['srv_storage'], conf=obj['conf'])
    obj['collections'] = storage.CollectionsClient(obj['storage_connection'])

    obj['ac_connection'] = accesscontrol.ACServerConnection(
        server_name=obj['srv_ac'], conf=obj['conf'],
        account_uid=obj['account_uid'], client_uid=obj['client_uid'])
    obj['authorizations'] = accesscontrol.AuthorizationsClient(obj['ac_connection'])

@collections.command(name='create')
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--uid', default=None, type=click.UUID)
@click.option('--userdata', nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def collections_create(obj, uid, userdata, tokens):

    tokens = list(tokens)
    userdata = dict(list(userdata))
    if not tokens:
        with obj['ac_connection']:
            objtype = obj['collections'].objtype
            objuid = None
            objperm = obj['collections'].objperm_create
            authz_uid = obj['authorizations'].request(objtype, objuid, objperm)
            authz_token = obj['authorizations'].wait_token(authz_uid)
        tokens = [authz_token]

    with obj['storage_connection']:
        userdata = dict(userdata)
        ac_server_url = obj['conf'].ac_server_get_url(obj['srv_ac'])
        assert(ac_server_url)
        ac_servers = [ac_server_url]
        uid = obj['collections'].create(tokens, ac_servers,
                                        uid=uid, userdata=userdata)

    click.echo(uid)


### Secret Storage Commands ###

@cli.group(name='secrets')
@click.argument('col_uid', type=click.UUID)
@click.pass_context
def secrets(ctx, col_uid):

    obj = ctx.obj
    obj['col_uid'] = col_uid

    obj['storage_connection'] = storage.StorageServerConnection(
        server_name=obj['srv_storage'], conf=obj['conf'])
    obj['secrets'] = storage.SecretsClient(obj['storage_connection'])

    obj['ac_connection'] = accesscontrol.ACServerConnection(
        server_name=obj['srv_ac'], conf=obj['conf'],
        account_uid=obj['account_uid'], client_uid=obj['client_uid'])
    obj['authorizations'] = accesscontrol.AuthorizationsClient(obj['ac_connection'])

@secrets.command(name='create')
@click.argument('data', type=click.STRING)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.option('--uid', default=None, type=click.UUID)
@click.option('--userdata', nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def secrets_create(obj, data, uid, userdata, tokens):

    tokens = list(tokens)
    userdata = dict(list(userdata))
    if not tokens:
        with obj['ac_connection']:
            objtype = obj['secrets'].objtype
            objuid = obj['col_uid']
            objperm = obj['secrets'].objperm_create
            authz_uid = obj['authorizations'].request(objtype, objuid, objperm)
            authz_token = obj['authorizations'].wait_token(authz_uid)
        tokens = [authz_token]

    with obj['storage_connection']:
        userdata = dict(userdata)
        uid = obj['secrets'].create(tokens, obj['col_uid'], data,
                                    uid=uid, userdata=userdata)

    click.echo(uid)

@secrets.command(name='fetch')
@click.argument('uid', type=click.UUID)
@click.option('--token', 'tokens', nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def secrets_fetch(obj, uid, tokens):

    tokens = list(tokens)
    if not tokens:
        with obj['ac_connection']:
            objtype = obj['secrets'].objtype
            objuid = obj['col_uid']
            objperm = obj['secrets'].objperm_fetch
            authz_uid = obj['authorizations'].request(objtype, objuid, objperm)
            authz_token = obj['authorizations'].wait_token(authz_uid)
        tokens = [authz_token]

    with obj['storage_connection']:
        sec = obj['secrets'].fetch(tokens, obj['col_uid'], uid)

    click.echo(sec)


### Main ###

if __name__ == '__main__':
    sys.exit(cli())
