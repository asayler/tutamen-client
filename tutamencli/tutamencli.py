#!/usr/bin/env python3


### Imports ###

import sys
import os

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
        ac_server_name = ctx.obj['conf'].defaults_get_ac_server()
    ctx.obj['srv_ac'] = srv_ac
    if not srv_storage:
        ac_server_name = ctx.obj['conf'].defaults_get_storage_server()
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

@util.command(name='setup_ac_server')
@click.argument('name', type=click.STRING)
@click.argument('url', type=click.STRING)
@click.pass_obj
def util_setup_ac_server(obj, name, url):

    utilities.setup_new_ac_server(name, url, conf=obj['conf'])

@util.command(name='setup_storage_server')
@click.argument('name', type=click.STRING)
@click.argument('url', type=click.STRING)
@click.pass_obj
def util_setup_storage_server(obj, name, url):

    utilities.setup_new_storage_server(name, url, conf=obj['conf'])

@util.command(name='setup_account')
@click.option('--cn', default=None, type=click.STRING)
@click.option('--country', default=None, type=click.STRING)
@click.option('--state', default=None, type=click.STRING)
@click.option('--locality', default=None, type=click.STRING)
@click.option('--organization', default=None, type=click.STRING)
@click.option('--ou', default=None, type=click.STRING)
@click.option('--email', default=None, type=click.STRING)
@click.option('--account_userdata', default={}, nargs=2, type=click.STRING, multiple=True)
@click.option('--client_userdata', default={}, nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def util_setup_account(obj, cn, country, state, locality, organization, ou, email,
                       account_userdata, client_userdata):

    ret = utilities.setup_new_account(ac_server_name=obj['srv_ac'],
                                      cn=cn, country=country, state=state, locality=locality,
                                      organization=organization, ou=ou, email=email,
                                      account_userdata=dict(account_userdata),
                                      account_uid=obj['account_uid'],
                                      client_userdata=dict(client_userdata),
                                      client_uid=obj['client_uid'],
                                      conf=obj['conf'])

    account_uid, client_uid, client_cert = ret
    click.echo("Account UUID: {}".format(str(account_uid)))
    click.echo("Client UUID: {}".format(str(client_uid)))


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
    obj['ac_connection'] = accesscontrol.ACServerConnection(ac_server_name=obj['srv_ac'],
                                                            account_uid=obj['account_uid'],
                                                            client_uid=obj['client_uid'],
                                                            conf=obj['conf'])
    obj['client_authorizations'] = accesscontrol.AuthorizationsClient(obj['ac_connection'])

@authorizations.command(name='request')
@click.argument('obj_type', type=click.STRING)
@click.argument('obj_uid', type=click.UUID)
@click.argument('obj_perm', type=click.STRING)
@click.option('--userdata', default={}, nargs=2, type=click.STRING, multiple=True)
@click.pass_obj
def authorizations_request(obj, obj_perm, obj_type, obj_uid, userdata):

    with obj['ac_connection']:
        uid = obj['client_authorizations'].request(obj_type, obj_uid, obj_perm)

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


### Collection Storage Commands ###

@cli.group(name='collections')
@click.pass_context
def collections(ctx):

    obj = ctx.obj
    obj['storage_connection'] = storage.StorageServerConnection(
        storage_server_name=obj['srv_storage'],
        conf=obj['conf'])
    obj['client_collections'] = storage.CollectionsClient(obj['storage_connection'])

@collections.command(name='create')
@click.option('--uid', default=None, type=click.UUID)
@click.option('--userdata', default={}, nargs=2, type=click.STRING, multiple=True)
@click.option('--tokens', default=[], nargs=1, type=click.STRING, multiple=True)
@click.pass_obj
def collections_create(obj, uid, userdata, tokens):

    with obj['storage_connection']:
        uid = obj['client_collections'].create(tokens, uid=uid, userdata=dict(userdata))

    click.echo(uid)

# ### Secret Storage Commands ###

# @cli.group(name='secrets')
# @click.pass_obj
# def secrets(obj):

#     obj['secrets_client'] = client.SecretsClient(obj['client'])

# @secrets.command(name='data')
# @click.argument('col_uid', type=click.UUID)
# @click.argument('sec_uid', type=click.UUID)
# @click.pass_obj
# def secrets_get_data(obj, col_uid, sec_uid):

#     click.echo(obj['secrets_client'].data(col_uid, sec_uid))

# @secrets.command(name='create')
# @click.argument('col_uid', type=click.UUID)
# @click.argument('data', type=click.STRING)
# @click.option('--userdata', default={}, nargs=2, type=click.STRING, multiple=True)
# @click.pass_obj
# def secrets_create(obj, col_uid, data, userdata):

#     click.echo(obj['secrets_client'].create(col_uid, data, userdata=dict(userdata)))

### Main ###

if __name__ == '__main__':
    sys.exit(cli())
