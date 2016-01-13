#!/usr/bin/env python3


### Imports ###

import sys
import os

import click

from pytutamen import api_client
from pytutamen import accesscontrol
from pytutamen import crypto


### Constants ###

_APP_NAME = 'tutamen-cli'
_PATH_SERVER_CONF = os.path.join(click.get_app_dir(_APP_NAME), 'servers')

_CLIENT_CN = "New Tutamen Client"

### CLI Root ###

@click.group()
@click.option('--url', prompt=True, help="API URL")
@click.option('--client_cert', default=None, help="Client Certificate File",
              type=click.Path(resolve_path=True))
@click.option('--client_key', default=None, help="Client Private Key File",
              type=click.Path(resolve_path=True))
@click.option('--ca', default=None, help="API CA Certificate File",
              type=click.Path(resolve_path=True))
@click.pass_context
def cli(ctx, url, client_cert, client_key, ca):
    """COG CLI"""

    # Setup Client
    apiclient = api_client.APIClient(url_server=url,
                                     path_cert=client_cert, path_key=client_key, path_ca=ca)
    apiclient.open()
    ctx.call_on_close(apiclient.close)

    # Setup Context
    ctx.obj = {}
    ctx.obj['apiclient'] = apiclient


### Bootstrap Commands ###

@cli.group(name='bootstrap')
@click.pass_obj
def bootstrap(obj):

    obj['bootstrap_client'] = accesscontrol.BootstrapClient(obj['apiclient'])

@bootstrap.command(name='account')
@click.argument('country', type=click.STRING)
@click.argument('state', type=click.STRING)
@click.argument('locality', type=click.STRING)
@click.argument('organization', type=click.STRING)
@click.argument('ou', type=click.STRING)
@click.argument('email', type=click.STRING)
@click.option('--account_userdata', default={}, nargs=2, type=click.STRING, multiple=True)
@click.option('--account_uid', default=None, type=click.UUID)
@click.option('--client_userdata', default={}, nargs=2, type=click.STRING, multiple=True)
@click.option('--client_uid', default=None, type=click.UUID)
@click.option('--key_file', default=None, help="Private Key File",
            type=click.Path(resolve_path=True))
@click.pass_obj
def bootstrap_account(obj, country, state, locality, organization, ou, email,
                      account_userdata, account_uid,
                      client_userdata, client_uid, key_file):

    if len(country) != 2:
        raise ValueError("Country must be 2-letter code")

    if not key_file:
        key_pem = crypto.gen_key()
    else:
        with open(key_file, 'r') as f:
            key_pem = f.read()

    with open("key.pem", 'w') as f:
        f.write(key_pem)

    csr_pem = crypto.gen_csr(key_pem, _CLIENT_CN, country, state, locality, organization, ou, email)

    with open("csr.pem", 'w') as f:
        f.write(csr_pem)

    ret = obj['bootstrap_client'].account(account_userdata=dict(account_userdata),
                                          account_uid=account_uid,
                                          client_userdata=dict(client_userdata),
                                          client_uid=client_uid,
                                          client_csr=csr_pem)
    account_uid, client_uid = ret
    click.echo("Account UUID: {}".format(str(account_uid)))
    click.echo("Client UUID: {}".format(str(client_uid)))


# ### Collection Storage Commands ###

# @cli.group(name='collections')
# @click.pass_obj
# def collections(obj):

#     obj['collections_client'] = api_client.CollectionsClient(obj['client'])

# @collections.command(name='create')
# @click.option('--usermetadata', default={}, nargs=2, type=click.STRING, multiple=True)
# @click.pass_obj
# def collections_create(obj, usermetadata):

#     click.echo(obj['collections_client'].create(usermetadata=dict(usermetadata)))

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
# @click.option('--usermetadata', default={}, nargs=2, type=click.STRING, multiple=True)
# @click.pass_obj
# def secrets_create(obj, col_uid, data, usermetadata):

#     click.echo(obj['secrets_client'].create(col_uid, data, usermetadata=dict(usermetadata)))

### Main ###

if __name__ == '__main__':
    sys.exit(cli())
