#irods configuration
IRODS = {
  'zone':'tempZone',
  'user':'rods',
  'host':'<irods_host>', 
  'port':<irods_port>,
  'openid_microservice':'<python_broker_url>',
}

GLOBUS = {
  'client-id': '<client-id>',
  'key': '<key-file>',
  'cert': '<certificate-file>',
  'endpoint': '<globus_endpoint>',
  'path': '<globus_path>',
  'auth_refresh_token': '<auth_refresh_token>',
  'transfer_refresh_token': '<transfer_refresh_token>'
}

STAGING= {
  'path': '<nfs path>',
}
