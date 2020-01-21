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
}

STAGING= {
  'path': '<path>',
  'globus_endpoint': '<globus_endpoint>',
  'globus_path': '<globus_path>'
}
