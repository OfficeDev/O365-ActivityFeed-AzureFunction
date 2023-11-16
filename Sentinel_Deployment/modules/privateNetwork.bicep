param PrivateNetworkAddressSpace string
param PrivateEndpointsSubnet string
param FunctionAppSubnet string
param FunctionAppName string
param StorageAccountName string
param StorageAccountId string
param KeyVaultName string
param KeyVaultId string
param location string
param PrincipalId string
param DeployCode bool

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2022-07-01' = {
  name: 'vnet-${FunctionAppName}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        PrivateNetworkAddressSpace
      ] 
    }
    subnets: [
      {
        name: 'privateEndpoints'
        properties: {
          addressPrefix: PrivateEndpointsSubnet
        }  
      }
      {
        name: 'functionAppVnetIntegration'
        properties: {
          addressPrefix: FunctionAppSubnet
          delegations: [
            {
              name: 'delegation'
              properties: {
                serviceName: 'Microsoft.Web/serverFarms' 
              }                
            } 
          ]  
        } 
      }  
    ]   
  }    
}

resource peKeyVault 'Microsoft.Network/privateEndpoints@2022-07-01' = {
  name: 'pe-${KeyVaultName}'
  location: location
  properties: {
     subnet: {
      id: virtualNetwork.properties.subnets[0].id
     }
     privateLinkServiceConnections: [
      {
        name: 'pe-${KeyVaultName}'
        properties: {
         privateLinkServiceId: KeyVaultId
         groupIds: [
          'vault'
         ] 
        }
      }
     ] 
  } 
}

resource peBlob 'Microsoft.Network/privateEndpoints@2022-07-01' = {
  name: 'pe-blob-${StorageAccountName}'
  location: location
  properties: {
     subnet: {
      id: virtualNetwork.properties.subnets[0].id
     }
     privateLinkServiceConnections: [
      {
        name: 'pe-blob-${StorageAccountName}'
        properties: {
         privateLinkServiceId: StorageAccountId
         groupIds: [
          'blob'
         ] 
        }
      }
     ] 
  } 
}

resource peFile 'Microsoft.Network/privateEndpoints@2022-07-01' = {
  name: 'pe-file-${StorageAccountName}'
  location: location
  properties: {
     subnet: {
      id: virtualNetwork.properties.subnets[0].id
     }
     privateLinkServiceConnections: [
      {
        name: 'pe-file-${StorageAccountName}'
        properties: {
         privateLinkServiceId: StorageAccountId
         groupIds: [
          'file'
         ] 
        }
      }
     ] 
  } 
}

resource privateDnsZoneBlob 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.blob.${environment().suffixes.storage}' 
  location: 'global'
  dependsOn: [
    virtualNetwork
  ] 
}


resource privateDnsZoneFile 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.file.${environment().suffixes.storage}'
  location: 'global'
  dependsOn: [
    virtualNetwork
  ]
}

resource privateDnsZoneKeyVault 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.vaultcore.azure.net'
  location: 'global'
  dependsOn: [
    virtualNetwork
  ]
}

resource privateDnsZoneLinkBlob 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: '${privateDnsZoneBlob.name}-link'
  parent: privateDnsZoneBlob
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetwork.id
    }  
  }   
}

resource privateDnsZoneLinkFile 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: '${privateDnsZoneFile.name}-link'
  parent: privateDnsZoneFile
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetwork.id
    }  
  }   
}

resource privateDnsZoneLinkKeyVault 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: '${privateDnsZoneKeyVault.name}-link'
  parent: privateDnsZoneKeyVault
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetwork.id
    }  
  }   
}

resource peDnsGroupBlob 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2022-07-01' = {
  name: '${peBlob.name}/dnsGroup'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: privateDnsZoneBlob.id
        } 
      }
    ]
  }
}

resource peDnsGroupFile 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2022-07-01' = {
  name: '${peFile.name}/dnsGroup'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: privateDnsZoneFile.id
        } 
      }
    ]
  }
}

resource peDnsGroupKeyVault 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2022-07-01' = {
  name: '${peKeyVault.name}/dnsGroup'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: privateDnsZoneKeyVault.id
        } 
      }
    ]
  }
}

var roleIdContributor = '/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'

resource roleAssignmentVnet 'Microsoft.Authorization/roleAssignments@2022-04-01' = if(DeployCode == true) {
  name: guid(subscription().id, resourceGroup().id, virtualNetwork.id)
  scope: virtualNetwork
  properties: {
    principalId: PrincipalId
    roleDefinitionId: roleIdContributor
    principalType: 'ServicePrincipal'
  }
}

output functionAppSubnetId string = virtualNetwork.properties.subnets[1].id
output privateEndpointSubnetId string = virtualNetwork.properties.subnets[0].id
output vnetId string = virtualNetwork.id
