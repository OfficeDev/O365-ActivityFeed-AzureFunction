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
param EnableElasticPremiumPlan bool

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
          networkSecurityGroup: {
           id: nsg.id
          } 
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
          serviceEndpoints: EnableElasticPremiumPlan == true ? [
            {
              service: 'Microsoft.Storage'
            }
          ] : []
          networkSecurityGroup: {
           id: nsg.id
          } 
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

resource peQueue 'Microsoft.Network/privateEndpoints@2022-07-01' = {
  name: 'pe-queue-${StorageAccountName}'
  location: location
  properties: {
     subnet: {
      id: virtualNetwork.properties.subnets[0].id
     }
     privateLinkServiceConnections: [
      {
        name: 'pe-queue-${StorageAccountName}'
        properties: {
         privateLinkServiceId: StorageAccountId
         groupIds: [
          'queue'
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

resource privateDnsZoneQueue 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.queue.${environment().suffixes.storage}'
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

resource privateDnsZoneLinkQueue 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  name: '${privateDnsZoneQueue.name}-link'
  parent: privateDnsZoneQueue
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

resource peDnsGroupQueue 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2022-07-01' = {
  name: '${peQueue.name}/dnsGroup'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'config1'
        properties: {
          privateDnsZoneId: privateDnsZoneQueue.id
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

var roleIdOwner = '/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'

resource roleAssignmentVnet 'Microsoft.Authorization/roleAssignments@2022-04-01' = if(DeployCode == true) {
  name: guid(subscription().id, resourceGroup().id, virtualNetwork.id)
  scope: virtualNetwork
  properties: {
    principalId: PrincipalId
    roleDefinitionId: roleIdOwner
    principalType: 'ServicePrincipal'
  }
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: 'nsg-sentineldlp'
  location: location
  /*
  properties: {
    securityRules: [
      {
        name: 'AllowOutboundAzureCloud'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'AzureCloud'
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }   
      }
      {
        name: 'DenyOutboundInternet'
        properties: {
          protocol: '*'
          sourcePortRange: '*'
          destinationPortRange: '*'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Internet'
          access: 'Deny'
          priority: 110
          direction: 'Outbound'
        }   
      } 
    ] 
  }
  */  
}

output functionAppSubnetId string = virtualNetwork.properties.subnets[1].id
output privateEndpointSubnetId string = virtualNetwork.properties.subnets[0].id
output vnetId string = virtualNetwork.id
