type AnvilDetailForProvisionServer = {
  anvilUUID: string;
  anvilName: string;
  hosts: Array<{
    hostUUID: string;
    hostName: string;
    hostCPUCores: number;
    hostMemory: string;
  }>;
  anvilTotalCPUCores: number;
  anvilTotalMemory: string;
  servers: Array<{
    serverUUID: string;
    serverName: string;
    serverCPUCores: number;
    serverMemory: string;
  }>;
  anvilTotalAllocatedCPUCores: number;
  anvilTotalAllocatedMemory: string;
  anvilTotalAvailableCPUCores: number;
  anvilTotalAvailableMemory: string;
  storageGroups: Array<{
    storageGroupUUID: string;
    storageGroupName: string;
    storageGroupSize: string;
    storageGroupFree: string;
  }>;
  files: Array<{
    fileUUID: string;
    fileName: string;
  }>;
};
