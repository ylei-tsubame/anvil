import { P_IF } from '../../consts';

import { queries, query } from '../../accessModule';
import { camel } from '../../camel';
import { setChain } from '../../chain';
import { getHostIpmi } from '../../disassembleCommand';
import join from '../../join';
import { perr, poutvar } from '../../shell';
import {
  sqlHosts,
  sqlIfaceAlias,
  sqlIpAddresses,
  sqlNetworkInterfaces,
  sqlScanDrbdPeers,
  sqlScanDrbdResources,
  sqlScanDrbdVolumes,
  sqlScanLvmVgs,
  sqlServers,
  sqlVariables,
} from '../../sqls';

const regexps = {
  network: {
    id: new RegExp(`^${P_IF.id}`),
  },
};

const setvarParams: Record<
  string,
  (
    parts: string[],
    value: string,
  ) => [string[], value: boolean | number | string]
> = {
  form: (parts, original) => {
    const [, part2 = ''] = parts;

    const part = part2.toLocaleLowerCase();

    const [head = '', ...rest] = part.split('_');

    let chain: string[];

    let value: boolean | number | string = original;

    if (regexps.network.id.test(head)) {
      chain = ['netconf', 'networks', head, camel(...rest)];

      if (/create_bridge/.test(part)) {
        value = original === '1';
      }
    } else if (/^dns$|^gateway|count$/.test(part)) {
      chain = ['netconf', camel(head, ...rest)];

      if (/count$/.test(part)) {
        value = Number(original);
      }
    } else {
      chain = ['variables', camel(head, ...rest)];

      if (/sequence/.test(part)) {
        value = Number(original);
      }
    }

    return [chain, value];
  },
  'install-target': (parts, original) => [
    ['variables', 'installTarget'],
    original === 'enabled',
  ],
  network: (parts, original) => [['netconf', 'ntp'], original],
  system: (parts, original) => [['configured'], original === '1'],
};

export const buildHostDetailList = async (
  options: {
    lsHost?: string[];
    lsNode?: string[];
    lsType?: string[];
  } = {},
): Promise<HostDetailList> => {
  const { lsHost, lsNode, lsType } = options;

  let conditions = 'TRUE';

  if (lsHost?.length) {
    conditions += join(lsHost, {
      beforeReturn: (csv) => csv && ` AND a.host_uuid IN (${csv})`,
      elementWrapper: "'",
      separator: ', ',
    });
  }

  if (lsNode?.length) {
    conditions += join(lsNode, {
      beforeReturn: (csv) => csv && ` AND b.anvil_uuid IN (${csv})`,
      elementWrapper: "'",
      separator: ', ',
    });
  }

  if (lsType?.length) {
    conditions += join(lsType, {
      beforeReturn: (csv) => csv && ` AND a.host_type IN (${csv})`,
      elementWrapper: "'",
      separator: ', ',
    });
  }

  let hostRows: string[][];

  const sqlGetHosts = `
    SELECT
      a.host_uuid,
      a.host_name,
      a.host_short_name,
      a.host_type,
      a.host_ipmi,
      a.host_status,
      ROUND(
        EXTRACT(epoch from a.modified_date)
      ) AS modified_epoch,
      b.anvil_uuid,
      b.anvil_name,
      b.anvil_description
    FROM (${sqlHosts()}) AS a
    LEFT JOIN anvils AS b
      ON a.host_uuid IN (
        b.anvil_node1_host_uuid,
        b.anvil_node2_host_uuid
      )
    WHERE ${conditions}
    ORDER BY
      a.host_name;`;

  try {
    hostRows = await query(sqlGetHosts);
  } catch (error) {
    perr(`Failed to get host(s); CAUSE: ${error}`);

    throw error;
  }

  const hosts: HostDetailList = {};

  let hostNamesLikeCsv = '';
  let hostUuidsCsv = '';

  hostRows.forEach((row) => {
    const [
      uuid,
      name,
      short,
      type,
      ipmiCommand,
      status,
      modified,
      anvilUuid,
      anvilName,
      anvilDescription,
    ] = row;

    hostNamesLikeCsv += `'%${name}%', `;
    hostUuidsCsv += `'${uuid}', `;

    const ipmi = getHostIpmi(ipmiCommand);

    const host: HostDetail = {
      configured: false,
      drbdResources: {},
      ipmi,
      modified: Number(modified),
      name,
      netconf: {
        dns: '',
        gateway: '',
        gatewayInterface: '',
        networks: {},
        ntp: '',
      },
      servers: {
        all: {},
        configured: [],
        replicating: [],
        running: [],
      },
      short,
      status: {
        drbd: {
          maxEstimatedTimeToSync: 0,
          status: 'none',
        },
        system: status,
      },
      storage: {
        volumeGroups: {},
        volumeGroupTotals: {
          free: '',
          size: '',
          used: '',
        },
      },
      type,
      uuid,
      variables: {},
    };

    if (anvilUuid) {
      host.anvil = {
        description: anvilDescription,
        name: anvilName,
        uuid: anvilUuid,
      };
    }

    hosts[uuid] = host;
  });

  poutvar(hosts, 'After getting hosts; hosts=');

  if (!hostUuidsCsv) {
    return hosts;
  }

  hostNamesLikeCsv = hostNamesLikeCsv.replace(/,\s+$/, '');
  hostUuidsCsv = hostUuidsCsv.replace(/,\s+$/, '');

  const sqlListAllHosts = `
    SELECT
      host_name,
      host_uuid
    FROM hosts
    ORDER BY modified_date ASC;`;

  const sqlGetIfaces = `
    SELECT
      a.network_interface_uuid,
      a.network_interface_host_uuid,
      a.network_interface_mac_address,
      SUBSTRING(
        b.network_interface_alias, '${P_IF.xType}'
      ) AS network_type,
      SUBSTRING(
        b.network_interface_alias, '${P_IF.xNum}'
      ) AS network_number,
      SUBSTRING(
        b.network_interface_alias, '${P_IF.xLink}'
      ) AS network_link,
      e.ip_address_address,
      e.ip_address_subnet_mask,
      e.ip_address_gateway,
      e.ip_address_default_gateway,
      e.ip_address_dns
    FROM (${sqlNetworkInterfaces()}) AS a
    JOIN (${sqlIfaceAlias()}) AS b
      ON b.network_interface_uuid = a.network_interface_uuid
    LEFT JOIN bonds AS c
      ON c.bond_uuid = a.network_interface_bond_uuid
    LEFT JOIN bridges AS d
      ON d.bridge_uuid IN (
        a.network_interface_bridge_uuid,
        c.bond_bridge_uuid
      )
    LEFT JOIN (${sqlIpAddresses()}) AS e
      ON e.ip_address_on_uuid IN (
        a.network_interface_uuid,
        c.bond_uuid,
        d.bridge_uuid
      )
    WHERE a.network_interface_host_uuid IN (${hostUuidsCsv})
    ORDER BY b.network_interface_alias;`;

  const sqlGetSaved = `
    SELECT
      a.job_host_uuid,
      a.host_name,
      a.key,
      a.value,
      b.network_interface_uuid
    FROM (
      SELECT
        job_host_uuid,
        host_name,
        split_part(entry, '=', 1) AS key,
        split_part(entry, '=', 2) AS value
      FROM (
        SELECT
          job_host_uuid,
          host_name,
          unnest(
            string_to_array( job_data, chr(10) )
          ) AS entry
        FROM (
          SELECT
            *,
            SUBSTRING(job_data, 'host_name::value=([^\\n]+)') AS host_name
          FROM jobs
          WHERE
              job_command LIKE '%anvil-configure-host%'
            AND
              job_data LIKE ANY (
                ARRAY[
                  ${hostNamesLikeCsv}
                ]
              )
          ORDER BY modified_date DESC
          LIMIT 1
        ) AS scope
      ) AS entries
      WHERE entry LIKE '%=%'
    ) AS a
    LEFT JOIN (${sqlNetworkInterfaces()}) AS b
      ON b.network_interface_mac_address = a.value
    WHERE a.key NOT LIKE ANY (
          ARRAY[
            '%host_name%'
          ]
        )
    ORDER BY a.key;`;

  const sqlGetVariables = `
    SELECT
      a.variable_source_uuid,
      NULL AS placeholder1,
      a.variable_name,
      a.variable_value,
      NULL AS placeholder2
    FROM (${sqlVariables()}) AS a
    WHERE
        a.variable_source_uuid IN (${hostUuidsCsv})
      AND
        a.variable_name LIKE ANY (
          ARRAY[
            'install-target::enabled',
            'network::ntp::servers',
            'system::configured'
          ]
        )
    ORDER BY a.variable_name;`;

  const sqlGetDrbdResources = `
    SELECT
      a.scan_drbd_resource_uuid,
      a.scan_drbd_resource_host_uuid,
      a.scan_drbd_resource_name,
      c.scan_drbd_peer_connection_state,
      c.scan_drbd_peer_local_disk_state,
      c.scan_drbd_peer_estimated_time_to_sync,
      d.server_uuid,
      a.scan_drbd_resource_xml LIKE CONCAT(
        '%', e.host_short_name, '%'
      ) AS server_configured,
      c.scan_drbd_peer_estimated_time_to_sync > 0 AS server_replicating,
      d.server_host_uuid = a.scan_drbd_resource_host_uuid AS server_running
    FROM (${sqlScanDrbdResources()}) AS a
    LEFT JOIN (${sqlScanDrbdVolumes()}) AS b
      ON b.scan_drbd_volume_scan_drbd_resource_uuid = a.scan_drbd_resource_uuid
    LEFT JOIN (${sqlScanDrbdPeers()}) AS c
      ON c.scan_drbd_peer_scan_drbd_volume_uuid = b.scan_drbd_volume_uuid
    LEFT JOIN (${sqlServers()}) AS d
      ON d.server_name = a.scan_drbd_resource_name
    LEFT JOIN (${sqlHosts()}) AS e
      ON e.host_uuid = a.scan_drbd_resource_host_uuid
    WHERE a.scan_drbd_resource_host_uuid IN (${hostUuidsCsv})
    ORDER BY a.scan_drbd_resource_name;`;

  const sqlGetDrbdSummary = `
    SELECT
      a.scan_drbd_peer_host_uuid,
      COUNT(a.scan_drbd_peer_uuid) AS number_of_peers,
      SUM(
        CAST(a.scan_drbd_peer_connection_state = 'off' AS int)
      ) AS connection_off,
      SUM(
        CAST(a.scan_drbd_peer_local_disk_state = 'uptodate' AS int)
      ) AS local_disk_uptodate,
      SUM(
        CAST(a.scan_drbd_peer_disk_state = 'uptodate' AS int)
      ) AS peer_disk_uptodate,
      MAX(
        a.scan_drbd_peer_estimated_time_to_sync
      ) AS max_estimated_time_to_sync
    FROM (${sqlScanDrbdPeers()}) AS a
    WHERE a.scan_drbd_peer_host_uuid IN (${hostUuidsCsv})
    GROUP BY a.scan_drbd_peer_host_uuid;`;

  const sqlGetVgTotals = `
    SELECT
      a.scan_lvm_vg_host_uuid,
      SUM(a.scan_lvm_vg_free) AS total_free,
      SUM(a.scan_lvm_vg_size) AS total_size,
      SUM(
        a.scan_lvm_vg_size - a.scan_lvm_vg_free
      ) AS total_used
    FROM (${sqlScanLvmVgs()}) AS a
    WHERE a.scan_lvm_vg_host_uuid IN (${hostUuidsCsv})
    GROUP BY a.scan_lvm_vg_host_uuid;`;

  const sqlGetVgs = `
    SELECT
      a.scan_lvm_vg_uuid,
      a.scan_lvm_vg_host_uuid,
      a.scan_lvm_vg_internal_uuid,
      a.scan_lvm_vg_name,
      a.scan_lvm_vg_size,
      a.scan_lvm_vg_free
    FROM (${sqlScanLvmVgs()}) AS a
    WHERE a.scan_lvm_vg_host_uuid IN (${hostUuidsCsv})
    ORDER BY a.scan_lvm_vg_name;`;

  let results: QueryResult[];

  try {
    results = await queries(
      sqlListAllHosts,
      sqlGetIfaces,
      sqlGetSaved,
      sqlGetVariables,
      sqlGetDrbdResources,
      sqlGetDrbdSummary,
      sqlGetVgTotals,
      sqlGetVgs,
    );
  } catch (error) {
    perr(`Failed to get host detail data; CAUSE: ${error}`);

    throw error;
  }

  const [
    allHostRows,
    ifaceRows,
    savedRows,
    variableRows,
    drbdResourceRows,
    drbdSummaryRows,
    vgTotalRows,
    vgRows,
  ] = results;

  const mapToLatestHostUuid: Record<string, string> = {};

  allHostRows.forEach((row) => {
    const [name, uuid] = row as string[];

    mapToLatestHostUuid[name] = uuid;
  });

  const counts: Record<string, number> = {};

  ifaceRows.forEach((row) => {
    const [
      uuid,
      hostUuid,
      mac,
      type,
      sequence,
      link,
      ip,
      subnetMask,
      gateway,
      defaultGateway,
      dns,
    ] = row as string[];

    const { [hostUuid]: host } = hosts;

    if ([host, type, sequence, link].some((v) => !v)) {
      return;
    }

    const { netconf } = host;

    const alias = `${type}${sequence}`;

    // 1st, set the network's values
    Object.entries({
      ip,
      [`${link}MacToSet`]: mac,
      [`${link}Uuid`]: uuid,
      sequence: Number(sequence),
      subnetMask,
      type,
    }).forEach((entry) => {
      const [k, v] = entry;

      if (!v) {
        return;
      }

      setChain([alias, k], v, netconf.networks);
    });

    // 2nd, accumulate the network count
    counts[type] = (counts[type] ?? 0) + 1;

    // 3rd, set the host's gateway
    if (defaultGateway === '1') {
      netconf.dns = dns;
      netconf.gateway = gateway;
      netconf.gatewayInterface = alias;
    }
  });

  poutvar(hosts, 'After getting network interfaces; hosts=');

  [...savedRows, ...variableRows].forEach((row) => {
    const [hostUuid = '', hostName = '', key, original, ifaceUuid] =
      row as string[];

    /**
     * The newest host_uuid (based on modified_date), or fallback to the
     * host_uuid attached to the job or variable record.
     *
     * There are 4 possible scenarios involving the host_uuid and host_name:
     *
     * 1. `uuid` and `name` combined matches a record on the `hosts` table: this is usually either the host hasn't changed **or** it's being rebuilt without changing the motherboard. Simply load the saved values.
     *
     * 2. `name` exists in the `hosts` table, but `uuid` changed: this is usually rebuilding the host **with** changing the motherboard. All saved values would be attached to the previous `uuid`, thus we need to connect the saved values to the new `uuid`.
     *
     * 3. `uuid` exists in the `hosts` table, but `name` changed: dunno what this is, but we can just fallback to use the existing `uuid` because we won't find the new `name`.
     *
     * 4. `uuid` and `name` combined doesn't exist in the `hosts` table: this is usually a new host, we won't be able to find any saved values because there's no common identifier.
     *
     * The host UUID from the records could be outdated because we're looking at
     * the most recent saved values, which would be from a deleted host in the
     * replacement scenario. Hence, we need to find the latest host UUID based
     * on the host name.
     */
    const currentHostUuid = mapToLatestHostUuid[hostName] ?? hostUuid;

    const { [currentHostUuid]: host } = hosts;

    if ([host, key].some((v) => !v)) {
      return;
    }

    const [prefix, ...parts] = key.split('::');

    const params = setvarParams[prefix]?.call(null, parts, original);

    if (!params) {
      return;
    }

    const [chain, value] = params;

    setChain(chain, value, host);

    // Set the network interface UUID based on a previously used MAC
    if (!/mac_to_set/.test(key)) {
      return;
    }

    const last = chain.pop();

    if (!last) {
      return;
    }

    const tail = last.replace('MacToSet', 'Uuid');

    chain.push(tail);

    setChain(chain, ifaceUuid, host);

    const matches = key.match(regexps.network.id);

    if (!matches) {
      return;
    }

    const [, type, sequence] = matches;

    const alias = `${type}${sequence}`;

    Object.entries({
      sequence: Number(sequence),
      type,
    }).forEach((entry) => {
      const [k, v] = entry;

      if (!v) {
        return;
      }

      setChain([alias, k], v, host.netconf.networks);
    });
  });

  poutvar(hosts, 'After getting variables; hosts=');

  drbdResourceRows.forEach((row) => {
    const [
      resourceUuid,
      hostUuid,
      resourceName,
      connectionState,
      localDiskState,
      estimatedTimeToSync,
      serverUuid,
      configured,
      replicating,
      running,
    ] = row as string[];

    const { [hostUuid]: host } = hosts;

    if (!host) {
      return;
    }

    host.drbdResources[resourceUuid] = {
      connection: {
        state: connectionState,
      },
      name: resourceName,
      replication: {
        estimatedTimeToSync: Number(estimatedTimeToSync),
        state: localDiskState,
      },
      uuid: resourceUuid,
    };

    if (!serverUuid) {
      return;
    }

    const { servers } = host;

    servers.all[serverUuid] = {
      name: resourceName,
      uuid: serverUuid,
    };

    if (configured) {
      servers.configured.push(serverUuid);
    }

    if (replicating) {
      servers.replicating.push(serverUuid);
    }

    if (running) {
      servers.running.push(serverUuid);
    }
  });

  drbdSummaryRows.forEach((row) => {
    const [
      hostUuid,
      numPeers,
      numConnectionOff,
      numLocalDiskUptodate,
      numPeerDiskUptodate,
      maxEstimatedTimeToSync,
    ] = row as number[];

    const { [hostUuid]: host } = hosts;

    if (!host || !numPeers) {
      return;
    }

    const { drbd } = host.status;

    if (numConnectionOff === numPeers) {
      drbd.status = 'offline';
    } else if (maxEstimatedTimeToSync > 0) {
      drbd.maxEstimatedTimeToSync = maxEstimatedTimeToSync;
      drbd.status = 'syncing';
    } else if (numLocalDiskUptodate + numPeerDiskUptodate === numPeers * 2) {
      drbd.status = 'optimal';
    } else {
      drbd.status = 'degraded';
    }
  });

  vgTotalRows.forEach((row) => {
    const [hostUuid, free, size, used] = row as string[];

    const { [hostUuid]: host } = hosts;

    if (!host) {
      return;
    }

    host.storage.volumeGroupTotals = {
      free,
      size,
      used,
    };
  });

  vgRows.forEach((row) => {
    const [uuid, hostUuid, internalUuid, name, size, free] = row as string[];

    let vgnUsed: bigint;

    try {
      const vgnFree = BigInt(free);
      const vgnSize = BigInt(size);

      vgnUsed = vgnSize - vgnFree;
    } catch (error) {
      perr(
        `Failed to calculate host volume group sizes, skipping; CAUSE: ${error}`,
      );

      return;
    }

    const { [hostUuid]: host } = hosts;

    if (!host) {
      return;
    }

    host.storage.volumeGroups[uuid] = {
      free,
      host: hostUuid,
      internalUuid,
      name,
      size,
      used: String(vgnUsed),
      uuid,
    };
  });

  // Do a simple test on all networks and drop the failing ones

  Object.keys(hosts).forEach((uuid) => {
    const { [uuid]: host } = hosts;

    const { networks } = host.netconf;

    Object.keys(networks).forEach((id) => {
      const { [id]: network } = networks;

      if (network.type && network.sequence) {
        return;
      }

      delete networks[id];
    });
  });

  return hosts;
};
