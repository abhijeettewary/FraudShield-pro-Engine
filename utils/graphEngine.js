function buildFraudGraph(transactions = [], ledgerEntries = []) {
  const nodesMap = new Map();
  const edges = [];

  // Tracking structures for network algorithms
  const deviceToAccounts = new Map(); // deviceId -> Set(account)
  const incomingSenders = new Map();  // receiver -> Set(sender)
  const outgoingReceivers = new Map(); // sender -> Set(receiver)
  const adjacency = new Map();        // sender -> Set(receiver) for cycle detection
  const accountStats = new Map();     // account -> { txCount, fraudCount, totalVolume }

  function ensureAccountNode(accId, label) {
    if (!accId) return;
    if (!nodesMap.has(accId)) {
      nodesMap.set(accId, {
        id: accId,
        label: label || accId,
        type: 'account',
        riskLevel: 'normal',
        details: { txCount: 0, fraudCount: 0, totalVolume: 0, linkedDevices: new Set() }
      });
    }
    if (!accountStats.has(accId)) {
      accountStats.set(accId, { txCount: 0, fraudCount: 0, totalVolume: 0 });
    }
  }

  function ensureDeviceNode(devId) {
    if (!devId || devId === 'DEV-UNKNOWN') return;
    if (!nodesMap.has(devId)) {
      nodesMap.set(devId, {
        id: devId,
        label: devId,
        type: 'device',
        riskLevel: 'normal',
        details: { linkedAccounts: new Set(), fraudHits: 0 }
      });
    }
  }

  // 1. Ingest FraudShield Transactions (Account <-> Device relationships)
  transactions.forEach((tx) => {
    const acc = tx.userId;
    const dev = tx.deviceId;
    ensureAccountNode(acc);

    const st = accountStats.get(acc);
    st.txCount += 1;
    st.totalVolume += Number(tx.amount) || 0;
    if (tx.status === 'Fraudulent') st.fraudCount += 1;

    if (dev && dev !== 'DEV-UNKNOWN') {
      ensureDeviceNode(dev);
      if (!deviceToAccounts.has(dev)) deviceToAccounts.set(dev, new Set());
      deviceToAccounts.get(dev).add(acc);

      nodesMap.get(acc).details.linkedDevices.add(dev);
      nodesMap.get(dev).details.linkedAccounts.add(acc);
      if (tx.status === 'Fraudulent') nodesMap.get(dev).details.fraudHits += 1;
    }
  });

  // Add Account <-> Device edges
  deviceToAccounts.forEach((accounts, devId) => {
    accounts.forEach((accId) => {
      edges.push({
        from: accId,
        to: devId,
        label: 'uses',
        type: 'device_link',
        dashes: true
      });
    });
  });

  // 2. Ingest Atomic Ledger Transfers (Account -> Account money flow)
  const transferEdgeAgg = new Map();
  ledgerEntries
    .filter((e) => e.type === 'DEBIT')
    .forEach((e) => {
      const from = e.accountNumber;
      const to = e.counterpartyAccount;
      ensureAccountNode(from);
      ensureAccountNode(to, `${e.counterpartyName}\n(${to})`);

      if (!incomingSenders.has(to)) incomingSenders.set(to, new Set());
      incomingSenders.get(to).add(from);

      if (!outgoingReceivers.has(from)) outgoingReceivers.set(from, new Set());
      outgoingReceivers.get(from).add(to);

      if (!adjacency.has(from)) adjacency.set(from, new Set());
      adjacency.get(from).add(to);

      const key = `${from}->${to}`;
      const prev = transferEdgeAgg.get(key) || { from, to, count: 0, total: 0 };
      prev.count += 1;
      prev.total += Number(e.amount) || 0;
      transferEdgeAgg.set(key, prev);
    });

  transferEdgeAgg.forEach((agg) => {
    edges.push({
      from: agg.from,
      to: agg.to,
      label: `₹${agg.total.toLocaleString('en-IN')} (${agg.count}x)`,
      type: 'transfer',
      arrows: 'to'
    });
  });

  // 3. Detect Suspicious Network Patterns
  const alerts = [];
  let deviceRingCount = 0;
  let muleCount = 0;
  let circularCount = 0;

  // Pattern A: Shared-Device Fraud Rings (2+ accounts on 1 device)
  deviceToAccounts.forEach((accounts, devId) => {
    if (accounts.size >= 2) {
      deviceRingCount++;
      const accList = Array.from(accounts);
      const severity = accounts.size >= 3 ? 'high' : 'medium';
      nodesMap.get(devId).riskLevel = severity;
      accList.forEach((a) => {
        if (nodesMap.get(a).riskLevel !== 'high') nodesMap.get(a).riskLevel = severity;
      });
      alerts.push({
        type: 'DEVICE_FRAUD_RING',
        severity,
        title: `Shared Device Ring (${devId})`,
        description: `${accounts.size} accounts (${accList.join(', ')}) operated from the same device.`,
        entities: [devId, ...accList]
      });
    }
  });

  // Pattern B: Money Mule Collectors (Fan-In: 2+ distinct senders -> 1 account)
  incomingSenders.forEach((senders, receiver) => {
    if (senders.size >= 2) {
      muleCount++;
      nodesMap.get(receiver).riskLevel = 'high';
      alerts.push({
        type: 'MONEY_MULE_COLLECTOR',
        severity: 'high',
        title: `Suspected Money Mule (${receiver})`,
        description: `Account received funds from ${senders.size} distinct accounts (${Array.from(senders).join(', ')}).`,
        entities: [receiver, ...Array.from(senders)]
      });
    }
  });

  // Pattern C: Pass-Through / Rapid Distribution (Fan-In + Fan-Out)
  outgoingReceivers.forEach((receivers, sender) => {
    const inCount = incomingSenders.get(sender)?.size || 0;
    if (inCount >= 1 && receivers.size >= 2) {
      muleCount++;
      nodesMap.get(sender).riskLevel = 'high';
      alerts.push({
        type: 'MULE_DISTRIBUTOR',
        severity: 'high',
        title: `Rapid Fund Distributor (${sender})`,
        description: `Received funds and distributed them to ${receivers.size} separate destinations.`,
        entities: [sender, ...Array.from(receivers)]
      });
    }
  });

  // Pattern D: Circular Money Transfers (DFS Cycle Detection: A -> B -> ... -> A)
  const visitedCycles = new Set();
  function findCycles(start, current, path, visited) {
    if (path.length > 4) return; // Check cycles up to 4 hops
    const neighbors = adjacency.get(current);
    if (!neighbors) return;

    for (const next of neighbors) {
      if (next === start && path.length >= 2) {
        const cycleKey = [...path].sort().join('|');
        if (!visitedCycles.has(cycleKey)) {
          visitedCycles.add(cycleKey);
          circularCount++;
          path.forEach((acc) => {
            if (nodesMap.has(acc)) nodesMap.get(acc).riskLevel = 'high';
          });
          alerts.push({
            type: 'CIRCULAR_TRANSFER',
            severity: 'high',
            title: `Circular Transfer Loop (${path.length} hops)`,
            description: `Funds cycled through: ${[...path, start].join(' → ')}.`,
            entities: [...path]
          });
        }
      } else if (!visited.has(next)) {
        visited.add(next);
        findCycles(start, next, [...path, next], visited);
        visited.delete(next);
      }
    }
  }

  adjacency.forEach((_, acc) => findCycles(acc, acc, [acc], new Set([acc])));

  // Serialize nodes for frontend
  const nodes = Array.from(nodesMap.values()).map((n) => {
    if (n.type === 'account') {
      const st = accountStats.get(n.id) || { txCount: 0, fraudCount: 0, totalVolume: 0 };
      if (st.fraudCount > 0 && n.riskLevel === 'normal') n.riskLevel = 'medium';
      return {
        id: n.id,
        label: n.label,
        type: 'account',
        riskLevel: n.riskLevel,
        meta: {
          txCount: st.txCount,
          fraudCount: st.fraudCount,
          totalVolume: st.totalVolume,
          linkedDevices: Array.from(n.details.linkedDevices)
        }
      };
    }
    return {
      id: n.id,
      label: n.label,
      type: 'device',
      riskLevel: n.riskLevel,
      meta: {
        linkedAccounts: Array.from(n.details.linkedAccounts),
        fraudHits: n.details.fraudHits
      }
    };
  });

  return {
    summary: {
      totalNodes: nodes.length,
      totalEdges: edges.length,
      deviceRingCount,
      muleCount,
      circularCount
    },
    nodes,
    edges,
    alerts
  };
}

module.exports = { buildFraudGraph };