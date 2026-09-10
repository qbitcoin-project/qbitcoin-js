import { describe, expect, it } from 'vitest';
import { balanceOf, type AddressInfo } from './types';
import { nodesFor, type NodeEndpoint } from './nodes';

describe('balanceOf', () => {
  it('returns confirmed-only when mempool is zero', () => {
    const info: AddressInfo = {
      address: 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU',
      chain: {
        fundedTxCount: 1,
        fundedSum: 500_000_000n,
        spentTxCount: 0,
        spentSum: 0n,
      },
      mempool: {
        fundedTxCount: 0,
        fundedSum: 0n,
        spentTxCount: 0,
        spentSum: 0n,
      },
      tokens: {},
    };
    expect(balanceOf(info)).toBe(500_000_000n);
  });

  it('subtracts spent sums', () => {
    const info: AddressInfo = {
      address: 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU',
      chain: {
        fundedTxCount: 2,
        fundedSum: 500_000_000n,
        spentTxCount: 1,
        spentSum: 100_000_000n,
      },
      mempool: {
        fundedTxCount: 0,
        fundedSum: 0n,
        spentTxCount: 0,
        spentSum: 0n,
      },
      tokens: {},
    };
    expect(balanceOf(info)).toBe(400_000_000n);
  });

  it('includes mempool net delta', () => {
    const info: AddressInfo = {
      address: 'vr8GF9kVrGaPRD7xCS4YDy9avFCk8N9jQtU',
      chain: {
        fundedTxCount: 1,
        fundedSum: 500_000_000n,
        spentTxCount: 0,
        spentSum: 0n,
      },
      mempool: {
        fundedTxCount: 1,
        fundedSum: 50_000_000n,
        spentTxCount: 1,
        spentSum: 200_000_000n,
      },
      tokens: {},
    };
    // confirmed 500M − 0 = +500M, mempool +50M − 200M = −150M
    // net = 350M
    expect(balanceOf(info)).toBe(350_000_000n);
  });

  it('clamps a rounding-negative total to zero', () => {
    // An emptied heavy-staking address: both cumulative sums came from
    // node-side doubles, and their difference can dip a hair below zero.
    const info: AddressInfo = {
      address: 'addr-1',
      chain: { fundedTxCount: 751_820, fundedSum: 1_541_593_943_344_830_000_000n, spentTxCount: 751_820, spentSum: 1_541_593_943_344_830_262_144n },
      mempool: { fundedTxCount: 0, fundedSum: 0n, spentTxCount: 0, spentSum: 0n },
      tokens: {},
    };
    expect(balanceOf(info)).toBe(0n);
  });
});

describe('nodesFor', () => {
  // The package ships no endpoint URLs — consumers pass their own list.
  const node = (
    name: string,
    network: 'mainnet' | 'testnet',
    priority: number,
  ): NodeEndpoint => ({
    name,
    url: `https://${name}.example`,
    protocol: 'esplora',
    network,
    operator: 'test',
    priority,
  });
  const NODES = [
    node('m-backup', 'mainnet', 2),
    node('t-primary', 'testnet', 1),
    node('m-primary', 'mainnet', 1),
  ];

  it('returns the priority-sorted subset for the network', () => {
    expect(nodesFor(NODES, 'mainnet').map((n) => n.name)).toEqual([
      'm-primary',
      'm-backup',
    ]);
    expect(nodesFor(NODES, 'testnet').map((n) => n.name)).toEqual(['t-primary']);
  });

  it('returns an empty list when nothing serves the network', () => {
    expect(nodesFor([], 'mainnet')).toEqual([]);
    expect(nodesFor([node('t', 'testnet', 1)], 'mainnet')).toEqual([]);
  });

  it('does not mutate the input list', () => {
    const input = [...NODES];
    nodesFor(input, 'mainnet');
    expect(input).toEqual(NODES);
  });
});
