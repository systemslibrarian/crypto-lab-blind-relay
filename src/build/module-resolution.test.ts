import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer } from 'vite';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import configuration from '../../vite.config';

describe('consumed HPKE module dependencies', () => {
  let foreign: string;
  let importer: string;
  beforeAll(async () => {
    foreign = await mkdtemp(path.join(tmpdir(), 'blind-relay-module-control-'));
    importer = path.join(foreign, 'hpke.ts');
    const nested = path.join(foreign, 'node_modules/@noble/hashes');
    await mkdir(nested, { recursive: true });
    await writeFile(importer, '');
    await writeFile(path.join(foreign, 'package.json'), JSON.stringify({
      name: 'consumed-hpke-resolution-fixture', private: true, type: 'module',
    }));
    await writeFile(path.join(nested, 'package.json'), JSON.stringify({
      name: '@noble/hashes', version: '2.4.0', type: 'module',
      exports: { './sha2.js': './sha2.js' },
    }));
    await writeFile(path.join(nested, 'sha2.js'), '// resolution fixture; never executed');
  });
  afterAll(async () => {
    if (foreign) await rm(foreign, { recursive: true, force: true });
  });

  async function resolvedIds(dedupe: string[] | undefined) {
    const server = await createServer({
      ...configuration,
      configFile: false,
      resolve: { ...configuration.resolve, dedupe },
      optimizeDeps: { noDiscovery: true, include: [] },
      server: { middlewareMode: true, hmr: false, watch: null },
    });
    try {
      const resolver = server.environments.client.pluginContainer;
      const local = await resolver.resolveId('@noble/hashes/sha2.js', path.resolve('src/ohttp/response.ts'));
      const consumed = await resolver.resolveId('@noble/hashes/sha2.js', importer);
      expect(local).not.toBeNull();
      expect(consumed).not.toBeNull();
      return { local: local!.id, consumed: consumed!.id };
    } finally {
      await server.close();
    }
  }

  it('resolves consumed source to the consumer locked package despite a nested copy', async () => {
    const result = await resolvedIds(configuration.resolve?.dedupe);
    expect(result.consumed).toBe(result.local);
    expect(result.local).not.toContain(foreign);
  });

  it('negative control resolves two module instances when deduplication is removed', async () => {
    const result = await resolvedIds([]);
    expect(result.consumed).not.toBe(result.local);
    expect(result.consumed).toContain(foreign);
  });
});
