/**
 * Zcash JSON-RPC client.
 */

export interface RpcConfig {
  url: string;
  apiKey?: string;
}

export function createRpc(config: RpcConfig) {
  let idCounter = 0;

  async function call(method: string, params: unknown[] = []): Promise<unknown> {
    const headers: Record<string, string> = {
      'accept': 'application/json',
      'content-type': 'application/json',
    };
    if (config.apiKey) {
      headers['x-api-key'] = config.apiKey;
    }

    const res = await fetch(config.url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        id: ++idCounter,
        jsonrpc: '2.0',
        method,
        params,
      }),
    });

    const json = (await res.json()) as { result?: unknown; error?: { message: string } };
    if (json.error) throw new Error(`RPC error: ${json.error.message}`);
    return json.result;
  }

  return {
    async getBlockCount(): Promise<number> {
      return (await call('getblockcount')) as number;
    },

    async getBlockHash(height: number): Promise<string> {
      return (await call('getblockhash', [height])) as string;
    },

    async getBlock(hashOrHeight: string | number): Promise<{ tx: string[]; height: number }> {
      const hash =
        typeof hashOrHeight === 'number'
          ? await this.getBlockHash(hashOrHeight)
          : hashOrHeight;
      return (await call('getblock', [hash, 1])) as { tx: string[]; height: number };
    },

    async getRawTransaction(txid: string): Promise<string> {
      return (await call('getrawtransaction', [txid, 0])) as string;
    },
  };
}
