import type { CryptoContext } from './types';
export const initializeCrypto = async (): Promise<CryptoContext> => {
    let cryptoAPI: CryptoContext;
    
    if (typeof globalThis.crypto !== 'undefined') {
      cryptoAPI = {
        crypto: globalThis.crypto,
        CryptoKey: globalThis.CryptoKey || null
      };
    } else if (typeof globalThis.require === 'function') {
      const { webcrypto } = await import('crypto');
      cryptoAPI = {
        crypto: webcrypto as Crypto,
        CryptoKey: null
      };
    } else {
      throw new Error('Crypto API is not available in this environment');
    }
    
    return cryptoAPI;
  };
  

