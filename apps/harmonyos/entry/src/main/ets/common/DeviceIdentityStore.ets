
import { cryptoFramework } from '@kit.CryptoArchitectureKit';
import { util } from '@kit.ArkTS';
import { common } from '@kit.AbilityKit';
import { fileIo as fs } from '@kit.CoreFileKit';

export interface DeviceIdentity {
  deviceId: string;
  publicKeyRawBase64: string;
  privateKeyPkcs8Base64: string;
  createdAtMs: number;
}

export class DeviceIdentityStore {
  private context: common.Context;
  private identityPath: string;
  private base64 = new util.Base64Helper();
  private encoder = util.TextEncoder.create('utf-8');

  constructor(context: common.Context) {
    this.context = context;
    this.identityPath = this.context.filesDir + '/openclaw/identity/device.json';
  }

  public async loadOrCreate(): Promise<DeviceIdentity> {
    const existing = await this.load();
    if (existing) {
      return existing;
    }
    const fresh = await this.generate();
    await this.save(fresh);
    return fresh;
  }

  public async signPayload(payload: string, identity: DeviceIdentity): Promise<string | undefined> {
    try {
      const priKeyData = this.base64.decodeSync(identity.privateKeyPkcs8Base64);
      const asyKeyGenerator = cryptoFramework.createAsyKeyGenerator('Ed25519');
      const keyPair = await asyKeyGenerator.convertKey(null, { data: priKeyData });
      
      const signer = cryptoFramework.createSign('Ed25519');
      await signer.init(keyPair.priKey);
      const payloadData = this.encoder.encode(payload);
      const signature = await signer.sign({ data: payloadData });
      
      return this.base64UrlEncode(signature.data);
    } catch (e) {
      console.error('DeviceIdentityStore', `signPayload FAILED: ${e instanceof Error ? e.message : String(e)}`);
      return undefined;
    }
  }

  public publicKeyBase64Url(identity: DeviceIdentity): string | undefined {
    try {
      const raw = this.base64.decodeSync(identity.publicKeyRawBase64);
      return this.base64UrlEncode(raw);
    } catch (e) {
      return undefined;
    }
  }

  private async load(): Promise<DeviceIdentity | undefined> {
    try {
      if (!fs.accessSync(this.identityPath)) return undefined;
      const contentStr = fs.readTextSync(this.identityPath);
      if (!contentStr) return undefined;

      const decoded = JSON.parse(contentStr) as DeviceIdentity;
      if (!decoded.deviceId || !decoded.publicKeyRawBase64 || !decoded.privateKeyPkcs8Base64) {
        return undefined;
      }
      return decoded;
    } catch (e) {
      console.error('DeviceIdentityStore', `load FAILED: ${e instanceof Error ? e.message : String(e)}`);
      return undefined;
    }
  }

  private async save(identity: DeviceIdentity): Promise<void> {
    try {
      const dir = this.identityPath.substring(0, this.identityPath.lastIndexOf('/'));
      if (!fs.accessSync(dir)) {
        this.mkdirRecursive(dir);
      }
      const encoded = JSON.stringify(identity);
      let file = fs.openSync(this.identityPath, fs.OpenMode.READ_WRITE | fs.OpenMode.CREATE | fs.OpenMode.TRUNC);
      fs.writeSync(file.fd, encoded);
      fs.closeSync(file);
    } catch (e) {
      console.error('DeviceIdentityStore', `save FAILED: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async generate(): Promise<DeviceIdentity> {
    const asyKeyGenerator = cryptoFramework.createAsyKeyGenerator('Ed25519');
    const keyPair = await asyKeyGenerator.generateKeyPair();
    
    // Export keys
    try {
      const pubKeyData = keyPair.pubKey.getEncoded();
      const priKeyData = keyPair.priKey.getEncoded();
      
      let rawPublicBytes = pubKeyData.data;
      if (rawPublicBytes.length === 44) {
        rawPublicBytes = rawPublicBytes.subarray(12);
      }
      
      const deviceId = await this.sha256Hex(rawPublicBytes);
      
      return {
        deviceId: deviceId,
        publicKeyRawBase64: this.base64.encodeToStringSync(rawPublicBytes),
        privateKeyPkcs8Base64: this.base64.encodeToStringSync(priKeyData.data),
        createdAtMs: Date.now()
      };
    } catch (e) {
      throw new Error(`Failed to generate identity: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  private async sha256Hex(data: Uint8Array): Promise<string> {
    try {
      const md = cryptoFramework.createMd('SHA256');
      await md.update({ data: data });
      const digest = await md.digest();
      let hex = '';
      for (let i = 0; i < digest.data.length; i++) {
          const h = digest.data[i].toString(16);
          hex += h.length === 1 ? '0' + h : h;
      }
      return hex;
    } catch (e) {
      return '';
    }
  }

  private base64UrlEncode(data: Uint8Array): string {
    const str = this.base64.encodeToStringSync(data);
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  }

  private mkdirRecursive(path: string): void {
    if (fs.accessSync(path)) return;
    const parent = path.substring(0, path.lastIndexOf('/'));
    if (parent && !fs.accessSync(parent)) {
      this.mkdirRecursive(parent);
    }
    fs.mkdirSync(path);
  }
}
