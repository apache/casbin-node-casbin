import { Adapter } from './adapter';
import { Model } from '../model';
import { Helper } from './helper';
import { arrayToString } from '../util';
import { FileSystem, mustGetDefaultFileSystem } from './fileSystem';

/**
 * FileAdapter is the file adapter for Casbin.
 * It can load policy from file or save policy to file.
 */
export class FileAdapter implements Adapter {
  public readonly filePath: string;
  protected readonly fs?: FileSystem;

  /**
   * FileAdapter is the constructor for FileAdapter.
   *
   * @param filePath filePath the path of the policy file.
   * @param fs {@link FileSystem}
   */
  constructor(filePath: string, fs?: FileSystem) {
    this.filePath = filePath;
    this.fs = fs;
  }

  public async loadPolicy(model: Model): Promise<void> {
    if (!this.filePath) {
      // throw new Error('invalid file path, file path cannot be empty');
      return;
    }
    await this.loadPolicyFile(model, Helper.loadPolicyLine);
  }

  private async loadPolicyFile(model: Model, handler: (line: string, model: Model) => void): Promise<void> {
    const bodyBuf = await (this.fs ? this.fs : mustGetDefaultFileSystem()).readFileSync(this.filePath);
    const lines = bodyBuf.toString().split('\n');
    lines.forEach((line: string) => {
      if (!line || line.trim().startsWith('#')) {
        return;
      }
      handler(line, model);
    });
  }

  /**
   * savePolicy saves all policy rules to the storage.
   */
  public async savePolicy(model: Model): Promise<boolean> {
    if (!this.filePath) {
      // throw new Error('invalid file path, file path cannot be empty');
      return false;
    }
    let result = '';

    const pList = model.model.get('p');
    if (pList) {
      pList.forEach((n) => {
        n.policy.forEach((m) => {
          result += n.key + ', ';
          result += arrayToString(m);
          result += '\n';
        });
      });
    }

    const gList = model.model.get('g');
    if (gList) {
      gList.forEach((n) => {
        n.policy.forEach((m) => {
          result += n.key + ', ';
          result += arrayToString(m.map((element) => this.escapeCsv(element)));
          result += '\n';
        });
      });
    }

    await this.savePolicyFile(result.trim());
    return true;
  }

  private escapeCsv(value: string): string {
    // If the value contains a comma, wrap it in double quotes and escape any existing double quotes
    if (value.includes(',')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  }

  private async savePolicyFile(text: string): Promise<void> {
    (this.fs ? this.fs : mustGetDefaultFileSystem()).writeFileSync(this.filePath, text);
  }

  /**
   * addPolicy adds a policy rule to the storage.
   */
  public async addPolicy(sec: string, ptype: string, rule: string[]): Promise<void> {
    throw new Error('not implemented');
  }
  /**
   * addPolicies adds policy rules to the storage.
   This is part of the Auto-Save feature.
   */
  public async addPolicies(sec: string, ptype: string, rules: string[][]): Promise<void> {
    throw new Error('not implemented');
  }

  /**
   * UpdatePolicy updates a policy rule from storage.
   * This is part of the Auto-Save feature.
   */
  updatePolicy(sec: string, ptype: string, oldRule: string[], newRule: string[]): Promise<void> {
    throw new Error('not implemented');
  }

  /**
   * removePolicy removes a policy rule from the storage.
   */
  public async removePolicy(sec: string, ptype: string, rule: string[]): Promise<void> {
    throw new Error('not implemented');
  }

  /**
   * removePolicies removes policy rules from the storage.
   * This is part of the Auto-Save feature.
   */
  public async removePolicies(sec: string, ptype: string, rules: string[][]): Promise<void> {
    throw new Error('not implemented');
  }

  /**
   * removeFilteredPolicy removes policy rules that match the filter from the storage.
   */
  public async removeFilteredPolicy(sec: string, ptype: string, fieldIndex: number, ...fieldValues: string[]): Promise<void> {
    throw new Error('not implemented');
  }
}
