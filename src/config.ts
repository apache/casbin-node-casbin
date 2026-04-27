// Copyright 2018 The Casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import { FileSystem, mustGetDefaultFileSystem } from './persist';
import { ValidatorEnforcer } from './validatorEnforcer';

// ConfigInterface defines the behavior of a Config implementation
export interface ConfigInterface {
  getString(key: string): string;

  getStrings(key: string): string[];

  getBool(key: string): boolean;

  getInt(key: string): number;

  getFloat(key: string): number;

  set(key: string, value: string): void;
}

export class Config implements ConfigInterface {
  private static DEFAULT_SECTION = 'default';
  private static DEFAULT_COMMENT = '#';
  private static DEFAULT_COMMENT_SEM = ';';
  private static DEFAULT_MULTI_LINE_SEPARATOR = '\\';

  private data: Map<string, Map<string, string>>;

  private readonly fs?: FileSystem;

  private constructor(fs?: FileSystem) {
    this.data = new Map<string, Map<string, string>>();
    if (fs) {
      this.fs = fs;
    }
  }

  /**
   * newConfig create an empty configuration representation from file.
   *
   * @param confName the path of the model file.
   * @return the constructor of Config.
   * @deprecated use {@link newConfigFromFile} instead.
   */
  public static newConfig(confName: string): Config {
    return this.newConfigFromFile(confName);
  }

  /**
   * newConfigFromFile create an empty configuration representation from file.
   * @param path the path of the model file.
   * @param fs {@link FileSystem}
   */
  public static newConfigFromFile(path: string, fs?: FileSystem): Config {
    const config = new Config(fs);
    config.parse(path);
    return config;
  }

  /**
   * newConfigFromText create an empty configuration representation from text.
   *
   * @param text the model text.
   * @return the constructor of Config.
   */
  public static newConfigFromText(text: string): Config {
    const config = new Config();
    config.parseBuffer(Buffer.from(text));
    return config;
  }

  /**
   * addConfig adds a new section->key:value to the configuration.
   */
  private addConfig(section: string, option: string, value: string): boolean {
    if (section === '') {
      section = Config.DEFAULT_SECTION;
    }
    const hasKey = this.data.has(section);
    if (!hasKey) {
      this.data.set(section, new Map<string, string>());
    }

    const item = this.data.get(section);
    if (item) {
      item.set(option, value);
      return item.has(option);
    } else {
      return false;
    }
  }

  private parse(path: string): void {
    const body = (this.fs ? this.fs : mustGetDefaultFileSystem()).readFileSync(path);
    this.parseBuffer(Buffer.isBuffer(body) ? body : Buffer.from(body));
  }

  private parseBuffer(buf: Buffer): void {
    const lines = buf
      .toString()
      .split('\n')
      .filter((v) => v);
    const linesCount = lines.length;
    let section = '';
    let currentLine = '';
    const seenSections = new Set<string>();

    lines.forEach((n, index) => {
      let commentPos = n.indexOf(Config.DEFAULT_COMMENT);
      if (commentPos > -1) {
        n = n.slice(0, commentPos);
      }
      commentPos = n.indexOf(Config.DEFAULT_COMMENT_SEM);
      if (commentPos > -1) {
        n = n.slice(0, commentPos);
      }

      const line = n.trim();
      if (!line) {
        return;
      }

      const lineNumber = index + 1;

      if (line.startsWith('[') && line.endsWith(']')) {
        if (currentLine.length !== 0) {
          this.write(section, lineNumber - 1, currentLine);
          currentLine = '';
        }
        section = line.substring(1, line.length - 1);
        if (seenSections.has(section)) {
          ValidatorEnforcer.validateDuplicateSection(section, lineNumber);
        }
        seenSections.add(section);
      } else {
        let shouldWrite = false;
        if (line.endsWith(Config.DEFAULT_MULTI_LINE_SEPARATOR)) {
          currentLine += line.substring(0, line.length - 1).trim();
        } else {
          currentLine += line;
          shouldWrite = true;
        }
        if (shouldWrite || lineNumber === linesCount) {
          this.write(section, lineNumber, currentLine);
          currentLine = '';
        }
      }
    });
  }

  private write(section: string, lineNum: number, line: string): void {
    const equalIndex = line.indexOf('=');
    if (equalIndex === -1) {
      ValidatorEnforcer.validateContentParse(lineNum);
    }
    const key = line.substring(0, equalIndex).trim();
    const value = line.substring(equalIndex + 1).trim();

    if (section === 'matchers') {
      ValidatorEnforcer.validateMatcher(value);
    }

    this.addConfig(section, key, value);
  }

  public getBool(key: string): boolean {
    return !!this.get(key);
  }

  public getInt(key: string): number {
    return Number.parseInt(this.get(key), 10);
  }

  public getFloat(key: string): number {
    return Number.parseFloat(this.get(key));
  }

  public getString(key: string): string {
    return this.get(key);
  }

  public getStrings(key: string): string[] {
    const v = this.get(key);
    return v.split(',');
  }

  public set(key: string, value: string): void {
    if (!key) {
      ValidatorEnforcer.validateEmptyKey();
    }

    let section = '';
    let option;

    const keys = key.toLowerCase().split('::');
    if (keys.length >= 2) {
      section = keys[0];
      option = keys[1];
    } else {
      option = keys[0];
    }

    this.addConfig(section, option, value);
  }

  public get(key: string): string {
    let section;
    let option;

    const keys = key.toLowerCase().split('::');
    if (keys.length >= 2) {
      section = keys[0];
      option = keys[1];
    } else {
      section = Config.DEFAULT_SECTION;
      option = keys[0];
    }

    const item = this.data.get(section);
    const itemChild = item && item.get(option);

    return itemChild ? itemChild : '';
  }
}
