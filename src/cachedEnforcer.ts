// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import { Enforcer, NewEnforcerParams, newEnforcerWithClass } from './enforcer';

// DEFAULT_CACHE_SIZE is the number of decisions a cached enforcer keeps by default.
export const DEFAULT_CACHE_SIZE = 100000;

// CachedEnforcer wraps Enforcer and provides decision cache
export class CachedEnforcer extends Enforcer {
  private enableCache = true;
  private m = new Map<string, boolean>();
  private maxCacheSize = DEFAULT_CACHE_SIZE;
  // cacheVersion is the policy version the cached decisions were made with.
  private cacheVersion = -1;

  // invalidateCache deletes all the existing cached decisions.
  public invalidateCache(): void {
    this.m = new Map<string, boolean>();
  }

  // setEnableCache determines whether to enable cache on e nforce(). When enableCache is enabled, cached result (true | false) will be returned for previous decisions.
  public setEnableCache(enableCache: boolean): void {
    this.enableCache = enableCache;
  }

  // setCacheSize sets how many decisions are kept at most. Zero or less means no limit.
  // When the cache is full, adding a new decision empties it first.
  public setCacheSize(size: number): void {
    this.maxCacheSize = size;
  }

  // getCacheSize returns the number of cached decisions.
  public getCacheSize(): number {
    return this.m.size;
  }

  private static canCache(...rvals: any[]): boolean {
    return rvals.every((n) => typeof n === 'string');
  }

  // getCacheKey length-prefixes each value so that different requests never share a key.
  private static getCacheKey(...rvals: string[]): string {
    return rvals.map((n) => `${n.length}:${n}`).join('');
  }

  private getCache(key: string): boolean | undefined {
    return this.m.get(key);
  }

  private setCache(key: string, value: boolean): void {
    if (this.maxCacheSize > 0 && this.m.size >= this.maxCacheSize && !this.m.has(key)) {
      this.invalidateCache();
    }
    this.m.set(key, value);
  }

  // syncCacheVersion drops all cached decisions when the policy has changed since they were cached.
  private syncCacheVersion(version: number): void {
    if (version !== this.cacheVersion) {
      this.invalidateCache();
      this.cacheVersion = version;
    }
  }

  // enforce decides whether a "subject" can access a "object" with the operation "action", input parameters are usually: (sub, obj, act).
  // if rvals is not string , ingore the cache
  public async enforce(...rvals: any[]): Promise<boolean> {
    if (!this.enableCache || !this.enabled) {
      return super.enforce(...rvals);
    }

    const version = this.getPolicyVersion();
    this.syncCacheVersion(version);

    let key = '';
    const cache = CachedEnforcer.canCache(...rvals);

    if (cache) {
      key = CachedEnforcer.getCacheKey(...rvals);
      const res = this.getCache(key);

      if (res !== undefined) {
        return res;
      }
    }

    const res = await super.enforce(...rvals);

    // A decision made while the policy changed may be outdated, so it is not cached.
    if (cache && version === this.getPolicyVersion()) {
      this.setCache(key, res);
    }

    return res;
  }
}

// newCachedEnforcer creates a cached enforcer via file or DB.
export async function newCachedEnforcer(...params: NewEnforcerParams): Promise<CachedEnforcer> {
  return newEnforcerWithClass(CachedEnforcer, ...params);
}
