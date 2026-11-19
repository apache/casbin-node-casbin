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

import { EffectorStream } from './effectorStream';
import { Effect } from './effector';
import { EffectExpress } from '../constants';

/**
 * DefaultEffectorStream is the default implementation of EffectorStream.
 */
export class DefaultEffectorStream implements EffectorStream {
  private done = false;
  private res = false;
  private rec = false;
  private readonly expr: string;

  constructor(expr: string) {
    this.expr = expr;
  }

  current(): boolean {
    return this.res;
  }

  public pushEffect(eft: Effect): [boolean, boolean, boolean] {
    switch (this.expr) {
      case EffectExpress.ALLOW:
        if (eft === Effect.Allow) {
          this.res = true;
          this.done = true;
          this.rec = true;
        }
        break;
      case EffectExpress.DENY:
        this.res = true;
        if (eft === Effect.Deny) {
          this.res = false;
          this.done = true;
          this.rec = true;
        }
        break;
      case EffectExpress.ALLOW_AND_DENY:
        if (eft === Effect.Allow) {
          this.res = true;
          this.rec = true;
        } else if (eft === Effect.Deny) {
          this.res = false;
          this.done = true;
          this.rec = true;
        } else {
          this.rec = false;
        }
        break;
      case EffectExpress.PRIORITY:
      case EffectExpress.SUBJECT_PRIORITY:
        if (eft !== Effect.Indeterminate) {
          this.res = eft === Effect.Allow;
          this.done = true;
          this.rec = true;
        }
        break;
      default:
        throw new Error('unsupported effect');
    }
    return [this.res, this.rec, this.done];
  }
}
