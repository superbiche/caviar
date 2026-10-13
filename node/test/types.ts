// SPDX-License-Identifier: AGPL-3.0-only
import {Client,Pool,CaviarError, type Json, type Result} from '../lib/index.js';
const c = new Client(new Uint8Array(32));
const p = new Pool(null,2,{allowPlain:true,acquireTimeout:0});
const t: Promise<Result<string>> = c.string('ordinary');
const value: Json = {ordinary:9007199254740993n};
const v: Promise<Result> = p.value(value);
const closed: Promise<void> = c.close();
const code: string = new CaviarError('closed').code;
// @ts-expect-error string() does not accept structured input
c.string({ordinary:true});
// @ts-expect-error caller must opt into byte keys, not strings
new Client('key');
// @ts-expect-error Pool admission timeout is required
new Pool(null,2,{});
void [t,v,closed,code];

import { decodeJson } from '../lib/index.js';
const internalDecoded = decodeJson(new Uint8Array(), 123);
// @ts-expect-error internal decoder still has a typed byte input
decodeJson("unsupported");
