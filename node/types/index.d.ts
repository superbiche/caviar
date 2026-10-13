// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Michel Tomas
export type Json = null | boolean | string | number | bigint | Json[] | { [key: string]: Json };
export type Hit = { rule: string; count: number };
export type Result<T = Json> = [T, Hit[]];
export type Options = { timeout?: number; allowPlain?: boolean };
export type PoolOptions = Options & { acquireTimeout: number };
export declare class CaviarError extends Error {
  readonly code: string;
  constructor(code: string);
}
export declare class Client {
  constructor(key: Uint8Array | null, options?: Options);
  string(text: string): Promise<Result<string>>;
  value(value: Json): Promise<Result>;
  close(): Promise<void>;
}
export declare class Pool {
  constructor(key: Uint8Array | null, size: number, options: PoolOptions);
  string(text: string): Promise<Result<string>>;
  value(value: Json): Promise<Result>;
  close(): Promise<void>;
}
