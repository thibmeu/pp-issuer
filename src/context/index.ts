import { Bindings } from '../bindings';
import { APICache, CachedR2Bucket, InMemoryCache, CascadingCache } from '../cache';
import { TokenType } from '../types';
import { Logger } from './logging';
import { MetricsRegistry } from './metrics';

export type WaitUntilFunc = (p: Promise<unknown>) => void;

export interface Environment {
	// variables and secrets
	DIRECTORY_CACHE_MAX_AGE_SECONDS: number;
	ENVIRONMENT: string;
	LOGGING_SHIM_TOKEN: string;
	SENTRY_ACCESS_CLIENT_ID: string;
	SENTRY_ACCESS_CLIENT_SECRET: string;
	SENTRY_DSN: string;
	SENTRY_SAMPLE_RATE: number;
	SUPPORTED_TOKEN_TYPES: TokenType[];

	// R2 buckets
	ISSUANCE_KEYS: R2Bucket;
}

export class Context {
	public env: Environment;
	private promises: Promise<unknown>[] = [];
	public cache: { ISSUANCE_KEYS: CachedR2Bucket };

	constructor(
		env: Bindings,
		private _waitUntil: WaitUntilFunc,
		public logger: Logger,
		public metrics: MetricsRegistry
	) {
		const cache = new CascadingCache(new InMemoryCache(), new APICache('r2/issuance_keys'));
		this.cache = {
			ISSUANCE_KEYS: new CachedR2Bucket(this, env.ISSUANCE_KEYS, cache),
		};

		this.env = {
			// variables and secrets
			DIRECTORY_CACHE_MAX_AGE_SECONDS: Number.parseInt(env.DIRECTORY_CACHE_MAX_AGE_SECONDS),
			ENVIRONMENT: env.ENVIRONMENT,
			LOGGING_SHIM_TOKEN: env.LOGGING_SHIM_TOKEN,
			SENTRY_ACCESS_CLIENT_ID: env.SENTRY_ACCESS_CLIENT_ID,
			SENTRY_ACCESS_CLIENT_SECRET: env.SENTRY_ACCESS_CLIENT_SECRET,
			SENTRY_DSN: env.SENTRY_DSN,
			SENTRY_SAMPLE_RATE: Number.parseInt(env.SENTRY_SAMPLE_RATE),
			SUPPORTED_TOKEN_TYPES: JSON.parse(env.SUPPORTED_TOKEN_TYPES),

			// R2 buckets
			ISSUANCE_KEYS: env.ISSUANCE_KEYS,
		};
	}

	isTest(): boolean {
		return RELEASE === 'test';
	}

	/**
	 * Registers async tasks with the runtime, tracks them internally and adds error reporting for uncaught exceptions
	 * @param p - Promise for the async task to track
	 */
	waitUntil(p: Promise<unknown>): void {
		// inform runtime of async task
		this._waitUntil(p);
		this.promises.push(
			p.catch((e: Error) => {
				console.log(e.message);
			})
		);
	}

	/**
	 * Waits for promises to complete in the order that they were registered.
	 *
	 * @remark
	 * It is important to wait for the promises in the array to complete sequentially since new promises created by async tasks may be added to the end of the array while this function runs.
	 */
	async waitForPromises(): Promise<void> {
		for (let i = 0; i < this.promises.length; i++) {
			try {
				await this.promises[i];
			} catch (e) {
				console.log(e);
			}
		}
	}
}
