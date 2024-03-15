import type { R2Bucket } from '@cloudflare/workers-types/2023-07-01';

export interface Bindings {
	// variables and secrets
	DIRECTORY_CACHE_MAX_AGE_SECONDS: string;
	ENVIRONMENT: string;
	LOGGING_SHIM_TOKEN: string;
	SENTRY_ACCESS_CLIENT_ID: string;
	SENTRY_ACCESS_CLIENT_SECRET: string;
	SENTRY_DSN: string;
	SENTRY_SAMPLE_RATE: string;
	SUPPORTED_TOKEN_TYPES: string;

	// R2 buckets
	ISSUANCE_KEYS: R2Bucket;
}
