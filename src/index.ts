import { Bindings } from './bindings';
import { Context } from './context';
import { Router } from './router';
import { HeaderNotDefinedError } from './errors';
import { IssuerConfigurationResponse } from './types';
import { b64ToB64URL, b64Tou8, b64URLtoB64, u8ToB64 } from './utils/base64';
import { MediaType, PRIVATE_TOKEN_ISSUER_DIRECTORY } from '@cloudflare/privacypass-ts';
import { ConsoleLogger } from './context/logging';
import { MetricsRegistry } from './context/metrics';
import { hexEncode } from './utils/hex';
import { DIRECTORY_CACHE_REQUEST, clearDirectoryCache, getDirectoryCache } from './cache';
import { getBucketKey, getTokenKeys, parseTokenRequestHeader, supportedTokenTypes } from './keys';

const keyToTokenKeyID = async (key: Uint8Array): Promise<number> => {
	const hash = await crypto.subtle.digest('SHA-256', key);
	const u8 = new Uint8Array(hash);
	return u8[u8.length - 1];
};

interface StorageMetadata extends Record<string, string> {
	publicKey: string;
	tokenKeyID: string;
	tokenType: string;
}

export const handleTokenRequest = async (ctx: Context, request: Request) => {
	ctx.metrics.issuanceRequestTotal.inc({ env: ctx.env.ENVIRONMENT });
	const contentType = request.headers.get('content-type');
	if (!contentType || contentType !== MediaType.PRIVATE_TOKEN_REQUEST) {
		throw new HeaderNotDefinedError(`"Content-Type" must be "${MediaType.PRIVATE_TOKEN_REQUEST}"`);
	}

	const buffer = new Uint8Array(await request.arrayBuffer());
	const { tokenType, truncatedTokenKeyId } = parseTokenRequestHeader(ctx, buffer);

	const key = await ctx.cache.ISSUANCE_KEYS.get(getBucketKey(tokenType, truncatedTokenKeyId));
	if (key === null) {
		throw new Error('Issuer not initialised');
	}

	const issuerBuilder = getTokenKeys(tokenType).issuerBuilder;

	const rawSk = await key.data!;
	const pkEnc = key?.customMetadata?.publicKey;
	if (!pkEnc) {
		throw new Error('Issuer not initialised');
	}

	const rawPk = b64Tou8(b64URLtoB64(pkEnc));
	const domain = new URL(request.url).host;
	const issue = await issuerBuilder(domain, rawSk, rawPk);
	const signedToken = await issue(buffer);
	ctx.metrics.signedTokenTotal.inc({
		env: ctx.env.ENVIRONMENT,
		tokenType: tokenType.value.toString(16),
	});

	return new Response(signedToken, {
		headers: { 'content-type': MediaType.PRIVATE_TOKEN_RESPONSE },
	});
};

export const handleHeadTokenDirectory = async (ctx: Context, request: Request) => {
	const getResponse = await handleTokenDirectory(ctx, request);

	return new Response(undefined, {
		status: getResponse.status,
		headers: getResponse.headers,
	});
};

export const handleTokenDirectory = async (ctx: Context, request: Request) => {
	const cache = await getDirectoryCache();
	const cachedResponse = await cache.match(DIRECTORY_CACHE_REQUEST);
	if (cachedResponse) {
		if (request.headers.get('if-none-match') === cachedResponse.headers.get('etag')) {
			return new Response(undefined, {
				status: 304,
				headers: cachedResponse.headers,
			});
		}
		return cachedResponse;
	}
	ctx.metrics.directoryCacheMissTotal.inc({ env: ctx.env.ENVIRONMENT });

	const keys = await ctx.cache.ISSUANCE_KEYS.list({ include: ['customMetadata'] });

	if (keys.objects.length === 0) {
		throw new Error('Issuer not initialised');
	}

	const directory: IssuerConfigurationResponse = {
		'issuer-request-uri': '/token-request',
		'token-keys': keys.objects.map(key => ({
			'token-type': Number.parseInt(key.key.split('-')[0]),
			'token-key': (key.customMetadata as StorageMetadata).publicKey,
			'not-before': new Date(key.uploaded).getTime(),
		})),
	};

	const body = JSON.stringify(directory);
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))
	);
	const etag = `"${hexEncode(digest)}"`;

	const response = new Response(body, {
		headers: {
			'content-type': MediaType.PRIVATE_TOKEN_ISSUER_DIRECTORY,
			'cache-control': `public, max-age=${ctx.env.DIRECTORY_CACHE_MAX_AGE_SECONDS}`,
			'content-length': body.length.toString(),
			'date': new Date().toUTCString(),
			etag,
		},
	});
	ctx.waitUntil(cache.put(DIRECTORY_CACHE_REQUEST, response.clone()));

	return response;
};

export const handleRotateKey = async (ctx: Context, _request?: Request) => {
	const publicKeys: string[] = [];
	for (const tokenType of supportedTokenTypes(ctx)) {
		ctx.metrics.keyRotationTotal.inc({
			env: ctx.env.ENVIRONMENT,
			tokenType: tokenType.value.toString(16),
		});

	const generate = getTokenKeys(tokenType).generate;
	let publicKeyEnc: string;
	let tokenKeyID: number;
	let privateKey: Uint8Array;
	do {
		const keypair = await generate();
		const publicKey = keypair.publicKey;
		publicKeyEnc = b64ToB64URL(u8ToB64(publicKey));
		tokenKeyID = await keyToTokenKeyID(publicKey);
		privateKey = keypair.privateKey;
		// The bellow condition ensure there is no collision between truncated_token_key_id provided by the issuer
		// This is a 1/256 with 2 keys, and 256/256 chances with 256 keys. This means an issuer cannot have more than 256 keys at the same time.
		// Otherwise, this loop is going to be infinite. With 255 keys, this iteration might take a while.
	} while ((await ctx.cache.ISSUANCE_KEYS.head(getBucketKey(tokenType, tokenKeyID))) !== null);

		const metadata: StorageMetadata = {
			publicKey: publicKeyEnc,
			tokenKeyID: tokenKeyID.toString(),
			tokenType: tokenType.value.toString(16),
		};

		publicKeys.push(publicKeyEnc);

		await ctx.env.ISSUANCE_KEYS.put(getBucketKey(tokenType, tokenKeyID), privateKey, {
			customMetadata: metadata,
		});
	}

	ctx.waitUntil(clearDirectoryCache());

	return new Response(publicKeys.join('\n'), { status: 201 });
};

const handleClearKey = async (ctx: Context, _request?: Request) => {
	const deletedKeys: string[] = [];
	for (const tokenType of supportedTokenTypes(ctx)) {
		ctx.metrics.keyClearTotal.inc({
			env: ctx.env.ENVIRONMENT,
			tokenType: tokenType.value.toString(16),
		});

		const keys = await ctx.env.ISSUANCE_KEYS.list({ prefix: `${tokenType.value.toString(16)}-` });

		let latestKey: R2Object = keys.objects[0];
		const toDelete: Set<string> = new Set();

		// only keep the latest key
		for (const key of keys.objects) {
			if (latestKey.uploaded < key.uploaded) {
				toDelete.add(latestKey.key);
				latestKey = key;
			} else if (key.uploaded !== latestKey.uploaded) {
				toDelete.add(key.key);
			}
		}
		const toDeleteArray = [...toDelete];
		await ctx.env.ISSUANCE_KEYS.delete(toDeleteArray);
		deletedKeys.push(...toDeleteArray);
	}

	ctx.waitUntil(clearDirectoryCache());

	return new Response(deletedKeys.join('\n'), { status: 201 });
};

export default {
	async fetch(request: Request, env: Bindings, ctx: ExecutionContext) {
		// router defines all API endpoints
		// this ease testing, as test can be performed on specific handler methods, not necessardily e2e
		const router = new Router();

		router
			.get(PRIVATE_TOKEN_ISSUER_DIRECTORY, handleTokenDirectory)
			.post('/token-request', handleTokenRequest)
			.post('/admin/rotate', handleRotateKey)
			.post('/admin/clear', handleClearKey);

		return router.handle(
			request as Request<Bindings, IncomingRequestCfProperties<unknown>>,
			env,
			ctx
		);
	},

	async scheduled(event: ScheduledEvent, env: Bindings, ectx: ExecutionContext) {
		const ctx = new Context(
			env,
			ectx.waitUntil.bind(ectx),
			new ConsoleLogger(),
			new MetricsRegistry({ bearerToken: env.LOGGING_SHIM_TOKEN })
		);
		const date = new Date(event.scheduledTime);
		const isRotation = date.getUTCDate() === 1;

		if (isRotation) {
			await handleRotateKey(ctx);
		} else {
			await handleClearKey(ctx);
		}
	},
};
