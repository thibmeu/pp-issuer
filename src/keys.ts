import {
	TOKEN_TYPES,
	TokenTypeEntry,
	privateVerif,
	publicVerif,
	util,
} from '@cloudflare/privacypass-ts';
import { Context } from './context';
const { BlindRSAMode, keyGen } = publicVerif;

const MODULUS_LENGTH = 2048;

interface TokenKeys {
	generate: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
	import: (publicKey: Uint8Array, privateKey: Uint8Array) => Promise<CryptoKeyPair>;
}

class Type2 implements TokenKeys {
	async generate() {
		const keypair = await keyGen(BlindRSAMode.PSS, {
			modulusLength: MODULUS_LENGTH,
			publicExponent: new Uint8Array([1, 0, 1]),
		});
		const publicKey = new Uint8Array(
			(await crypto.subtle.exportKey('spki', keypair.publicKey)) as ArrayBuffer
		);
		const rsaSsaPssPublicKey = util.convertEncToRSASSAPSS(publicKey);
		const privateKey = (await crypto.subtle.exportKey('pkcs8', keypair.privateKey)) as ArrayBuffer;
		return { publicKey: rsaSsaPssPublicKey, privateKey: new Uint8Array(privateKey) };
	}

	async import(publicKey: Uint8Array, privateKey: Uint8Array): Promise<CryptoKeyPair> {
		const publicKeyBytes = util.convertRSASSAPSSToEnc(publicKey);
		const publicKeyCrypto = await crypto.subtle.importKey(
			'spki',
			publicKeyBytes,
			{ name: 'RSA-PSS', hash: 'SHA-384', length: MODULUS_LENGTH },
			true,
			['verify']
		);
		const privateKeyCrypto = await crypto.subtle.importKey(
			'pkcs8',
			privateKey,
			{ name: 'RSA-PSS', hash: 'SHA-384', length: MODULUS_LENGTH },
			true,
			['sign']
		);
		return { publicKey: publicKeyCrypto, privateKey: privateKeyCrypto };
	}
}

export function getTokenKeys(tokenTypeEntry: TokenTypeEntry): TokenKeys {
	switch (tokenTypeEntry.value) {
		case 0x0002:
			return new Type2();
		default:
			throw new Error('Invalid token type');
	}
}

export function getBucketKey(tokenTypeEntry: TokenTypeEntry, tokenKeyID: number): string {
	return `${tokenTypeEntry.value.toString(16)}-${tokenKeyID}`;
}

export function parseTokenRequestHeader(
	ctx: Context,
	bytes: Uint8Array
): {
	tokenType: TokenTypeEntry;
	truncatedTokenKeyId: number;
} {
	// All token requests have a 2-byte value at the beginning of the token describing TokenTypeEntry.
	const input = new DataView(bytes.buffer);

	const type = input.getUint16(0);
	const truncatedTokenKeyId = input.getUint8(2);
	const tokenType = supportedTokenTypes(ctx).find(t => t.value === type);

	if (tokenType === undefined) {
		throw new Error(`unrecognized or non-supported token type: ${type}`);
	}

	return { tokenType, truncatedTokenKeyId };
}

export function getIssuer(
	tokenTypeEntry: TokenTypeEntry
): (
	domain: string,
	sk: Uint8Array,
	pk: Uint8Array
) => Promise<(tokenRequest: Uint8Array) => Promise<Uint8Array>> {
	switch (tokenTypeEntry.value) {
		case TOKEN_TYPES.VOPRF.value:
			return async (domain: string, sk: Uint8Array, pk: Uint8Array) => {
				const issuer = new privateVerif.Issuer(domain, sk, pk);
				return (tokenRequest: Uint8Array) =>
					issuer
						.issue(privateVerif.TokenRequest.deserialize(tokenRequest))
						.then(r => r.serialize());
			};
		case TOKEN_TYPES.BLIND_RSA.value:
			return async (domain: string, sk: Uint8Array, pk: Uint8Array) => {
				const importKeypair = getTokenKeys(tokenTypeEntry).import;
				const { privateKey, publicKey } = await importKeypair(pk, sk);
				const issuer = new publicVerif.Issuer(BlindRSAMode.PSS, domain, privateKey, publicKey, {
					supportsRSARAW: true,
				});
				return (tokenRequest: Uint8Array) =>
					issuer.issue(publicVerif.TokenRequest.deserialize(tokenRequest)).then(r => r.serialize());
			};
		default:
			throw new Error('Invalid token type');
	}
}

export function supportedTokenTypes(ctx: Context): TokenTypeEntry[] {
	return Object.values(TOKEN_TYPES).filter(tokenType =>
		ctx.env.SUPPORTED_TOKEN_TYPES.includes(tokenType.value)
	);
}
