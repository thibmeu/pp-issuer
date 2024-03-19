// The following is available in workers as long as node_compat is enabled
// However, typing is tricky, as can be seen in https://github.com/cloudflare/workerd/issues/1298
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { generatePrimeSync } from 'node:crypto';
import {
	TOKEN_TYPES,
	TokenTypeEntry,
	privateVerif,
	publicVerif,
	util,
} from '@cloudflare/privacypass-ts';
import { Context } from './context';
const { keyGen: privateKeyGen } = privateVerif;
const { BlindRSAMode, PartiallyBlindRSAMode } = publicVerif;

const MODULUS_LENGTH = 2048;

interface TokenKeys {
	generate: () => Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
	issuerBuilder: (
		domain: string,
		sk: Uint8Array,
		pk: Uint8Array
	) => Promise<(tokenRequest: Uint8Array) => Promise<Uint8Array>>;
}

class Type1 implements TokenKeys {
	async generate() {
		return privateKeyGen();
	}

	async issuerBuilder(domain: string, sk: Uint8Array, pk: Uint8Array) {
		const issuer = new privateVerif.Issuer(domain, sk, pk);
		return (tokenRequest: Uint8Array) =>
			issuer.issue(privateVerif.TokenRequest.deserialize(tokenRequest)).then(r => r.serialize());
	}
}

class Type2 implements TokenKeys {
	async generate() {
		const keypair = await publicVerif.Issuer.generateKey(BlindRSAMode.PSS, {
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

	async issuerBuilder(domain: string, sk: Uint8Array, pk: Uint8Array) {
		const importKeypair = async (privateKey: Uint8Array, publicKey: Uint8Array) => {
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
			return { privateKey: privateKeyCrypto, publicKey: publicKeyCrypto };
		};
		const { privateKey, publicKey } = await importKeypair(sk, pk);
		const issuer = new publicVerif.Issuer(BlindRSAMode.PSS, domain, privateKey, publicKey, {
			supportsRSARAW: true,
		});
		return (tokenRequest: Uint8Array) =>
			issuer
				.issue(publicVerif.TokenRequest.deserialize(TOKEN_TYPES.BLIND_RSA, tokenRequest))
				.then(r => r.serialize());
	}
}

class TypeDA7A implements TokenKeys {
	async generate() {
		const keypair = await publicVerif.IssuerWithMetadata.generateKey(
			PartiallyBlindRSAMode.PSS,
			{
				modulusLength: MODULUS_LENGTH,
				publicExponent: new Uint8Array([1, 0, 1]),
			},
			(length: number) => generatePrimeSync(length, { safe: true, bigint: true })
		);
		const publicKey = new Uint8Array(
			(await crypto.subtle.exportKey('spki', keypair.publicKey)) as ArrayBuffer
		);
		const rsaSsaPssPublicKey = util.convertEncToRSASSAPSS(publicKey);
		const privateKey = (await crypto.subtle.exportKey('pkcs8', keypair.privateKey)) as ArrayBuffer;
		return { publicKey: rsaSsaPssPublicKey, privateKey: new Uint8Array(privateKey) };
	}

	async issuerBuilder(domain: string, sk: Uint8Array, pk: Uint8Array) {
		const importKeypair = async (privateKey: Uint8Array, publicKey: Uint8Array) => {
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
			return { privateKey: privateKeyCrypto, publicKey: publicKeyCrypto };
		};
		const { privateKey, publicKey } = await importKeypair(sk, pk);
		const issuer = new publicVerif.IssuerWithMetadata(
			BlindRSAMode.PSS,
			domain,
			privateKey,
			publicKey,
			{
				supportsRSARAW: true,
			}
		);
		return (tokenRequest: Uint8Array) =>
			issuer
				.issue(publicVerif.ExtendedTokenRequest.deserialize(tokenRequest))
				.then(r => r.serialize());
	}
}

export function getTokenKeys(tokenTypeEntry: TokenTypeEntry): TokenKeys {
	switch (tokenTypeEntry.value) {
		case 0x0001:
			return new Type1();
		case 0x0002:
			return new Type2();
		case 0xda7a:
			return new TypeDA7A();
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
	// note that this field is not defined at the top of the standard and is specific to every token type
	// at the time of writing, it's present in every token type
	const truncatedTokenKeyId = input.getUint8(2);
	const tokenType = supportedTokenTypes(ctx).find(t => t.value === type);

	if (tokenType === undefined) {
		throw new Error(`unrecognized or non-supported token type: ${type}`);
	}

	return { tokenType, truncatedTokenKeyId };
}

export function supportedTokenTypes(ctx: Context): TokenTypeEntry[] {
	return Object.values(TOKEN_TYPES).filter(tokenType =>
		ctx.env.SUPPORTED_TOKEN_TYPES.includes(tokenType.value)
	);
}
