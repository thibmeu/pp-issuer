// Privacy Pass Issuance Protocol (Draft 10) - https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-10.html

import { TOKEN_TYPES } from '@cloudflare/privacypass-ts';

export type IssuerConfigurationResponse = {
	'issuer-request-uri': string;
	'token-keys': IssuerTokenKey[];
};

export type IssuerTokenKey = {
	'token-type': TokenType;
	'token-key': string;
	'token-key-legacy'?: string;
	'not-before'?: number;
};

export type TokenType = (typeof TOKEN_TYPES)[keyof typeof TOKEN_TYPES]['value'];
