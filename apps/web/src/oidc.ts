import { createRemoteJWKSet, jwtVerify } from 'jose'

type OidcSettings = {
  issuer: string
  clientId: string
  audience?: string
  scope: string
  redirectUri?: string
}

type DiscoveryDocument = {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
}

const stateKey = 'sieve_oidc_state'
const verifierKey = 'sieve_oidc_verifier'
const nonceKey = 'sieve_oidc_nonce'

export function oidcLoginConfigured(): boolean {
  return Boolean(import.meta.env.VITE_OIDC_ISSUER?.trim() && import.meta.env.VITE_OIDC_CLIENT_ID?.trim())
}

function settings(): OidcSettings {
  const issuer = import.meta.env.VITE_OIDC_ISSUER?.trim()
  const clientId = import.meta.env.VITE_OIDC_CLIENT_ID?.trim()
  if (!issuer || !clientId) throw new Error('Identity provider login is not configured.')
  if (new URL(issuer).protocol !== 'https:') throw new Error('The identity provider must use HTTPS.')

  return {
    issuer,
    clientId,
    audience: import.meta.env.VITE_OIDC_AUDIENCE?.trim() || undefined,
    scope: import.meta.env.VITE_OIDC_SCOPE?.trim() || 'openid profile email',
    redirectUri: import.meta.env.VITE_OIDC_REDIRECT_URI?.trim() || undefined,
  }
}

function randomValue(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

function redirectUri(config: OidcSettings): string {
  const candidate = new URL(config.redirectUri || `${window.location.origin}${window.location.pathname}`)
  if (candidate.origin !== window.location.origin || candidate.hash) {
    throw new Error('The OIDC redirect URI must use this app origin and cannot include a URL fragment.')
  }
  return candidate.toString()
}

function secureEndpoint(value: string): URL {
  const endpoint = new URL(value)
  if (endpoint.protocol !== 'https:') throw new Error('The identity provider returned an insecure endpoint.')
  return endpoint
}

async function discover(config: OidcSettings): Promise<DiscoveryDocument> {
  const discoveryUrl = new URL(`${config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`)
  const response = await fetch(discoveryUrl, { headers: { Accept: 'application/json' }, redirect: 'error', cache: 'no-store' })
  if (!response.ok) throw new Error('Could not reach the identity provider.')
  const document = await response.json() as Partial<DiscoveryDocument>
  if (
    document.issuer !== config.issuer ||
    typeof document.authorization_endpoint !== 'string' ||
    typeof document.token_endpoint !== 'string' ||
    typeof document.jwks_uri !== 'string'
  ) {
    throw new Error('The identity provider returned incomplete configuration.')
  }
  secureEndpoint(document.authorization_endpoint)
  secureEndpoint(document.token_endpoint)
  secureEndpoint(document.jwks_uri)
  return document as DiscoveryDocument
}

export async function beginOidcLogin(): Promise<void> {
  const config = settings()
  const metadata = await discover(config)
  const state = randomValue()
  const verifier = randomValue()
  const nonce = randomValue()
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  const challenge = encodeBase64Url(new Uint8Array(digest))

  sessionStorage.setItem(stateKey, state)
  sessionStorage.setItem(verifierKey, verifier)
  sessionStorage.setItem(nonceKey, nonce)

  const authorizationUrl = secureEndpoint(metadata.authorization_endpoint)
  authorizationUrl.searchParams.set('client_id', config.clientId)
  authorizationUrl.searchParams.set('redirect_uri', redirectUri(config))
  authorizationUrl.searchParams.set('response_type', 'code')
  authorizationUrl.searchParams.set('scope', [...new Set(['openid', ...config.scope.split(/\s+/).filter(Boolean)])].join(' '))
  authorizationUrl.searchParams.set('state', state)
  authorizationUrl.searchParams.set('nonce', nonce)
  authorizationUrl.searchParams.set('code_challenge', challenge)
  authorizationUrl.searchParams.set('code_challenge_method', 'S256')
  if (config.audience) authorizationUrl.searchParams.set('audience', config.audience)
  window.location.assign(authorizationUrl.toString())
}

export function hasOidcCallback(): boolean {
  const query = new URLSearchParams(window.location.search)
  return query.has('code') || query.has('error') || query.has('state')
}

function clearCallbackUrl(url: URL): void {
  for (const parameter of ['code', 'state', 'error', 'error_description', 'iss', 'session_state']) {
    url.searchParams.delete(parameter)
  }
  window.history.replaceState({}, document.title, `${url.pathname}${url.search}${url.hash}`)
}

export async function completeOidcCallback(): Promise<string | null> {
  const callbackUrl = new URL(window.location.href)
  const code = callbackUrl.searchParams.get('code')
  const state = callbackUrl.searchParams.get('state')
  const providerError = callbackUrl.searchParams.get('error')
  const returnedIssuer = callbackUrl.searchParams.get('iss')
  const expectedState = sessionStorage.getItem(stateKey)
  const verifier = sessionStorage.getItem(verifierKey)
  const expectedNonce = sessionStorage.getItem(nonceKey)
  clearCallbackUrl(callbackUrl)
  sessionStorage.removeItem(stateKey)
  sessionStorage.removeItem(verifierKey)
  sessionStorage.removeItem(nonceKey)

  if (providerError) throw new Error('Sign-in was cancelled or rejected by the identity provider.')
  if (!code || !state || !expectedState || !verifier || !expectedNonce || state !== expectedState) {
    throw new Error('The identity provider response could not be verified. Please try again.')
  }

  const config = settings()
  if (returnedIssuer && returnedIssuer !== config.issuer) {
    throw new Error('The sign-in response came from an unexpected identity provider.')
  }
  const metadata = await discover(config)
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.clientId,
    code,
    redirect_uri: redirectUri(config),
    code_verifier: verifier,
  })
  const response = await fetch(secureEndpoint(metadata.token_endpoint), {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
    credentials: 'omit',
    redirect: 'error',
    cache: 'no-store',
  })
  if (!response.ok) throw new Error('The identity provider could not complete sign-in.')
  const tokens = await response.json() as { access_token?: unknown; id_token?: unknown; token_type?: unknown }
  if (
    typeof tokens.access_token !== 'string' ||
    typeof tokens.id_token !== 'string' ||
    typeof tokens.token_type !== 'string' ||
    tokens.token_type.toLowerCase() !== 'bearer'
  ) {
    throw new Error('The identity provider returned an invalid token response.')
  }

  const keySet = createRemoteJWKSet(secureEndpoint(metadata.jwks_uri))
  const { payload } = await jwtVerify(tokens.id_token, keySet, {
    issuer: config.issuer,
    audience: config.clientId,
  })
  if (payload.nonce !== expectedNonce || typeof payload.sub !== 'string' || !payload.sub) {
    throw new Error('The identity token could not be verified. Please sign in again.')
  }
  if (typeof payload.exp !== 'number' || payload.exp <= Date.now() / 1000) {
    throw new Error('The identity provider returned an expired identity token.')
  }
  return tokens.access_token
}
