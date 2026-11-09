type GoogleCredentialResponse = {
  credential?: string
}

type GoogleIdentityApi = {
  initialize(options: {
    client_id: string
    auto_select: false
    callback(response: GoogleCredentialResponse): void
  }): void
  renderButton(
    element: HTMLElement,
    options: { type: 'standard'; theme: 'outline'; size: 'large'; text: 'signin_with'; shape: 'rectangular'; width: number },
  ): void
}

declare global {
  interface Window {
    google?: { accounts: { id: GoogleIdentityApi } }
  }
}

const googleScriptUrl = 'https://accounts.google.com/gsi/client'
let googleApiLoad: Promise<GoogleIdentityApi> | undefined

function loadGoogleIdentityApi(): Promise<GoogleIdentityApi> {
  if (window.google?.accounts.id) return Promise.resolve(window.google.accounts.id)
  if (googleApiLoad) return googleApiLoad

  googleApiLoad = new Promise((resolve, reject) => {
    const script = document.createElement('script')
    script.src = googleScriptUrl
    script.async = true
    script.defer = true
    script.onload = () => {
      const googleApi = window.google?.accounts.id
      if (googleApi) resolve(googleApi)
      else reject(new Error('Google Sign-In could not be initialized.'))
    }
    script.onerror = () => reject(new Error('Google Sign-In could not be loaded.'))
    document.head.append(script)
  })
  return googleApiLoad
}

export function renderGoogleSignInButton(
  container: HTMLElement,
  clientId: string,
  onCredential: (idToken: string) => Promise<void>,
  onError: (error: Error) => void,
): () => void {
  let mounted = true
  void loadGoogleIdentityApi().then((googleApi) => {
    if (!mounted) return
    googleApi.initialize({
      client_id: clientId,
      auto_select: false,
      callback: (response) => {
        if (!response.credential) {
          onError(new Error('Google did not return a sign-in token.'))
          return
        }
        void onCredential(response.credential).catch((error: unknown) => {
          onError(error instanceof Error ? error : new Error('Google sign-in could not be completed.'))
        })
      },
    })
    googleApi.renderButton(container, {
      type: 'standard',
      theme: 'outline',
      size: 'large',
      text: 'signin_with',
      shape: 'rectangular',
      width: Math.max(240, Math.min(360, Math.floor(container.clientWidth || 320))),
    })
  }).catch((error: unknown) => {
    if (mounted) onError(error instanceof Error ? error : new Error('Google Sign-In could not be loaded.'))
  })

  return () => {
    mounted = false
    container.replaceChildren()
  }
}
