export class ApiError extends Error {
  code: string;
  status: number;

  constructor(message: string, code: string = 'UNKNOWN_ERROR', status: number = 500) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
  }
}

let currentAuthToken: string | null = null;

export function setAuthToken(token: string | null) {
  currentAuthToken = token;
  if (token) {
    try {
      sessionStorage.setItem('phishshield_auth_token', token);
    } catch {
      // Storage unavailable or disabled
    }
  } else {
    try {
      sessionStorage.removeItem('phishshield_auth_token');
    } catch {
      // Storage unavailable or disabled
    }
  }
}

export function getAuthToken(): string | null {
  if (!currentAuthToken) {
    try {
      currentAuthToken = sessionStorage.getItem('phishshield_auth_token');
    } catch {
      // Storage unavailable or disabled
    }
  }
  return currentAuthToken;
}

export async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = endpoint.startsWith('http') ? endpoint : `/api${endpoint.startsWith('/') ? endpoint : `/${endpoint}`}`;

  const headers = new Headers(options.headers || {});
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  // Attach Bearer token if present and not already set
  const token = getAuthToken();
  if (token && !headers.has('Authorization')) {
    headers.set('Authorization', `Bearer ${token}`);
  }

  const response = await fetch(url, {
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = 'An unexpected error occurred.';
    let errorCode = 'REQUEST_FAILED';

    try {
      const errorJson = await response.json();
      if (errorJson.detail?.error) {
        errorDetail = errorJson.detail.error.message || errorDetail;
        errorCode = errorJson.detail.error.code || errorCode;
      } else if (errorJson.error) {
        errorDetail = errorJson.error.message || errorDetail;
        errorCode = errorJson.error.code || errorCode;
      } else if (typeof errorJson.detail === 'string') {
        errorDetail = errorJson.detail;
      }
    } catch {
      errorDetail = `${response.status} ${response.statusText}`;
    }

    // If 401 Unauthorized, dispatch a custom event for auth listeners
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent('phishshield_unauthorized'));
    }

    throw new ApiError(errorDetail, errorCode, response.status);
  }

  // Handle blob responses (like PDF export)
  if (response.headers.get('content-type')?.includes('application/pdf')) {
    return (await response.blob()) as unknown as T;
  }

  return response.json();
}
