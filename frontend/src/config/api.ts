/**
 * API Configuration
 * 
 * API_BASE_URL can be set to:
 * - A full URL (e.g., 'http://127.0.0.1:8000') for absolute addressing
 * - An empty string ('') for relative addressing (same origin)
 * 
 * If set to empty string, all API calls will use relative URLs.
 * This is useful when the API is served from the same origin or configured via proxy.
 */
// Default '' = same origin: Caddy serves the frontend and proxies /api/* to Django.
// For local frontend development against a separate backend, set VITE_API_BASE_URL
// (e.g. VITE_API_BASE_URL=http://127.0.0.1:8000 npm run dev).
export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? '';

export const API_ENDPOINTS = {
  CVE_LIST: '/api/v1/cve/',
  CVE_DETAIL: (id: string) => `/api/v1/cve/${id}/`,
  GPM_LIST: '/api/v1/gpm/',
  GPM_SINGLE: (id: string) => `/api/v1/gpm/${id}/`,
  GPM_DAILY: '/api/v1/gpm-daily/',
  GPM_HISTORICAL: (id: string) => `/api/v1/gpm/${id}/`,
  GPM_BADGES: '/api/v1/gpm-badges/',
} as const;

