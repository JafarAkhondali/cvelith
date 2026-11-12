/**
 * Auth utility functions for API requests
 */

/**
 * Get authentication headers for API requests
 * @param token - Authentication token (optional, will be retrieved from localStorage if not provided)
 * @returns Headers object with Authorization header if token exists
 */
export const getAuthHeaders = (token?: string | null): HeadersInit => {
  const authToken = token || localStorage.getItem('gpm_cve_auth_token');
  
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  
  if (authToken) {
    headers['Authorization'] = `Token ${authToken}`;
  }
  
  return headers;
};

/**
 * Handle API response and check for 401 errors
 * @param response - Fetch response object
 * @param onUnauthorized - Callback to handle 401 errors (e.g., show login modal)
 * @returns The response if not 401, otherwise throws an error
 */
export const handleApiResponse = async (
  response: Response,
  onUnauthorized?: () => void
): Promise<Response> => {
  if (response.status === 401) {
    // Clear invalid token
    localStorage.removeItem('gpm_cve_auth_token');
    
    // Trigger login modal
    if (onUnauthorized) {
      onUnauthorized();
    } else {
      // Dispatch custom event for global 401 handling
      window.dispatchEvent(new CustomEvent('auth:unauthorized'));
    }
    
    throw new Error('Unauthorized: Please log in to continue');
  }
  
  return response;
};

/**
 * Authenticated fetch wrapper
 * @param url - Request URL
 * @param options - Fetch options
 * @param onUnauthorized - Callback for 401 errors
 * @returns Promise with response
 */
export const authenticatedFetch = async (
  url: string,
  options: RequestInit = {},
  onUnauthorized?: () => void
): Promise<Response> => {
  const token = localStorage.getItem('gpm_cve_auth_token');
  
  const headers = new Headers(options.headers);
  headers.set('Content-Type', 'application/json');
  
  if (token) {
    headers.set('Authorization', `Token ${token}`);
  }
  
  const response = await fetch(url, {
    ...options,
    headers,
  });
  
  return handleApiResponse(response, onUnauthorized);
};

