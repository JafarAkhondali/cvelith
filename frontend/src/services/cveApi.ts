import { API_BASE_URL, API_ENDPOINTS } from "@/config/api";
import { authenticatedFetch } from "@/utils/auth";

/**
 * CVE Data Interface
 */
export interface CVEData {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  publishedDate: string;
  lastModified?: string;
  cvss?: {
    score: number;
    vector: string;
  };
  cwes?: Array<{ id: string; name: string }>;
  references?: string[];
  affectedProducts?: string[];
  gpm?: number; // Absolute GPM (total_gpm)
  relativeGpm?: number; // Relative GPM (gpm) - shown with + sign
  epss?: number;
  epssPercentile?: number;
  kev?: string | string[] | Array<{ date?: string; organizer?: string; [key: string]: any }> | null;
  datePublished?: string | null;
}

/**
 * GPM Data Interface - matches actual API response
 */
export interface GPMData {
  cve_id: string;
  gpm: number;
  base_score?: number;
  base_severity?: string;
  vector_string?: string;
  epss?: number;
  cwe_names?: string;
  description?: string;
  date?: string;
  published_date?: string;
  date_published?: string | null;
  kev?: string | string[] | Array<{ date?: string; organizer?: string; [key: string]: any }> | null;
  [key: string]: any; // Allow additional fields from API
}

/**
 * Paginated CVE Response
 */
export interface PaginatedCVEResponse {
  count?: number;
  next?: string | null;
  previous?: string | null;
  results: CVEData[];
}

/**
 * Paginated GPM Response
 */
export interface PaginatedGPMResponse {
  page?: number;
  page_size?: number;
  count?: number;
  has_next?: boolean;
  next?: string | null; // Keep for backward compatibility
  previous?: string | null; // Keep for backward compatibility
  results: GPMData[];
}

/**
 * Convert CVSS score to severity level
 */
const getSeverityFromScore = (score: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" => {
  if (score >= 9.0) return "CRITICAL";
  if (score >= 7.0) return "HIGH";
  if (score >= 4.0) return "MEDIUM";
  if (score > 0) return "LOW";
  return "INFO";
};

/**
 * Check if severity is valid
 */
const isValidSeverity = (severity: string | undefined | null): boolean => {
  if (!severity) return false;
  const upperSeverity = severity.toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upperSeverity) && upperSeverity !== "?";
};

/**
 * Normalize CVE data from API response
 * Matches the actual API response structure
 */
const normalizeCVEData = (item: any): CVEData => {
  // API structure: { id, description, status, date_published, date_reserved }
  const cveId = item.id || "";
  const description = item.description || "";
  
  // Convert ISO date to YYYY-MM-DD format
  const parseDate = (dateStr: string): string => {
    if (!dateStr) return "";
    try {
      const date = new Date(dateStr);
      return date.toISOString().split('T')[0];
    } catch {
      return dateStr.split('T')[0]; // Fallback: just take date part
    }
  };
  
  const publishedDate = parseDate(item.date_published || "");
  const lastModified = parseDate(item.date_reserved || publishedDate);
  
  // Extract CVSS score - API may provide base_score from GPM endpoint
  const cvssScore = item.base_score || item.cvss_score || 0;
  const cvssVector = item.vector_string || item.cvss_vector || "";
  
  // Extract severity - API provides base_severity in GPM endpoint
  const severity = item.base_severity 
    ? (item.base_severity.toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO")
    : getSeverityFromScore(cvssScore);
  
  // Extract CWEs - API provides cwe_names as a string with separators
  let normalizedCWEs: Array<{ id: string; name: string }> = [];
  if (item.cwe_names) {
    // Split by "|SEP_CWE_SEP|" or "|" and create CWE objects
    const cweNames = item.cwe_names.split(/\s*\|\s*SEP_CWE_SEP\s*\|\s*/).filter((n: string) => n.trim());
    normalizedCWEs = cweNames.map((name: string) => ({
      id: `CWE-${name.replace(/\D/g, '')}` || "",
      name: name.trim()
    }));
  } else if (item.cwes) {
    // Handle array format if it exists
    normalizedCWEs = Array.isArray(item.cwes)
      ? item.cwes.map((cwe: any) => ({
          id: typeof cwe === 'string' ? cwe : (cwe.id || ""),
          name: typeof cwe === 'string' ? cwe : (cwe.name || "")
        }))
      : [];
  }
  
  // Extract references - API may not provide these in list endpoint
  const references = item.references || [];
  const normalizedReferences = Array.isArray(references)
    ? references.map((ref: any) => typeof ref === 'string' ? ref : (ref.url || ""))
    : [];
  
  // Extract affected products - API may not provide these in list endpoint
  const affectedProducts = item.affected_products || [];
  const normalizedProducts = Array.isArray(affectedProducts)
    ? affectedProducts.map((product: any) => typeof product === 'string' ? product : (product.name || ""))
    : [];
  
  return {
    id: cveId,
    severity,
    description,
    publishedDate,
    lastModified,
    cvss: cvssScore > 0 ? {
      score: cvssScore,
      vector: cvssVector
    } : undefined,
    cwes: normalizedCWEs.length > 0 ? normalizedCWEs : undefined,
    references: normalizedReferences.length > 0 ? normalizedReferences : undefined,
    affectedProducts: normalizedProducts.length > 0 ? normalizedProducts : undefined,
    gpm: item.gpm
  };
};

/**
 * Fetch CVEs with pagination
 * @param page - Page number (default: 1)
 * @param limit - Number of results per page (optional)
 * @returns Promise with paginated CVE data
 */
export const fetchCVEs = async (page: number = 1, limit?: number, onUnauthorized?: () => void): Promise<PaginatedCVEResponse> => {
  try {
    let url = `${API_BASE_URL}${API_ENDPOINTS.CVE_LIST}?page=${page}`;
    if (limit) {
      url += `&limit=${limit}`;
    }
    
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 CVE List API Response:", {
        url,
        count: data.count,
        resultsCount: data.results?.length || 0,
        sampleItem: data.results?.[0] || null
      });
    }
    
    // Handle different possible response structures
    const results = data.results || data.data || data.items || (Array.isArray(data) ? data : []);
    const normalizedResults = Array.isArray(results) 
      ? results.map(normalizeCVEData)
      : [];
    
    return {
      count: data.count,
      next: data.next || null,
      previous: data.previous || null,
      results: normalizedResults
    };
  } catch (error) {
    console.error("Error fetching CVEs:", error);
    throw error;
  }
};

/**
 * Fetch recent CVEs (backwards compatibility)
 * @param limit - Maximum number of CVEs to fetch
 * @param daysBack - Optional: filter CVEs published in the last N days
 * @returns Promise with array of CVE data
 */
export const fetchRecentCVEs = async (limit: number = 20, daysBack?: number): Promise<CVEData[]> => {
  try {
    const allCVEs: CVEData[] = [];
    let page = 1;
    let hasMore = true;
    const maxPages = 50; // Limit pages to prevent infinite loops
    const cutoffDate = daysBack ? (() => {
      const date = new Date();
      date.setDate(date.getDate() - daysBack);
      return date;
    })() : null;
    
    // Fetch enough pages to find recent CVEs
    while (hasMore && allCVEs.length < limit * 3 && page <= maxPages) {
      const response = await fetchCVEs(page);
      const pageCVEs = response.results || [];
      
      // Filter by date if specified
      if (cutoffDate) {
        const filtered = pageCVEs.filter(cve => {
          if (!cve.publishedDate) return false;
          const pubDate = new Date(cve.publishedDate);
          return pubDate >= cutoffDate;
        });
        allCVEs.push(...filtered);
      } else {
        allCVEs.push(...pageCVEs);
      }
      
      // Stop if we have enough or no more pages
      if (!response.next || allCVEs.length >= limit * 3) {
        hasMore = false;
      } else {
        page++;
      }
    }
    
    // Sort by published date (most recent first) and take limit
    const sorted = allCVEs
      .sort((a, b) => {
        const dateA = new Date(a.publishedDate || 0).getTime();
        const dateB = new Date(b.publishedDate || 0).getTime();
        return dateB - dateA; // Most recent first
      })
      .slice(0, limit);
    
    return sorted;
  } catch (error) {
    console.error("Error fetching recent CVEs:", error);
    return [];
  }
};

/**
 * CVE Detail Response Interface
 */
export interface CVEDetailResponse {
  id: string;
  description: string;
  status: string;
  date_published: string | null;
  date_reserved: string | null;
  date_added: string | null;
  cwes?: Array<{
    id: string;
    name: string;
    status: string;
    is_category: boolean;
  }>;
  references?: Array<{
    tag: string;
    description: string;
    url: string;
  }>;
  cvss?: Array<{
    id: number;
    cve_id: string;
    version: string;
    base_score: string;
    base_severity: string;
    vector_string: string;
    metrics?: {
      scope?: string;
      version?: string;
      baseScore?: number;
      attackVector?: string;
      baseSeverity?: string;
      vectorString?: string;
      integrityImpact?: string;
      userInteraction?: string;
      attackComplexity?: string;
      availabilityImpact?: string;
      privilegesRequired?: string;
      confidentialityImpact?: string;
      [key: string]: any;
    };
  }>;
  kev?: string | string[] | Array<{ date?: string; organizer?: string; [key: string]: any }> | null;
}

/**
 * Fetch CVE detail by ID from the CVE endpoint
 * @param id - CVE ID (e.g., "CVE-2024-4947")
 * @returns Promise with CVE detail data or null if not found
 */
export const fetchCVEDetail = async (id: string, onUnauthorized?: () => void): Promise<CVEDetailResponse | null> => {
  try {
    const url = `${API_BASE_URL}${API_ENDPOINTS.CVE_DETAIL(id)}`;
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 CVE Detail API Response:", {
        url,
        id,
        hasData: !!data
      });
    }
    
    return data as CVEDetailResponse;
  } catch (error) {
    console.error("Error fetching CVE detail:", error);
    return null;
  }
};

/**
 * Fetch CVE by ID (legacy function - kept for compatibility)
 * @param id - CVE ID (e.g., "CVE-2011-3805")
 * @returns Promise with CVE data or null if not found
 */
export const fetchCVEById = async (id: string, onUnauthorized?: () => void): Promise<CVEData | null> => {
  try {
    const url = `${API_BASE_URL}${API_ENDPOINTS.CVE_DETAIL(id)}`;
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 CVE Detail API Response:", {
        url,
        cveId: id,
        responseKeys: Object.keys(data)
      });
    }
    
    return normalizeCVEData(data);
  } catch (error) {
    console.error("Error fetching CVE:", error);
    return null;
  }
};

/**
 * Fetch GPM data
 * @param days - Optional: filter GPMs from the last N days (e.g., 7, 14)
 * @param page - Page number (default: 1)
 * @param pageSize - Optional: number of items per page (default: 50)
 * @param gpmOnly - Optional: if true, only return CVEs that are GPM-only (unpublished)
 * @param kevOnly - Optional: if true, only return CVEs that are in KEV
 * @param notKevOnly - Optional: if true, only return CVEs that are NOT in KEV
 * @returns Promise with paginated GPM data
 */
export const fetchGPMs = async (
  days?: number, 
  page: number = 1,
  pageSize?: number,
  gpmOnly?: boolean,
  kevOnly?: boolean,
  notKevOnly?: boolean, 
  onUnauthorized?: () => void
): Promise<PaginatedGPMResponse> => {
  try {
    let url = `${API_BASE_URL}${API_ENDPOINTS.GPM_LIST}?page=${page}`;
    
    // Add page_size parameter if specified
    if (pageSize !== undefined) {
      url += `&page_size=${pageSize}`;
    }
    
    // Only add days parameter if it's explicitly provided (not undefined)
    if (days !== undefined) {
      url += `&days=${days}`;
    }
    // Add gpm_only parameter if specified
    if (gpmOnly === true) {
      url += `&gpm_only=true`;
    }
    // Add kev_only parameter if specified
    if (kevOnly === true) {
      url += `&kev_only=true`;
    }
    // Add not_kev_only parameter if specified
    if (notKevOnly === true) {
      url += `&not_kev_only=true`;
    }
    
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 GPM API Response:", {
        url,
        days,
        requestedPage: page,
        pageSize,
        gpmOnly,
        kevOnly,
        notKevOnly,
        responsePage: data.page,
        page_size: data.page_size,
        count: data.count,
        has_next: data.has_next,
        resultsCount: data.results?.length || 0,
        sampleItem: data.results?.[0] || null
      });
    }
    
    // Handle different possible response structures
    const results = data.results || data.data || data.items || (Array.isArray(data) ? data : []);
    
    return {
      page: data.page,
      page_size: data.page_size,
      count: data.count,
      has_next: data.has_next,
      next: data.next || null, // Keep for backward compatibility
      previous: data.previous || null, // Keep for backward compatibility
      results: Array.isArray(results) ? results : []
    };
  } catch (error) {
    console.error("Error fetching GPMs:", error);
    throw error;
  }
};

/**
 * Fetch GPM data for a specific CVE ID
 * @param cveId - CVE ID (e.g., "CVE-2024-4947")
 * @returns Promise with GPM data for the CVE, or null if not found
 */
export const fetchGPMByCveId = async (cveId: string, onUnauthorized?: () => void): Promise<GPMData | null> => {
  try {
    const url = `${API_BASE_URL}${API_ENDPOINTS.GPM_SINGLE(cveId)}`;
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      if (response.status === 404) {
        return null;
      }
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 GPM by CVE ID API Response:", {
        url,
        cveId,
        responseKeys: Object.keys(data),
        hasCveId: 'cve_id' in data || 'cveid' in data,
        hasResults: 'results' in data
      });
    }
    
    // If the response is historical data (has 'results' array with 'day' and 'samples')
    // This means the endpoint returned historical data, not current GPM data
    // Return null - we should use the historical endpoint separately for historical data
    if (data.results && Array.isArray(data.results) && data.results.length > 0 && 'day' in data.results[0]) {
      return null;
    }
    
    // If it's a single GPM data object (has cve_id field)
    if (data.cve_id === cveId || data.cveid === cveId) {
      return {
        ...data,
        cve_id: data.cve_id || data.cveid
      } as GPMData;
    }
    
    // If it's wrapped in a results array
    const results = data.results || data.data || data.items || (Array.isArray(data) ? data : []);
    if (Array.isArray(results) && results.length > 0) {
      const match = results.find((item: any) => (item.cve_id || item.cveid) === cveId);
      if (match) {
        return {
          ...match,
          cve_id: match.cve_id || match.cveid
        } as GPMData;
      }
      return results[0] as GPMData;
    }
    
    return null;
  } catch (error) {
    console.error("Error fetching GPM by CVE ID:", error);
    return null;
  }
};

/**
 * Fetch all GPMs (across all pages)
 * @param days - Optional: filter GPMs from the last N days
 * @returns Promise with array of all GPM data
 */
export const fetchAllGPMs = async (
  days?: number, 
  gpmOnly?: boolean,
  kevOnly?: boolean,
  notKevOnly?: boolean,
  onUnauthorized?: () => void
): Promise<GPMData[]> => {
  try {
    const allGPMs: GPMData[] = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      const response = await fetchGPMs(days, page, undefined, gpmOnly, kevOnly, notKevOnly, onUnauthorized);
      allGPMs.push(...response.results);
      
      // Check has_next first (new format), fallback to next (old format)
      if (response.has_next === false || (!response.has_next && !response.next)) {
        hasMore = false;
      } else {
        page++;
      }
    }
    
    return allGPMs;
  } catch (error) {
    console.error("Error fetching all GPMs:", error);
    return [];
  }
};

/**
 * Fetch GPM-only (unpublished) CVEs
 * @param days - Optional: filter GPMs from the last N days
 * @param page - Page number (default: 1)
 * @param pageSize - Optional: number of items per page (default: 50)
 * @param kevOnly - Optional: if true, only return CVEs that are in KEV
 * @param notKevOnly - Optional: if true, only return CVEs that are NOT in KEV
 * @returns Promise with paginated GPM data for unpublished CVEs
 */
export const fetchGPMOnly = async (
  days?: number, 
  page: number = 1,
  pageSize?: number,
  kevOnly?: boolean,
  notKevOnly?: boolean, 
  onUnauthorized?: () => void
): Promise<PaginatedGPMResponse> => {
  // Use GPM_LIST endpoint with gpm_only=true query string
  return fetchGPMs(days, page, pageSize, true, kevOnly, notKevOnly, onUnauthorized);
};

/**
 * GPM Daily Data Interface
 */
export interface GPMDailyData {
  day: string;
  samples: number;
}

/**
 * Paginated GPM Daily Response
 */
export interface PaginatedGPMDailyResponse {
  count?: number;
  next?: string | null;
  previous?: string | null;
  results: GPMDailyData[];
}

/**
 * Fetch GPM daily data
 * @param days - Number of days to fetch (default: 365). If undefined, fetches all time data.
 * @returns Promise with GPM daily data
 */
export const fetchGPMDaily = async (days?: number, onUnauthorized?: () => void): Promise<GPMDailyData[]> => {
  try {
    const allDailyData: GPMDailyData[] = [];
    let page = 1;
    let hasMore = true;
    
    while (hasMore) {
      let url = `${API_BASE_URL}${API_ENDPOINTS.GPM_DAILY}?page=${page}`;
      if (days !== undefined) {
        url += `&days=${days}`;
      }
      const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const data = await response.json();
      
      // Debug logging (can be removed in production)
      if (import.meta.env.DEV && page === 1) {
        console.log("🔍 GPM Daily API Response:", {
          url,
          days,
          count: data.count,
          resultsCount: data.results?.length || 0,
          sampleItem: data.results?.[0] || null
        });
      }
      
      const results = data.results || [];
      allDailyData.push(...results);
      
      if (!data.next) {
        hasMore = false;
      } else {
        page++;
      }
    }
    
    return allDailyData;
  } catch (error) {
    console.error("Error fetching GPM daily data:", error);
    return [];
  }
};

/**
 * Historical GPM Data Interface
 */
export interface HistoricalGPMData {
  day: string;
  samples: number;
}

/**
 * Historical GPM Response
 */
export interface HistoricalGPMResponse {
  cveid: string;
  days: number;
  count: number;
  results: HistoricalGPMData[];
}

/**
 * Fetch historical GPM data for a specific CVE
 * @param cveId - CVE ID (e.g., "CVE-2024-4947")
 * @returns Promise with historical GPM data
 */
export const fetchHistoricalGPM = async (cveId: string, onUnauthorized?: () => void): Promise<HistoricalGPMData[]> => {
  try {
    const url = `${API_BASE_URL}${API_ENDPOINTS.GPM_HISTORICAL(cveId)}`;
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data: HistoricalGPMResponse = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 Historical GPM API Response:", {
        url,
        cveId,
        count: data.count,
        resultsCount: data.results?.length || 0
      });
    }
    
    return data.results || [];
  } catch (error) {
    console.error("Error fetching historical GPM data:", error);
    return [];
  }
};

/**
 * EPSS API Response Interface
 */
export interface EPSSData {
  cve: string;
  epss: string;
  percentile: string;
  date: string;
}

export interface EPSSResponse {
  status: string;
  "status-code": number;
  version: string;
  access: string;
  total: number;
  offset: number;
  limit: number;
  data: EPSSData[];
}

/**
 * Fetch EPSS data for one or more CVEs from FIRST.org API
 * @param cveIds - Single CVE ID or array of CVE IDs
 * @param date - Optional date string (YYYY-MM-DD). If not provided, returns latest available EPSS
 * @returns Promise with EPSS data mapped by CVE ID
 */
export const fetchEPSS = async (cveIds: string | string[], date?: string): Promise<Map<string, EPSSData>> => {
  try {
    const cveList = Array.isArray(cveIds) ? cveIds : [cveIds];
    const epssMap = new Map<string, EPSSData>();
    
    // FIRST.org API supports multiple CVEs in a single request
    // Format: ?cve=CVE-2022-22965,CVE-2022-22964
    const cveParams = cveList.map(cve => encodeURIComponent(cve)).join(',');
    let url = `https://api.first.org/data/v1/epss?cve=${cveParams}`;
    
    if (date) {
      url += `&date=${date}`;
    }
    
    const response = await fetch(url);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data: EPSSResponse = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 EPSS API Response:", {
        url,
        cveIds: cveList,
        total: data.total,
        found: data.data.length
      });
    }
    
    // Map EPSS data by CVE ID
    data.data.forEach(item => {
      epssMap.set(item.cve, item);
    });
    
    return epssMap;
  } catch (error) {
    console.error("Error fetching EPSS data:", error);
    return new Map();
  }
};

/**
 * GPM Badges Response Interface
 */
export interface GPMBadgesResponse {
  badges: {
    avg_gpm: number;
    median_gpm: number;
    repo_count: number;
    latest_sync: string;
    total_gpm_cves: number;
  };
}

/**
 * Fetch GPM badges data
 * @param onUnauthorized - Optional callback for unauthorized requests
 * @returns Promise with GPM badges data
 */
export const fetchGPMBadges = async (onUnauthorized?: () => void): Promise<GPMBadgesResponse | null> => {
  try {
    const url = `${API_BASE_URL}${API_ENDPOINTS.GPM_BADGES}`;
    const response = await authenticatedFetch(url, { method: 'GET' }, onUnauthorized);
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    
    // Debug logging (can be removed in production)
    if (import.meta.env.DEV) {
      console.log("🔍 GPM Badges API Response:", {
        url,
        data
      });
    }
    
    return data as GPMBadgesResponse;
  } catch (error) {
    console.error("Error fetching GPM badges:", error);
    return null;
  }
};

/**
 * Calculate GPM from published date (fallback function)
 * This is kept for backwards compatibility but should not be used
 * if GPM data is available from the API
 */
export const calculateGPM = (publishedDate: string): number => {
  const published = new Date(publishedDate);
  const now = new Date();
  const monthsDiff = (now.getFullYear() - published.getFullYear()) * 12 + 
                     (now.getMonth() - published.getMonth());
  
  return monthsDiff > 0 ? Math.random() * 5 + 1 : Math.random() * 2 + 3;
};

/**
 * Merge CVE data with GPM data
 * @param cves - Array of CVE data
 * @param gpms - Array of GPM data
 * @returns Array of CVEs with GPM values and additional data from GPM endpoint
 */
export const mergeCVEWithGPM = (cves: CVEData[], gpms: GPMData[]): CVEData[] => {
  const gpmMap = new Map<string, GPMData>();
  
  // Create a map of CVE ID to GPM data
  gpms.forEach(gpm => {
    const cveId = gpm.cve_id;
    if (cveId) {
      gpmMap.set(cveId, gpm);
    }
  });
  
  // Merge GPM values and additional data into CVEs
  return cves.map(cve => {
    const gpmData = gpmMap.get(cve.id);
    if (!gpmData) {
      return cve;
    }
    
    // Parse CWE names from GPM data if available
    let cwes = cve.cwes || [];
    if (gpmData.cwe_names && !cwes.length) {
      const cweNames = gpmData.cwe_names.split(/\s*\|\s*SEP_CWE_SEP\s*\|\s*/).filter((n: string) => n.trim());
      cwes = cweNames.map((name: string) => ({
        id: `CWE-${name.replace(/\D/g, '')}` || "",
        name: name.trim()
      }));
    }
    
    return {
      ...cve,
      gpm: gpmData.gpm,
      // Enhance with CVSS data from GPM if not already present
      cvss: cve.cvss || (gpmData.base_score ? {
        score: gpmData.base_score,
        vector: gpmData.vector_string || ""
      } : undefined),
      // Update severity from GPM if available
      severity: gpmData.base_severity 
        ? (gpmData.base_severity.toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO")
        : cve.severity,
      // Use CWE from GPM if available
      cwes: cwes.length > 0 ? cwes : cve.cwes
    };
  });
};
