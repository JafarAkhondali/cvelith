import { useParams, Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowLeft, ExternalLink, AlertCircle, Database, TrendingUp } from "lucide-react";
import { Progress } from "@/components/ui/progress";
import { fetchCVEDetail, fetchEPSS, HistoricalGPMData, CVEDetailResponse, GPMData } from "@/services/cveApi";
import { CircularProgress } from "@/components/CircularProgress";
import { Skeleton } from "@/components/ui/skeleton";
import { TrendChart } from "@/components/TrendChart";
import { useAuth } from "@/contexts/AuthContext";
import { API_BASE_URL, API_ENDPOINTS } from "@/config/api";
import { authenticatedFetch } from "@/utils/auth";

const CVEDetail = () => {
  const { id } = useParams<{ id: string }>();
  const { isAuthenticated, isInitialized, setShowLoginModal } = useAuth();
  const [cve, setCve] = useState<any>(null);
  const [historicalGPM, setHistoricalGPM] = useState<HistoricalGPMData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Show login modal if not authenticated after initialization
  useEffect(() => {
    if (isInitialized && !isAuthenticated) {
      setShowLoginModal(true);
    }
  }, [isInitialized, isAuthenticated, setShowLoginModal]);

  useEffect(() => {
    // Wait for auth initialization and ensure user is authenticated
    if (!isInitialized || !isAuthenticated || !id) {
      return;
    }

    const loadCVE = async () => {
      setLoading(true);
      setError(null);
      
      const handleUnauthorized = () => {
        setShowLoginModal(true);
      };
      
      // Helper function to format dates
      const formatDate = (dateStr: string | null | undefined) => {
        if (!dateStr) return null;
        try {
          return new Date(dateStr).toISOString().split('T')[0];
        } catch {
          return null;
        }
      };

      // Helper function to extract KEV date from various formats
      const extractKEVDate = (kev: any) => {
        let kevDateRaw: string | null = null;
        let kevDateFormatted: string | null = null;
        let hasKEV = false;

        if (kev) {
          // Handle boolean true value (when is_kev is true)
          if (kev === true) {
            hasKEV = true;
            // No date provided, but CVE is in KEV
          } else if (Array.isArray(kev)) {
            const firstKEV = kev[0];
            if (typeof firstKEV === 'string') {
              kevDateRaw = firstKEV;
              kevDateFormatted = formatDate(firstKEV);
              hasKEV = true;
            } else if (firstKEV && typeof firstKEV === 'object') {
              const kevObj = firstKEV as { date?: string; organizer?: string; [key: string]: any };
              if (kevObj.date) {
                kevDateRaw = kevObj.date;
                kevDateFormatted = formatDate(kevObj.date);
                hasKEV = true;
              }
            }
          } else if (typeof kev === 'string' && kev !== "") {
            kevDateRaw = kev;
            kevDateFormatted = formatDate(kev);
            hasKEV = true;
          }
        }

        return { raw: kevDateRaw, formatted: kevDateFormatted, hasKEV };
      };
      
      try {
        // Try to fetch CVE detail first
        let cveDetail: CVEDetailResponse | null = null;
        try {
          cveDetail = await fetchCVEDetail(id, handleUnauthorized);
        } catch (err) {
          console.warn("CVE detail endpoint not available, will try GPM data:", err);
        }

        // Fetch GPM data - make a single request to avoid duplicate calls
        // The endpoint /api/v1/gpm/{id}/ can return either current GPM data or historical data
        let gpmData: GPMData | null = null;
        let historical: HistoricalGPMData[] = [];
        
        try {
          // Make a single request to the GPM endpoint
          const url = `${API_BASE_URL}${API_ENDPOINTS.GPM_SINGLE(id)}`;
          const response = await authenticatedFetch(url, { method: 'GET' }, handleUnauthorized);
          
          if (response.ok) {
            const data = await response.json();
            
            // Check if the response is historical data format (has 'results' array with 'day' and 'samples')
            if (data.results && Array.isArray(data.results) && data.results.length > 0 && 'day' in data.results[0]) {
              // It's historical GPM data
              historical = data.results;
              setHistoricalGPM(historical);
            } else if (data.cve_id || data.cveid || data.gpm !== undefined) {
              // It's current GPM data
              gpmData = {
                ...data,
                cve_id: data.cve_id || data.cveid || id
              } as GPMData;
            } else if (data.results && Array.isArray(data.results)) {
              // Check if results array contains GPM data objects
              const firstResult = data.results[0];
              if (firstResult && (firstResult.cve_id || firstResult.cveid)) {
                gpmData = {
                  ...firstResult,
                  cve_id: firstResult.cve_id || firstResult.cveid
                } as GPMData;
              }
            }
          }
        } catch (err) {
          console.warn("GPM data endpoint not available:", err);
        }

        // If neither CVE detail nor GPM data is available, show error
        if (!cveDetail && !gpmData && historical.length === 0) {
          setError(`CVE ${id} not found in CVE or GPM data`);
          setLoading(false);
          return;
        }
        
        // Set historical GPM if we got it
        if (historical.length > 0) {
          setHistoricalGPM(historical);
        }

        // Calculate GPM by summing samples
        const totalGPM = historical.reduce((sum, item) => sum + (item.samples || 0), 0) || gpmData?.gpm || 0;
        
        // Fetch EPSS data for this CVE (without date to get latest)
        let epssData = null;
        try {
          const epssMap = await fetchEPSS(id);
          epssData = epssMap.get(id) || null;
        } catch (err) {
          console.warn("EPSS data not available:", err);
        }
        
        // Get CVSS data - prefer from CVE detail, fallback to GPM data
        // If multiple CVSS scores exist, use the latest version (highest version number)
        let cvssData = null;
        if (cveDetail?.cvss && cveDetail.cvss.length > 0) {
          // Sort by version (descending) to get the latest
          const sortedCvss = [...cveDetail.cvss].sort((a, b) => {
            const versionA = parseFloat(a.version || "0");
            const versionB = parseFloat(b.version || "0");
            return versionB - versionA; // Descending order
          });
          cvssData = sortedCvss[0];
        } else if (gpmData?.base_score) {
          // Construct CVSS-like object from GPM data
          cvssData = {
            base_score: gpmData.base_score.toString(),
            base_severity: gpmData.base_severity || "INFO",
            vector_string: gpmData.vector_string || "",
            version: "3.1",
            metrics: {}
          };
        }

        // Get dates - prefer CVE detail, fallback to GPM data
        const publishedDate = formatDate(cveDetail?.date_published || gpmData?.date_published || gpmData?.published_date);
        const reservedDate = formatDate(cveDetail?.date_reserved);

        // Get KEV date - prefer CVE detail, fallback to GPM data
        // Check for is_kev boolean field first, then kev_date, then kev field
        const kevFromCVE = cveDetail?.kev;
        let kevFromGPM = gpmData?.kev;
        
        // Handle is_kev boolean field from API
        if (gpmData?.is_kev === true) {
          // If is_kev is true, use kev_date if available, otherwise use true to indicate KEV status
          kevFromGPM = gpmData.kev_date || gpmData.kev || true;
        }
        
        const kevInfo = extractKEVDate(kevFromCVE || kevFromGPM);

        // Get description - prefer CVE detail, fallback to GPM data
        const description = cveDetail?.description || gpmData?.description || "No description available.";

        // Get CWEs - prefer CVE detail, fallback to parsing from GPM data
        let cwes = cveDetail?.cwes?.map(cwe => ({
          id: cwe.id,
          name: cwe.name
        }));
        
        if (!cwes && gpmData?.cwe_names) {
          // Parse CWE names from GPM data (format: "CWE-22|SEP_CWE_SEP|CWE-79")
          const cweNames = gpmData.cwe_names.split(/\s*\|\s*SEP_CWE_SEP\s*\|\s*/).filter(n => n.trim());
          cwes = cweNames.map(name => ({
            id: name.trim(),
            name: name.trim()
          }));
        }

        // Get references - only from CVE detail (GPM doesn't have references)
        // Keep full reference objects with tag, description, and url
        const references = cveDetail?.references || [];

        // Determine severity - calculate from base_score if base_severity is invalid
        const getSeverityFromScore = (score: number): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" => {
          if (score >= 9.0) return "CRITICAL";
          if (score >= 7.0) return "HIGH";
          if (score >= 4.0) return "MEDIUM";
          if (score > 0) return "LOW";
          return "INFO";
        };

        const isValidSeverity = (severity: string | undefined | null): boolean => {
          if (!severity) return false;
          const upperSeverity = severity.toUpperCase();
          return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].includes(upperSeverity) && upperSeverity !== "?";
        };

        let severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" = "INFO";
        if (cvssData?.base_severity && isValidSeverity(cvssData.base_severity)) {
          severity = cvssData.base_severity.toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
        } else if (gpmData?.base_severity && isValidSeverity(gpmData.base_severity)) {
          severity = gpmData.base_severity.toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
        } else if (cvssData?.base_score) {
          // Calculate from base_score if severity is invalid
          severity = getSeverityFromScore(parseFloat(cvssData.base_score));
        } else if (gpmData?.base_score) {
          // Calculate from base_score if severity is invalid
          severity = getSeverityFromScore(gpmData.base_score);
        }

        const cveData = {
          id: cveDetail?.id || gpmData?.cve_id || id || "UNKNOWN",
          description: description,
          publishedDate: publishedDate || "",
          reservedDate: reservedDate,
          severity: severity,
          cvss: cvssData ? {
            score: parseFloat(cvssData.base_score),
            vector: cvssData.vector_string || "",
            version: parseFloat(cvssData.version || "3.1").toFixed(1),
            metrics: cvssData.metrics
          } : undefined,
          cwes: cwes || undefined,
          references: references.length > 0 ? references : undefined,
          gpm: totalGPM,
          epss: epssData ? parseFloat(epssData.epss) : undefined,
          epssPercentile: epssData ? parseFloat(epssData.percentile) : undefined,
          epssDate: epssData?.date || undefined,
          title: `${severity} Severity Vulnerability`,
          epssData: epssData ? {
            score: parseFloat(epssData.epss),
            percentile: parseFloat(epssData.percentile),
            date: epssData.date
          } : {
            score: 0,
            percentile: 0,
            date: undefined
          },
          kev: {
            inKEV: kevInfo.hasKEV,
            dateAdded: kevInfo.formatted || "",
            dueDate: ""
          },
          datePublished: cveDetail?.date_published || gpmData?.date_published || gpmData?.published_date,
          dateReserved: cveDetail?.date_reserved,
          kevDate: kevInfo.raw, // Store raw ISO date for chart matching
          hasCveDetail: !!cveDetail, // Flag to indicate if CVE detail was available
          hasGpmData: !!gpmData // Flag to indicate if GPM data was available
        };
        
        setCve(cveData);

        // Show warning if CVE detail is missing but GPM data is available
        if (!cveDetail && gpmData) {
          setError(`Note: CVE detail endpoint unavailable, showing available GPM data for ${id}`);
        }
      } catch (err) {
        console.error("Error loading CVE:", err);
        setError("Failed to load CVE data. Please check your API connection.");
      } finally {
        setLoading(false);
      }
    };
    loadCVE();
  }, [id, isInitialized, isAuthenticated, setShowLoginModal]);

  // Don't render content if not initialized or not authenticated
  // Wait for initialization to complete before showing anything
  if (!isInitialized) {
    return (
      <div className="min-h-screen p-6 md:p-8 lg:p-12 mesh-gradient">
        <div className="max-w-6xl mx-auto space-y-6">
          <Skeleton className="h-10 w-40" />
          <div className="space-y-4">
            <Skeleton className="h-12 w-64" />
            <Skeleton className="h-6 w-96" />
            <Skeleton className="h-4 w-48" />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <Skeleton className="h-64 w-full" />
              <Skeleton className="h-48 w-full" />
            </div>
            <div className="space-y-6">
              <Skeleton className="h-48 w-full" />
              <Skeleton className="h-48 w-full" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Show login modal if not authenticated after initialization
  if (!isAuthenticated) {
    return null; // Login modal will be shown by App component
  }

  if (loading) {
    return (
      <div className="min-h-screen p-6 md:p-8 lg:p-12 mesh-gradient">
        <div className="max-w-6xl mx-auto space-y-6">
          <Skeleton className="h-10 w-40" />
          <div className="space-y-4">
            <Skeleton className="h-12 w-64" />
            <Skeleton className="h-6 w-96" />
            <Skeleton className="h-4 w-48" />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 space-y-6">
              <Skeleton className="h-64 w-full" />
              <Skeleton className="h-48 w-full" />
            </div>
            <div className="space-y-6">
              <Skeleton className="h-48 w-full" />
              <Skeleton className="h-48 w-full" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  // Only show error page if we have no CVE data at all
  if (!cve) {
    return (
      <div className="min-h-screen p-6 md:p-8 lg:p-12 mesh-gradient flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold text-foreground mb-4">
            {error || "CVE Not Found"}
          </h2>
          <Link to="/">
            <Button>Return to Dashboard</Button>
          </Link>
        </div>
      </div>
    );
  }

  // Transform historical GPM data for chart and fill missing dates with 0
  const historicalGPMData = historicalGPM.sort((a, b) => new Date(a.day).getTime() - new Date(b.day).getTime());
  
  let chartData: any[] = [];
  
  if (historicalGPMData.length > 0) {
    const startDate = new Date(historicalGPMData[0].day);
    const endDate = new Date(historicalGPMData[historicalGPMData.length - 1].day);
    const dataMap = new Map<string, number>();
    
    // Map existing data
    historicalGPMData.forEach(item => {
      const dateKey = item.day;
      dataMap.set(dateKey, item.samples || 0);
    });
    
    // Fill missing dates with 0
    const allDates: string[] = [];
    const currentDate = new Date(startDate);
    while (currentDate <= endDate) {
      const dateKey = currentDate.toISOString().split('T')[0];
      allDates.push(dateKey);
      if (!dataMap.has(dateKey)) {
        dataMap.set(dateKey, 0);
      }
      currentDate.setDate(currentDate.getDate() + 1);
    }
    
    // Convert to chart data format
    chartData = allDates.map(dateKey => ({
      date: new Date(dateKey).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
      gpm: dataMap.get(dateKey) || 0,
      value: dataMap.get(dateKey) || 0,
      rawDate: dateKey // Keep raw date for reference line matching
    }));
  }

  return (
    <div className="min-h-screen p-6 md:p-8 lg:p-12 mesh-gradient">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Back Button */}
        <Link to="/">
          <Button variant="outline" className="gap-2">
            <ArrowLeft className="h-4 w-4" />
            Back to Dashboard
          </Button>
        </Link>

        {/* Header */}
        <div className="space-y-4 animate-fade-in">
          {/* Warning banner if CVE detail is missing but GPM data is available */}
          {error && error.includes("CVE detail endpoint unavailable") && (
            <div className="p-4 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-yellow-600 dark:text-yellow-400">
              <div className="flex items-center gap-2">
                <AlertCircle className="h-4 w-4" />
                <p className="text-sm font-medium">{error}</p>
              </div>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-4">
            <h1 className="text-3xl md:text-4xl font-bold gradient-text">{cve.id}</h1>
            <SeverityBadge severity={cve.severity} />
            {cve.kev.inKEV && (
              <Badge className="bg-critical text-white">
                <AlertCircle className="h-3 w-3 mr-1" />
                KEV Listed
              </Badge>
            )}
          </div>
          <h2 className="text-xl text-foreground/90">{cve.title}</h2>
          <div className="space-y-1">
            {!cve.hasCveDetail && !cve.hasGpmData ? (
              <div className="space-y-1">
                <p className="text-muted-foreground">
                  No CVE data available
                </p>
              </div>
            ) : cve.datePublished === null || cve.datePublished === undefined ? (
              <div className="space-y-1">
                <p className="text-muted-foreground">
                  Published: <span className="font-bold text-primary">0-DAY</span>{" "}
                  <a 
                    href={`https://nvd.nist.gov/vuln/detail/${id}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-primary hover:underline"
                  >
                    (View on NVD)
                  </a>
                </p>
                <p className="text-xs text-muted-foreground italic">
                  When CVE publish date is not known, it's possible that data sync is in progress.
                </p>
              </div>
            ) : (
              <p className="text-muted-foreground">
                Published: {cve.publishedDate || "N/A"}
              </p>
            )}
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Main Details */}
          <div className="lg:col-span-2 space-y-6">
            {/* GPM Card - Moved to top */}
            {cve.gpm !== undefined && (
              <Card className="glass-card border-border/50 animate-slide-up">
                <CardContent className="p-6">
                  <div className="flex items-center justify-between gap-6">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <TrendingUp className="h-5 w-5 text-foreground" />
                        <CardTitle className="text-foreground text-lg mb-0">GPM Metric</CardTitle>
                      </div>
                      <CardDescription className="text-xs mb-2">Measures the popularity of CVE exploits in GitHub</CardDescription>
                      <p className="text-xs text-muted-foreground">A GPM over <b>12</b> has <b>~50%</b> chance of being exploited in the wild.</p>
                    </div>
                    <div className="flex-shrink-0">
                      <div className="text-5xl font-bold gradient-text">{(cve.gpm ?? 0).toFixed(0)}</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Description */}
            <Card className="glass-card border-border/50 animate-slide-up">
              <CardHeader>
                <CardTitle className="text-foreground">Description</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-foreground/90 leading-relaxed">{cve.description}</p>
              </CardContent>
            </Card>

            {/* Historical GPM Chart */}
            {historicalGPM.length > 0 && (
              <Card className="glass-card border-border/50 animate-slide-up">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-foreground">
                    <TrendingUp className="h-5 w-5" />
                    Historical GPM Trend
                  </CardTitle>
                  <CardDescription>
                    Daily samples for {id} over time
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <TrendChart
                    title=""
                    description=""
                    data={chartData}
                    dataKey="gpm"
                    timeKey="date"
                    referenceLines={[
                      cve.datePublished ? { 
                        date: cve.datePublished, // Pass raw ISO date, chart will match it
                        label: 'Published', 
                        color: '#3b82f6' 
                      } : null,
                      cve.dateReserved ? { 
                        date: cve.dateReserved, // Pass raw ISO date, chart will match it
                        label: 'Reserved', 
                        color: '#10b981' 
                      } : null,
                      cve.kevDate ? { 
                        date: cve.kevDate, // Pass raw ISO date, chart will match it
                        label: 'KEV date added', 
                        color: '#ef4444' 
                      } : null
                    ].filter(Boolean) as Array<{ date: string; label: string; color: string }>}
                  />
                </CardContent>
              </Card>
            )}

            {/* CWEs */}
            {cve.cwes && cve.cwes.length > 0 && (
              <Card className="glass-card border-border/50 animate-slide-up">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-foreground">
                    <Database className="h-5 w-5" />
                    Common Weakness Enumeration (CWE)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {cve.cwes.map((cwe, idx) => {
                      // Extract CWE number from ID (e.g., "CWE-22" -> "22")
                      const cweNumber = cwe.id ? cwe.id.replace(/^CWE-?/i, '') : null;
                      const cweUrl = cweNumber ? `https://cwe.mitre.org/data/definitions/${cweNumber}.html` : null;
                      
                      return (
                        <div key={cwe.id || idx} className="flex items-center gap-3 p-3 bg-secondary/50 rounded-lg">
                          {cwe.id && cweUrl ? (
                            <a 
                              href={cweUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="hover:opacity-80 transition-opacity"
                            >
                              <Badge variant="outline" className="border-primary/50 cursor-pointer">
                                {cwe.id}
                              </Badge>
                            </a>
                          ) : cwe.id ? (
                            <Badge variant="outline" className="border-primary/50">
                              {cwe.id}
                            </Badge>
                          ) : null}
                          <span className="text-sm text-foreground/90">{cwe.name}</span>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Affected Products */}
            {cve.affectedProducts && cve.affectedProducts.length > 0 && (
              <Card className="glass-card border-border/50 animate-slide-up">
                <CardHeader>
                  <CardTitle className="text-foreground">Affected Products</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {cve.affectedProducts.map((product, idx) => (
                      <li key={idx} className="flex items-center gap-2 text-foreground/90">
                        <div className="h-1.5 w-1.5 rounded-full bg-primary" />
                        {product}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            {/* References */}
            {cve.references && cve.references.length > 0 && (
              <Card className="glass-card border-border/50 animate-slide-up lg:col-span-2">
                <CardHeader>
                  <CardTitle className="text-foreground">References</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {cve.references.map((ref, idx) => {
                      // Split tags by both double quote and comma
                      const parseTags = (tagString: string | undefined): string[] => {
                        if (!tagString) return [];
                        // Split by comma first, then by double quotes
                        return tagString
                          .split(',')
                          .flatMap(tag => tag.split('"'))
                          .map(tag => tag.trim())
                          .filter(tag => tag.length > 0);
                      };

                      const tags = parseTags(ref.tag);
                      const url = typeof ref === 'string' ? ref : ref.url;
                      const description = typeof ref === 'string' ? undefined : ref.description;
                      
                      return (
                        <div key={idx} className="p-3 bg-secondary/50 rounded-lg border border-border/50">
                          <div className="flex items-start gap-2">
                            <ExternalLink className="h-4 w-4 mt-1 text-primary flex-shrink-0" />
                            <div className="flex-1 min-w-0">
                              <a
                                href={url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-primary hover:text-primary/80 transition-colors break-all"
                              >
                                <span className="text-sm font-medium">{url}</span>
                              </a>
                              {tags.length > 0 && (
                                <div className="flex flex-wrap gap-1 mt-2">
                                  {tags.map((tag, tagIdx) => (
                                    <span
                                      key={tagIdx}
                                      className="px-2 py-1 text-xs bg-primary/10 text-primary rounded-md border border-primary/20"
                                    >
                                      {tag}
                                    </span>
                                  ))}
                                </div>
                              )}
                              {description && (
                                <p className="text-xs text-muted-foreground mt-2">{description}</p>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Right Column - Metrics */}
          <div className="space-y-6">
            {/* CVSS Score */}
            {cve.cvss && (
              <Card className="glass-card border-border/50 animate-slide-up">
                <CardHeader>
                  <CardTitle className="text-foreground">CVSS Metrics</CardTitle>
                  <CardDescription>Base Score v{cve.cvss.version || "3.1"}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="flex flex-col items-center justify-center">
                    <CircularProgress value={cve.cvss.score} max={10} size={140} strokeWidth={10}>
                      <div className="text-center">
                        <div className={`text-4xl font-bold ${cve.cvss.score >= 9.0 ? 'text-critical' : cve.cvss.score >= 7.0 ? 'text-orange-500' : cve.cvss.score >= 4.0 ? 'text-yellow-500' : 'text-green-500'}`}>
                          {cve.cvss.score.toFixed(2)}
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">Base Score</div>
                      </div>
                    </CircularProgress>
                  </div>
                  
                  {cve.cvss.vector && (
                    <div className="space-y-2">
                      <div className="text-sm font-semibold text-foreground">Vector String</div>
                      <p className="text-xs text-muted-foreground font-mono break-all bg-secondary/50 p-2 rounded">
                        {cve.cvss.vector}
                      </p>
                      
                      {/* Display CVSS metrics from API */}
                      {cve.cvss.metrics && (
                        <div className="space-y-2 mt-4">
                          <div className="text-sm font-semibold text-foreground">Metrics</div>
                          <div className="grid grid-cols-2 gap-2">
                            {Object.entries(cve.cvss.metrics).map(([key, value]) => {
                              // Skip non-metric fields
                              if (['scope', 'version', 'baseScore', 'baseSeverity', 'vectorString'].includes(key)) {
                                return null;
                              }
                              const metricName = key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase()).trim();
                              return (
                                <div key={key} className="flex justify-between items-center text-xs bg-secondary/30 p-2 rounded">
                                  <span className="text-muted-foreground">{metricName}:</span>
                                  <span className="font-semibold text-foreground">{String(value)}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* EPSS */}
            {cve.epssData && cve.epssData.score > 0 && (
              <Card className="glass-card border-border/50 animate-slide-up">
                <CardHeader>
                  <CardTitle className="text-foreground">EPSS</CardTitle>
                  <CardDescription>Likelihood (probability) this CVE will be exploited in the wild in next 30 days.</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  {cve.epssDate && (
                    <div className="text-xs text-muted-foreground">
                      Date: {new Date(cve.epssDate).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}
                    </div>
                  )}
                  <div>
                    <div className="flex justify-between mb-2">
                      <span className="text-sm text-muted-foreground">Probability</span>
                      <span className="text-sm font-semibold text-violet-500">
                        {(cve.epssData.score * 100).toFixed(2)}%
                      </span>
                    </div>
                    <Progress value={cve.epssData.score * 100} className="h-2" />
                  </div>
                  {cve.epssData.percentile > 0 && (
                    <div>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-muted-foreground">Percentile</span>
                        <span className="text-sm font-semibold text-violet-500">{(cve.epssData.percentile * 100).toFixed(1)}%</span>
                      </div>
                      <Progress value={cve.epssData.percentile * 100} className="h-2" />
                    </div>
                  )}
                </CardContent>
              </Card>
            )}

            {/* KEV Status */}
            {cve.kev.inKEV && (
              <Card className="glass-card border-critical/30 animate-slide-up animate-glow">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-critical">
                    <AlertCircle className="h-5 w-5" />
                    KEV Status
                  </CardTitle>
                  <CardDescription>Known Exploited Vulnerability</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-sm text-muted-foreground">Date Added to KEV</span>
                    <span className="text-sm font-semibold text-foreground">
                      {cve.kev.dateAdded 
                        ? new Date(cve.kev.dateAdded).toLocaleDateString('en-US', { 
                            year: 'numeric', 
                            month: 'short', 
                            day: 'numeric' 
                          })
                        : "N/A"}
                    </span>
                  </div>
                </CardContent>
              </Card>
            )}

          </div>
        </div>
      </div>
    </div>
  );
};

export default CVEDetail;
