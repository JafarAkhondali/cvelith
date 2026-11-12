import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { MetricCard } from "@/components/MetricCard";
import { TrendChart } from "@/components/TrendChart";
import { CVECard } from "@/components/CVECard";
import { TopGPMCard } from "@/components/TopGPMCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Activity, TrendingUp, AlertTriangle, Shield, LogOut, Search, Filter, ChevronLeft, ChevronRight, Database, Calendar } from "lucide-react";
import { fetchGPMDaily, fetchEPSS, CVEData, fetchGPMs, PaginatedGPMResponse, fetchGPMBadges, GPMBadgesResponse } from "@/services/cveApi";
import { GPMBadgesCard } from "@/components/GPMBadgesCard";
import { MetricCardSkeleton, CVECardSkeleton, ChartSkeleton } from "@/components/LoadingSkeleton";
import { useAuth } from "@/contexts/AuthContext";
import {
  Pagination,
  PaginationContent,
  PaginationItem,
  PaginationLink,
  PaginationNext,
  PaginationPrevious,
} from "@/components/ui/pagination";

const timeFrames = ["7D", "30D", "90D", "1Y", "ALL"];
const topCVETimeFrames = [
  { label: "Last day", value: 1 },
  { label: "7 Days", value: 7 },
  { label: "30 Days", value: 30 },
  { label: "90 Days", value: 90 },
  { label: "1 Year", value: 365 },
  { label: "All Time", value: null }
];

/**
 * Transform GPM daily data for chart display
 * Converts API response to chart-friendly format with different aggregation levels
 */
type AggregationLevel = "daily" | "weekly" | "monthly" | "yearly";

const aggregationLevels: AggregationLevel[] = ["daily", "weekly", "monthly", "yearly"];

const transformGPMDailyData = (dailyData: any[], aggregation: AggregationLevel = "daily") => {
  if (!dailyData || dailyData.length === 0) {
    return [];
  }

  const groupedMap = new Map<string, { samples: number }>();

  dailyData.forEach(item => {
    const date = new Date(item.day);
    let key: string;
    let labelPrefix: string;

    if (aggregation === "daily") {
      key = date.toISOString().split('T')[0];
      labelPrefix = "";
    } else if (aggregation === "weekly") {
      const weekStart = new Date(date);
      weekStart.setDate(date.getDate() - date.getDay()); // Start of week (Sunday)
      key = weekStart.toISOString().split('T')[0];
      labelPrefix = "Week ";
    } else if (aggregation === "monthly") {
      key = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-01`;
      labelPrefix = "";
    } else if (aggregation === "yearly") {
      key = `${date.getFullYear()}-01-01`;
      labelPrefix = "";
    } else {
      key = date.toISOString().split('T')[0];
      labelPrefix = "";
    }

    const existing = groupedMap.get(key) || { samples: 0 };
    groupedMap.set(key, {
      samples: existing.samples + (item.samples || 0)
    });
  });

  return Array.from(groupedMap.entries())
    .map(([dateKey, data]) => {
      const date = new Date(dateKey);
      let formattedDate: string;

      if (aggregation === "daily") {
        formattedDate = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
      } else if (aggregation === "weekly") {
        formattedDate = `Week ${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;
      } else if (aggregation === "monthly") {
        formattedDate = date.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
      } else if (aggregation === "yearly") {
        formattedDate = date.getFullYear().toString();
      } else {
        formattedDate = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
      }

      return {
        date: formattedDate,
        gpm: data.samples, // Use sum
        value: data.samples,
        sortDate: date.getTime() // For proper sorting
      };
    })
    .sort((a, b) => a.sortDate - b.sortDate)
    .map(({ sortDate, ...item }) => item); // Remove sortDate from final output
};

const Dashboard = () => {
  const { isAuthenticated, isInitialized, logout, setShowLoginModal } = useAuth();
  const navigate = useNavigate();
  const [selectedTimeFrame, setSelectedTimeFrame] = useState("ALL"); // Default to All Time
  const [selectedTopCVETimeFrame, setSelectedTopCVETimeFrame] = useState<number | null>(7);
  const [customDays, setCustomDays] = useState<string>("");
  const [showCustomDays, setShowCustomDays] = useState(false);
  const [chartCustomDays, setChartCustomDays] = useState<string>("");
  const [showChartCustomDays, setShowChartCustomDays] = useState(false);
  const [chartDays, setChartDays] = useState<number | null>(10950); // Default to All Time (10950 days)
  const [chartAggregation, setChartAggregation] = useState<AggregationLevel>("monthly"); // Default to Monthly
  const [recentCVEs, setRecentCVEs] = useState<CVEData[]>([]);
  const [trendData, setTrendData] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<"all" | "gpm_only" | "kev_only" | "not_kev_only">("all");
  const [cveSearchInput, setCveSearchInput] = useState<string>("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [itemsPerPage, setItemsPerPage] = useState(50); // Default page size
  const [gpmBadges, setGpmBadges] = useState<GPMBadgesResponse | null>(null);
  const [badgesLoading, setBadgesLoading] = useState(true);
  const [currentGpmResponse, setCurrentGpmResponse] = useState<PaginatedGPMResponse | null>(null);

  // Show login modal if not authenticated after initialization
  useEffect(() => {
    if (isInitialized && !isAuthenticated) {
      setShowLoginModal(true);
    }
  }, [isInitialized, isAuthenticated, setShowLoginModal]);

  const handleUnauthorized = () => {
    setShowLoginModal(true);
  };

  // Load CVEs and GPM data - only after authentication is confirmed
  useEffect(() => {
    // Wait for auth initialization and ensure user is authenticated
    if (!isInitialized || !isAuthenticated) {
      return;
    }

    const loadData = async () => {
      setLoading(true);
      setError(null);
      
      try {
        // Fetch GPM data - this contains all the information we need!
        // Only send days parameter if it's not "All Time" (null)
        const daysForGPM = selectedTopCVETimeFrame !== null ? selectedTopCVETimeFrame : undefined;
        
        // Determine filter parameters based on filterType
        const gpmOnly = filterType === "gpm_only";
        const kevOnly = filterType === "kev_only";
        const notKevOnly = filterType === "not_kev_only";
        
        // Fetch GPM data with appropriate filters and page size
        const gpmResponse = await fetchGPMs(daysForGPM, currentPage, itemsPerPage, gpmOnly, kevOnly, notKevOnly, handleUnauthorized);
        
        const gpms = gpmResponse.results;
        
        // Store response for pagination check
        setCurrentGpmResponse(gpmResponse);
        
        // Update pagination info using new format
        if (gpmResponse.page_size !== undefined) {
          setItemsPerPage(gpmResponse.page_size);
        } else if (gpms.length > 0) {
          // Fallback: use actual items per page from response
          setItemsPerPage(gpms.length);
        }
        
        if (gpmResponse.count !== undefined) {
          setTotalCount(gpmResponse.count);
          
          // Calculate total pages based on count and page size
          const pageSize = gpmResponse.page_size || itemsPerPage;
          let calculatedPages = Math.ceil(gpmResponse.count / pageSize);
          
          // If has_next is true, ensure we show at least current page + 1
          if (gpmResponse.has_next === true) {
            calculatedPages = Math.max(calculatedPages, currentPage + 1);
          }
          
          setTotalPages(calculatedPages > 0 ? calculatedPages : 1);
        } else {
          // If count is not provided, use has_next to determine pagination
          if (gpmResponse.has_next === true) {
            // If has_next is true, there's at least one more page
            setTotalPages(currentPage + 1);
          } else if (gpmResponse.has_next === false) {
            // If has_next is explicitly false, we're on the last page
            setTotalPages(currentPage);
          } else {
            // Fallback to old format (next/previous)
            if (gpmResponse.next) {
              setTotalPages(currentPage + 1);
            } else if (gpmResponse.previous) {
              setTotalPages(currentPage);
            } else {
              setTotalPages(1);
            }
          }
        }
        
        if (gpms.length === 0) {
          setRecentCVEs([]);
          setLoading(false);
          return;
        }
        
        // Convert GPM data directly to CVE objects (no need for CVE detail API calls)
        const cveIds = gpms.map(gpm => gpm.cve_id);
        
        // Fetch EPSS data for all CVEs at once (optimized)
        // Use latest_sync date from gpm-badges if available (access from state, not dependency)
        const badgesData = gpmBadges?.badges.latest_sync;
        const epssDate = badgesData || undefined;
        const epssMap = await fetchEPSS(cveIds, epssDate);
        
        const cves: CVEData[] = gpms.map((gpm) => {
          const cweNames = gpm.cwe_names ? gpm.cwe_names.split(/\s*\|\s*SEP_CWE_SEP\s*\|\s*/).filter(n => n.trim()) : [];
          const epssData = epssMap.get(gpm.cve_id);
          
          // Format published date properly
          const publishedDate = gpm.date_published || gpm.published_date || gpm.date || "";
          const formattedDate = publishedDate 
            ? new Date(publishedDate).toLocaleDateString('en-US', { 
                year: 'numeric', 
                month: 'short', 
                day: 'numeric' 
              })
            : "";
          
          // Handle KEV data - check for is_kev boolean or kev field
          let kevValue: string | string[] | Array<{ date?: string; organizer?: string; [key: string]: any }> | null = null;
          if (gpm.is_kev === true) {
            // If is_kev is true, use kev_date if available, otherwise use a truthy value
            kevValue = gpm.kev_date || gpm.kev || true;
          } else if (gpm.kev) {
            kevValue = gpm.kev;
          }
          
          return {
            id: gpm.cve_id,
            description: gpm.description || (cweNames.length > 0 ? cweNames.join(", ") : `CVE ${gpm.cve_id}`),
            publishedDate: formattedDate,
            severity: (gpm.base_severity?.toUpperCase() || "INFO") as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
            cvss: gpm.base_score ? {
              score: gpm.base_score,
              vector: gpm.vector_string || ""
            } : undefined,
            cwes: cweNames.length > 0 ? cweNames.map(name => ({
              id: "",
              name: name.trim()
            })) : undefined,
            gpm: gpm.total_gpm ?? gpm.gpm, // Use total_gpm (absolute) if available, fallback to gpm
            relativeGpm: gpm.relative_gpm, // Use relative_gpm from API
            epss: epssData ? parseFloat(epssData.epss) : undefined,
            epssPercentile: epssData ? parseFloat(epssData.percentile) : undefined,
            kev: kevValue,
            datePublished: gpm.date_published
          };
        });
        
        // GPM API already filters by days and sorts by GPM, so we just use the data as-is
        setRecentCVEs(cves);
      } catch (err) {
        console.error("Error loading data:", err);
        setError("Failed to load data. Please check your API connection.");
      } finally {
        setLoading(false);
      }
    };
    
    loadData();
  }, [selectedTopCVETimeFrame, isInitialized, isAuthenticated, filterType, currentPage]);

  // Load GPM badges data - only after authentication is confirmed
  useEffect(() => {
    // Wait for auth initialization and ensure user is authenticated
    if (!isInitialized || !isAuthenticated) {
      return;
    }

    const loadBadges = async () => {
      setBadgesLoading(true);
      try {
        const badgesData = await fetchGPMBadges(handleUnauthorized);
        setGpmBadges(badgesData);
      } catch (err) {
        console.error("Error loading GPM badges:", err);
        setGpmBadges(null);
      } finally {
        setBadgesLoading(false);
      }
    };
    
    loadBadges();
  }, [isInitialized, isAuthenticated]);

  // Load GPM daily data for chart - only after authentication is confirmed
  useEffect(() => {
    // Wait for auth initialization and ensure user is authenticated
    if (!isInitialized || !isAuthenticated) {
      return;
    }

    const loadTrendData = async () => {
      try {
        // Use chartDays state (10950 for "all time")
        const daysForChart = chartDays ?? 365;
        const dailyData = await fetchGPMDaily(daysForChart, handleUnauthorized);
        const transformed = transformGPMDailyData(dailyData, chartAggregation);
        setTrendData(transformed);
      } catch (err) {
        console.error("Error loading GPM daily data:", err);
        setTrendData([]);
      }
    };
    
    loadTrendData();
  }, [chartDays, chartAggregation, isInitialized, isAuthenticated]);

  // Update chartDays when selectedTimeFrame changes (but not for CUSTOM)
  useEffect(() => {
    if (selectedTimeFrame === "CUSTOM") {
      return; // Don't override custom days
    }
    
    const daysMap: Record<string, number> = {
      "7D": 7,
      "30D": 30,
      "90D": 90,
      "1Y": 365,
      "ALL": 10950 // All time (30 years)
    };

    setChartDays(daysMap[selectedTimeFrame] ?? 10950);
  }, [selectedTimeFrame]);

  // Handle custom days input for CVE list
  const handleCustomDaysSubmit = () => {
    const days = parseInt(customDays);
    if (!isNaN(days) && days > 0) {
      setSelectedTopCVETimeFrame(days);
      setShowCustomDays(false);
      setCustomDays("");
    }
  };

  // Handle custom days input for chart
  const handleChartCustomDaysSubmit = () => {
    const days = parseInt(chartCustomDays);
    if (!isNaN(days) && days > 0) {
      setChartDays(days);
      setSelectedTimeFrame("CUSTOM");
      setShowChartCustomDays(false);
      setChartCustomDays("");
    }
  };

  // Handle CVE search
  const handleCVESearch = () => {
    const cveId = cveSearchInput.trim().toUpperCase();
    if (cveId) {
      // Navigate to CVE detail page
      navigate(`/cve/${cveId}`);
    }
  };

  // Handle filter type change
  const handleFilterChange = (value: "all" | "gpm_only" | "kev_only" | "not_kev_only") => {
    setFilterType(value);
    setCurrentPage(1); // Reset to first page when changing filter
  };

  // Handle page change
  const handlePageChange = (page: number) => {
    setCurrentPage(page);
    // Scroll to top of CVE section
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  // Don't render content if not authenticated (wait for initialization)
  if (!isInitialized || !isAuthenticated) {
    return null; // Login modal will be shown by App component
  }

  return (
    <div className="min-h-screen p-6 md:p-8 lg:p-12 mesh-gradient">
      <div className="max-w-7xl mx-auto space-y-8">
        {/* Header */}
        <div className="space-y-4 animate-fade-in">
          <div className="flex items-center justify-between">
            <h1 className="text-4xl md:text-5xl font-bold gradient-text">
              CVE GPM Trends Dashboard
            </h1>
            <Button
              variant="outline"
              size="sm"
              onClick={logout}
              className="flex items-center gap-2"
            >
              <LogOut className="h-4 w-4" />
              Logout
            </Button>
          </div>
          <p className="text-muted-foreground text-lg">
          GPM (GitHub Popularity Metric) is a metric designed to measure the popularity of CVE exploits in GitHub and reflect CVE-specific exploitation interest.
          </p>
          {error && (
            <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
              {error}
            </div>
          )}
        </div>

        {/* CVE Search Section */}
        <div className="space-y-4 animate-fade-in">
          <div className="flex gap-2 items-center">
            <Input
              type="text"
              placeholder="Search for any CVE (e.g., CVE-2024-4947)"
              value={cveSearchInput}
              onChange={(e) => setCveSearchInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCVESearch()}
              className="max-w-md"
            />
            <Button
              onClick={handleCVESearch}
              className="gap-2"
            >
              <Search className="h-4 w-4" />
              Search CVE
            </Button>
          </div>
        </div>

        {/* Top GPM CVEs Section */}
        <div className="space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex flex-col gap-2">
              <h2 className="text-3xl font-bold text-foreground flex items-center gap-3">
                <span className="inline-block h-1.5 w-16 bg-gradient-to-r from-primary via-accent to-primary rounded-full animate-pulse"></span>
                {filterType === "gpm_only" ? "Unpublished GPM CVEs" : filterType === "kev_only" ? "KEV CVEs" : filterType === "not_kev_only" ? "Non-KEV CVEs" : "Top GPM CVEs Trends"}
              </h2>
              {gpmBadges?.badges.latest_sync && selectedTopCVETimeFrame !== null && (
                <p className="text-sm text-muted-foreground ml-20">
                  Based on data from {new Date(gpmBadges.badges.latest_sync).toLocaleDateString('en-US', { 
                    year: 'numeric', 
                    month: 'short', 
                    day: 'numeric' 
                  })} and {selectedTopCVETimeFrame} days before that
                </p>
              )}
            </div>
            <div className="flex gap-2 flex-wrap items-center">
              <Select value={filterType} onValueChange={handleFilterChange}>
                <SelectTrigger className="w-[200px] gap-2">
                  <Filter className="h-4 w-4" />
                  <SelectValue placeholder="Filter CVEs" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All CVEs</SelectItem>
                  <SelectItem value="gpm_only">Unpublished CVEs in GPM</SelectItem>
                  <SelectItem value="kev_only">KEV GPMs only</SelectItem>
                  <SelectItem value="not_kev_only">CVE GPMs not in KEV</SelectItem>
                </SelectContent>
              </Select>
              {topCVETimeFrames.map((tf) => (
                <Button
                  key={tf.label}
                  variant={selectedTopCVETimeFrame === tf.value ? "default" : "outline"}
                  onClick={() => {
                    setSelectedTopCVETimeFrame(tf.value);
                    setShowCustomDays(false);
                    setCurrentPage(1);
                  }}
                  className="transition-all duration-300"
                  size="sm"
                >
                  {tf.label}
                </Button>
              ))}
              {!showCustomDays ? (
                <Button
                  variant="outline"
                  onClick={() => setShowCustomDays(true)}
                  className="transition-all duration-300"
                  size="sm"
                >
                  Custom Days
                </Button>
              ) : (
                <div className="flex gap-2 items-center">
                  <Input
                    type="number"
                    placeholder="Days"
                    value={customDays}
                    onChange={(e) => setCustomDays(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleCustomDaysSubmit()}
                    className="w-20 h-8"
                    min="1"
                  />
                  <Button
                    variant="default"
                    onClick={handleCustomDaysSubmit}
                    size="sm"
                    className="h-8"
                  >
                    Apply
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setShowCustomDays(false);
                      setCustomDays("");
                    }}
                    size="sm"
                    className="h-8"
                  >
                    Cancel
                  </Button>
                </div>
              )}
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
            {loading ? (
              <>
                <CVECardSkeleton />
                <CVECardSkeleton />
                <CVECardSkeleton />
                <CVECardSkeleton />
                <CVECardSkeleton />
                <CVECardSkeleton />
              </>
            ) : recentCVEs.length === 0 ? (
              <div className="col-span-full text-center p-8 text-muted-foreground">
                No CVEs found for the selected timeframe
              </div>
            ) : (
              recentCVEs.map((cve, index) => {
                // Calculate rank based on current page and items per page
                const rank = (currentPage - 1) * itemsPerPage + index + 1;
                return (
                  <TopGPMCard 
                    key={cve.id} 
                    rank={rank}
                    id={cve.id}
                    severity={cve.severity}
                    description={cve.description}
                    publishedDate={cve.publishedDate}
                    gpm={cve.gpm}
                    cvssScore={cve.cvss?.score}
                    epss={cve.epss}
                    datePublished={cve.datePublished}
                    kev={cve.kev}
                    relativeGpm={cve.relativeGpm}
                  />
                );
              })
            )}
          </div>
          
          {/* Pagination */}
          {!loading && recentCVEs.length > 0 && (currentGpmResponse?.has_next === true || currentGpmResponse?.previous || currentGpmResponse?.next) && (
            <div className="flex justify-center mt-6">
              <Pagination>
                <PaginationContent>
                  <PaginationItem>
                    <Button
                      variant="ghost"
                      size="default"
                      onClick={() => currentPage > 1 && handlePageChange(currentPage - 1)}
                      disabled={currentPage === 1 || !currentGpmResponse?.previous}
                      className="gap-1 pl-2.5"
                    >
                      <ChevronLeft className="h-4 w-4" />
                      <span>Previous</span>
                    </Button>
                  </PaginationItem>
                  <PaginationItem>
                    <Button
                      variant="ghost"
                      size="default"
                      onClick={() => handlePageChange(currentPage + 1)}
                      disabled={currentGpmResponse?.has_next === false && !currentGpmResponse?.next}
                      className="gap-1 pr-2.5"
                    >
                      <span>Next</span>
                      <ChevronRight className="h-4 w-4" />
                    </Button>
                  </PaginationItem>
                </PaginationContent>
              </Pagination>
            </div>
          )}
        </div>

        {/* GPM Badges */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {badgesLoading ? (
            <>
              <MetricCardSkeleton />
              <MetricCardSkeleton />
              <MetricCardSkeleton />
              <MetricCardSkeleton />
            </>
          ) : gpmBadges ? (
            <>
              <GPMBadgesCard
                title="Average GPM"
                avgGpm={gpmBadges.badges.avg_gpm}
                medianGpm={gpmBadges.badges.median_gpm}
                icon={TrendingUp}
              />
              <MetricCard
                title="Total GPM CVEs"
                value={gpmBadges.badges.total_gpm_cves.toLocaleString()}
                change="Total CVEs with GPM data"
                changeType="neutral"
                icon={Database}
              />
              <MetricCard
                title="Repository Count"
                value={gpmBadges.badges.repo_count.toLocaleString()}
                change="Total repositories analyzed"
                changeType="neutral"
                icon={Activity}
              />
              <MetricCard
                title="Latest Sync"
                value={gpmBadges.badges.latest_sync 
                  ? new Date(gpmBadges.badges.latest_sync).toLocaleDateString('en-US', { 
                      year: 'numeric', 
                      month: 'short', 
                      day: 'numeric' 
                    })
                  : "N/A"
                }
                change="Last data synchronization"
                changeType="neutral"
                icon={Calendar}
              />
            </>
          ) : (
            <>
              <MetricCard
                title="Average GPM"
                value="Error"
                change="Failed to load badges"
                changeType="neutral"
                icon={TrendingUp}
              />
              <MetricCard
                title="Total GPM CVEs"
                value="Error"
                change="Failed to load badges"
                changeType="neutral"
                icon={Database}
              />
              <MetricCard
                title="Repository Count"
                value="Error"
                change="Failed to load badges"
                changeType="neutral"
                icon={Activity}
              />
              <MetricCard
                title="Latest Sync"
                value="Error"
                change="Failed to load badges"
                changeType="neutral"
                icon={Calendar}
              />
            </>
          )}
        </div>

        {/* Time Frame Selector */}
        <div className="space-y-4">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div className="flex gap-2 flex-wrap items-center">
              {timeFrames.map((tf) => (
                <Button
                  key={tf}
                  variant={selectedTimeFrame === tf ? "default" : "outline"}
                  onClick={() => {
                    setSelectedTimeFrame(tf);
                    setShowChartCustomDays(false);
                  }}
                  className="transition-all duration-300"
                >
                  {tf === "ALL" ? "All Time" : tf}
                </Button>
              ))}
              {selectedTimeFrame === "CUSTOM" && (
                <Button
                  variant="default"
                  className="transition-all duration-300"
                  disabled
                >
                  {chartDays} Days
                </Button>
              )}
              {!showChartCustomDays ? (
                <Button
                  variant="outline"
                  onClick={() => setShowChartCustomDays(true)}
                  className="transition-all duration-300"
                  size="sm"
                >
                  Custom Days
                </Button>
              ) : (
                <div className="flex gap-2 items-center">
                  <Input
                    type="number"
                    placeholder="Days"
                    value={chartCustomDays}
                    onChange={(e) => setChartCustomDays(e.target.value)}
                    onKeyDown={(e) => e.key === "Enter" && handleChartCustomDaysSubmit()}
                    className="w-20 h-8"
                    min="1"
                  />
                  <Button
                    variant="default"
                    onClick={handleChartCustomDaysSubmit}
                    size="sm"
                    className="h-8"
                  >
                    Apply
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => {
                      setShowChartCustomDays(false);
                      setChartCustomDays("");
                    }}
                    size="sm"
                    className="h-8"
                  >
                    Cancel
                  </Button>
                </div>
              )}
            </div>
            <div className="flex gap-2">
              {aggregationLevels.map((agg) => (
                <Button
                  key={agg}
                  variant={chartAggregation === agg ? "default" : "outline"}
                  onClick={() => setChartAggregation(agg)}
                  className="transition-all duration-300 capitalize"
                  size="sm"
                >
                  {agg}
                </Button>
              ))}
            </div>
          </div>

          {/* GPM Chart */}
          {loading ? (
            <ChartSkeleton />
          ) : trendData.length === 0 ? (
            <div className="glass-card border-border/50 p-8 text-center text-muted-foreground">
              No GPM trend data available for the selected timeframe
            </div>
          ) : (
            <TrendChart
              title="GPM Daily Trend"
              description={`GPM samples${chartDays !== null ? ` over the last ${chartDays} days` : ' (All Time)'} (${chartAggregation.charAt(0).toUpperCase() + chartAggregation.slice(1)} view)`}
              data={trendData}
              dataKey="gpm"
              showEvents={chartDays === 10950 && chartAggregation === "monthly"}
              aggregation={chartAggregation}
            />
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
