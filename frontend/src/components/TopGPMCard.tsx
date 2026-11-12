import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "./SeverityBadge";
import { TrendingUp, Calendar, Shield, AlertCircle, Heart } from "lucide-react";
import { Link } from "react-router-dom";

interface TopGPMCardProps {
  rank: number;
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  publishedDate: string;
  gpm: number | undefined;
  relativeGpm?: number;
  cvssScore?: number;
  epss?: number;
  datePublished?: string | null;
  kev?: string | string[] | Array<{ date?: string; organizer?: string; [key: string]: any }> | boolean | null;
}

export const TopGPMCard = ({ rank, id, severity, description, publishedDate, gpm, relativeGpm, cvssScore, epss, datePublished, kev }: TopGPMCardProps) => {
  const getRankBadgeColor = () => {
    if (rank <= 3) return "from-amber-500 to-yellow-600";
    if (rank <= 10) return "from-slate-400 to-slate-600";
    return "from-slate-500 to-slate-700";
  };

  // Format published date - show 0-DAY if date_published is null
  const formatPublishedDate = () => {
    if (datePublished === null || datePublished === undefined) {
      return (
        <span className="font-bold text-primary">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              window.open(`https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`, '_blank', 'noopener,noreferrer');
            }}
            className="hover:underline bg-transparent border-none p-0 cursor-pointer text-primary font-bold"
            aria-label={`View ${id} on NVD`}
          >
            0-DAY
          </button>
        </span>
      );
    }
    return publishedDate || "N/A";
  };

  // Check if CVE is in KEV
  const isInKEV = () => {
    // Handle boolean true value (when is_kev is true)
    if (kev === true) return true;
    if (!kev) return false;
    if (typeof kev === 'string' && kev !== "") return true;
    if (Array.isArray(kev) && kev.length > 0) {
      const firstKEV = kev[0];
      if (typeof firstKEV === 'string') return true;
      if (typeof firstKEV === 'object' && firstKEV?.date) return true;
    }
    return false;
  };

  // Get KEV date for display
  const getKEVDate = () => {
    if (kev === true) return null; // Boolean true means in KEV but no date provided
    if (!kev) return null;
    if (typeof kev === 'string') return kev;
    if (Array.isArray(kev) && kev.length > 0) {
      const firstKEV = kev[0];
      if (typeof firstKEV === 'string') return firstKEV;
      if (typeof firstKEV === 'object' && firstKEV?.date) return firstKEV.date;
    }
    return null;
  };

  return (
    <Link to={`/cve/${id}`}>
      <Card className="glass-card border-border/50 cursor-pointer group animate-fade-in relative overflow-hidden h-full">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-accent/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-primary/10 to-transparent blur-3xl group-hover:blur-2xl transition-all duration-500" />
        
        <CardHeader className="relative space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className={`flex items-center justify-center w-12 h-12 rounded-xl bg-gradient-to-br ${getRankBadgeColor()} text-white font-bold text-lg shadow-lg`}>
                #{rank}
              </div>
              <div>
                <CardTitle className="text-lg font-semibold text-foreground group-hover:text-primary transition-colors">
                  {id}
                </CardTitle>
                <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                  <Calendar className="h-3 w-3" />
                  {formatPublishedDate()}
                </div>
              </div>
            </div>
            <div className="flex flex-col items-end gap-2">
              <SeverityBadge severity={severity} />
              {isInKEV() && (
                <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-critical/20 border border-critical/30">
                  <AlertCircle className="h-3 w-3 text-critical" />
                  <span className="text-xs font-semibold text-critical">KEV</span>
                </div>
              )}
            </div>
          </div>
        </CardHeader>

        <CardContent className="relative space-y-4">
          {description && (
            <div className="max-h-20 overflow-hidden">
              <p className="text-sm text-foreground/90 line-clamp-3 leading-relaxed">
                {description}
              </p>
            </div>
          )}

          <div className="grid grid-cols-3 gap-3">
            <div className="flex flex-col items-center justify-center p-3 rounded-lg bg-gradient-to-br from-primary/10 to-primary/5 border border-primary/20">
              <TrendingUp className="h-4 w-4 text-primary mb-1" />
              <span className="text-xs text-muted-foreground">GPM</span>
              {relativeGpm !== undefined && relativeGpm !== null ? (
                <div className="flex items-baseline gap-1.5 mt-1">
                  <span className="text-lg font-bold text-primary">{(gpm ?? 0).toFixed(0)}</span>
                  <span className="text-[11px] font-medium text-primary/50">(+{relativeGpm.toFixed(0)})</span>
                </div>
              ) : (
                <span className="text-lg font-bold text-primary mt-1">{(gpm ?? 0).toFixed(0)}</span>
              )}
            </div>
            
            {cvssScore !== undefined && (
              <div className="flex flex-col items-center justify-center p-3 rounded-lg bg-gradient-to-br from-blue-500/10 to-blue-500/5 border border-blue-500/20">
                <Shield className="h-4 w-4 text-blue-500 mb-1" />
                <span className="text-xs text-muted-foreground">CVSS</span>
                <span className="text-lg font-bold text-blue-500">{cvssScore.toFixed(1)}</span>
              </div>
            )}

            <div className="flex flex-col items-center justify-center p-3 rounded-lg bg-gradient-to-br from-violet-500/10 to-violet-500/5 border border-violet-500/20">
              <AlertCircle className="h-4 w-4 text-violet-500 mb-1" />
              <span className="text-xs text-muted-foreground">EPSS</span>
              <div className="text-sm font-semibold text-violet-500">
                {epss !== undefined ? `${(epss * 100).toFixed(2)}%` : "N/A"}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </Link>
  );
};
