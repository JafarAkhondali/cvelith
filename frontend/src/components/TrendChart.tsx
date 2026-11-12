import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Area, AreaChart, ReferenceLine, Cell } from "recharts";
import { Heart, AlertTriangle, Zap, Shield } from "lucide-react";

interface ReferenceLine {
  date: string;
  label: string;
  color: string;
}

interface TrendChartProps {
  title: string;
  description: string;
  data: any[];
  dataKey: string;
  timeKey?: string;
  showEvents?: boolean;
  aggregation?: string;
  referenceLines?: ReferenceLine[];
}

interface SecurityEvent {
  name: string;
  cveId: string;
  month: string; // Format: "YYYY-MM" for monthly matching
  icon: any;
  color: string;
}

const securityEvents: SecurityEvent[] = [
  {
    name: "Heartbleed",
    cveId: "CVE-2014-0160",
    month: "2014-04",
    icon: Heart,
    color: "#ef4444"
  },
  {
    name: "Log4Shell",
    cveId: "CVE-2021-44228",
    month: "2021-12",
    icon: AlertTriangle,
    color: "#f59e0b"
  },
  {
    name: "Spring4Shell",
    cveId: "CVE-2022-22965",
    month: "2022-03",
    icon: Zap,
    color: "#8b5cf6"
  },
  {
    name: "Palo Alto CVE-2024-3400",
    cveId: "CVE-2024-3400",
    month: "2024-04",
    icon: Shield,
    color: "#3b82f6"
  }
];

export const TrendChart = ({ title, description, data, dataKey, timeKey = "date", showEvents = false, aggregation = "daily", referenceLines = [] }: TrendChartProps) => {
  // Find event positions in data for monthly view
  const getEventPositions = () => {
    if (!showEvents || aggregation !== "monthly" || !data || data.length === 0) {
      return [];
    }

    return securityEvents.map(event => {
      // Parse event month (format: "YYYY-MM")
      const eventDate = new Date(event.month + "-01");
      const eventYear = eventDate.getFullYear();
      const eventMonth = eventDate.getMonth(); // 0-indexed
      
      // Find the data point that matches this month
      // Monthly format is "Nov 2024" so we need to parse it
      const matchingPoint = data.find((point: any) => {
        try {
          const pointDate = new Date(point.date);
          // Handle both "Nov 2024" format and other formats
          if (!isNaN(pointDate.getTime())) {
            return pointDate.getFullYear() === eventYear && 
                   pointDate.getMonth() === eventMonth;
          }
          // Try parsing as "Month YYYY" format
          const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
          const parts = point.date.split(" ");
          if (parts.length === 2) {
            const monthIdx = monthNames.indexOf(parts[0]);
            const year = parseInt(parts[1]);
            if (monthIdx !== -1 && !isNaN(year)) {
              return year === eventYear && monthIdx === eventMonth;
            }
          }
        } catch {
          return false;
        }
        return false;
      });

      return {
        ...event,
        dataPoint: matchingPoint,
        dateStr: event.month
      };
    }).filter(e => e.dataPoint); // Only include events that have matching data points
  };

  const eventPositions = getEventPositions();
  
  // Find reference line positions in data
  const getReferenceLinePositions = () => {
    if (!referenceLines || referenceLines.length === 0 || !data || data.length === 0) {
      return [];
    }
    
    return referenceLines.map(refLine => {
      // Try to find matching data point
      // First try to parse the reference date
      let refDate: Date | null = null;
      try {
        refDate = new Date(refLine.date);
      } catch {
        return null;
      }
      
      if (!refDate || isNaN(refDate.getTime())) {
        return null;
      }
      
      // Try to find exact match first using rawDate if available
      let matchingPoint = data.find((point: any) => {
        if (point.rawDate) {
          try {
            const pointDate = new Date(point.rawDate);
            return pointDate.toDateString() === refDate!.toDateString();
          } catch {
            return false;
          }
        }
        return false;
      });
      
      // If no exact match, try matching formatted dates
      if (!matchingPoint) {
        matchingPoint = data.find((point: any) => {
          try {
            // Try parsing the formatted date
            const pointDate = new Date(point.date);
            if (!isNaN(pointDate.getTime())) {
              return pointDate.toDateString() === refDate!.toDateString();
            }
          } catch {
            return false;
          }
          return false;
        });
      }
      
      // If still no match, find the closest date
      if (!matchingPoint && data.length > 0) {
        let closest = data[0];
        let minDiff = Infinity;
        
        data.forEach((point: any) => {
          try {
            const pointDate = point.rawDate ? new Date(point.rawDate) : new Date(point.date);
            if (!isNaN(pointDate.getTime())) {
              const diff = Math.abs(pointDate.getTime() - refDate!.getTime());
              if (diff < minDiff) {
                minDiff = diff;
                closest = point;
              }
            }
          } catch {
            // Skip invalid dates
          }
        });
        
        // Use closest if within 7 days
        if (minDiff < 7 * 24 * 60 * 60 * 1000) {
          matchingPoint = closest;
        }
      }
      
      return matchingPoint ? {
        ...refLine,
        dataPoint: matchingPoint,
        dateValue: refLine.date
      } : null;
    }).filter(ref => ref !== null && ref.dataPoint) as Array<{ date: string; label: string; color: string; dataPoint: any; dateValue: string }>;
  };
  
  const referenceLinePositions = getReferenceLinePositions();
  
  // Determine if we should show the Card wrapper (only if title or description is provided)
  const showCardWrapper = title || description;
  
  const chartContent = (
    <>
      <ResponsiveContainer width="100%" height={300}>
        <AreaChart data={data}>
            <defs>
              <linearGradient id="colorValue" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="hsl(var(--primary))" stopOpacity={0.3}/>
                <stop offset="95%" stopColor="hsl(var(--primary))" stopOpacity={0}/>
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
            <XAxis 
              dataKey={timeKey} 
              stroke="hsl(var(--muted-foreground))"
              tick={{ fill: 'hsl(var(--muted-foreground))' }}
            />
            <YAxis 
              stroke="hsl(var(--muted-foreground))"
              tick={{ fill: 'hsl(var(--muted-foreground))' }}
              allowDecimals={false}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'hsl(var(--card))', 
                border: '1px solid hsl(var(--border))',
                borderRadius: '8px'
              }}
            />
            <Area 
              type="monotone" 
              dataKey={dataKey} 
              stroke="hsl(var(--primary))" 
              strokeWidth={2}
              fill="url(#colorValue)" 
            />
            {showEvents && aggregation === "monthly" && eventPositions.map((event, index) => {
              const Icon = event.icon;
              return (
                <ReferenceLine
                  key={`${event.cveId}-${index}`}
                  x={event.dataPoint.date}
                  stroke={event.color}
                  strokeWidth={2}
                  strokeDasharray="5 5"
                  label={{
                    value: `${event.name} (${event.cveId})`,
                    position: "top",
                    offset: 10,
                    fill: event.color,
                    fontSize: 12,
                    fontWeight: "bold"
                  }}
                />
              );
            })}
            {referenceLinePositions.map((refLine, index) => (
              <ReferenceLine
                key={`ref-${refLine.label}-${index}`}
                x={refLine.dataPoint.date}
                stroke={refLine.color}
                strokeWidth={2}
                strokeDasharray="5 5"
                label={{
                  value: refLine.label === 'KEV' ? 'KEV date added' : refLine.label,
                  position: "top",
                  offset: 10,
                  fill: refLine.color,
                  fontSize: 11,
                  fontWeight: "bold"
                }}
              />
            ))}
          </AreaChart>
        </ResponsiveContainer>
        {/* Reference Lines Legend */}
        {referenceLinePositions.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-4 justify-center text-xs">
            {referenceLinePositions.map((refLine, index) => {
              const isKEV = refLine.label === 'KEV' || refLine.label === 'KEV date added';
              const legendLabel = isKEV ? 'KEV date added' : refLine.label;
              
              return (
                <div 
                  key={`ref-legend-${index}`} 
                  className="flex items-center gap-2"
                  title={legendLabel}
                >
                  <div 
                    className="w-4 h-0.5 border-t-2 border-dashed" 
                    style={{ borderColor: refLine.color }}
                  />
                  <span className="text-muted-foreground">{legendLabel}</span>
                </div>
              );
            })}
          </div>
        )}
        {/* Event Legend */}
        {showEvents && aggregation === "monthly" && eventPositions.length > 0 && (
          <div className="mt-4 flex flex-wrap gap-4 justify-center">
            {eventPositions.map((event, index) => {
              const Icon = event.icon;
              return (
                <div key={`legend-${event.cveId}-${index}`} className="flex items-center gap-2 text-xs">
                  <Icon className="h-4 w-4" style={{ color: event.color }} />
                  <span className="font-semibold" style={{ color: event.color }}>{event.name}</span>
                  <span className="text-muted-foreground">({event.cveId})</span>
                </div>
              );
            })}
          </div>
        )}
    </>
  );
  
  // Conditionally wrap in Card if title/description provided
  if (showCardWrapper) {
    return (
      <Card className="glass-card border-border/50 animate-slide-up group relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-accent/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
        <CardHeader className="relative">
          <CardTitle className="text-foreground">{title}</CardTitle>
          <CardDescription className="text-muted-foreground">{description}</CardDescription>
        </CardHeader>
        <CardContent className="relative">
          {chartContent}
        </CardContent>
      </Card>
    );
  }
  
  return <div className="relative">{chartContent}</div>;
};
