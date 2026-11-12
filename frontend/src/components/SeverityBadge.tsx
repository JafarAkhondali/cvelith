import { Badge } from "@/components/ui/badge";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

interface SeverityBadgeProps {
  severity: Severity;
}

export const SeverityBadge = ({ severity }: SeverityBadgeProps) => {
  const severityConfig = {
    CRITICAL: { color: "bg-critical text-white", label: "Critical" },
    HIGH: { color: "bg-high text-white", label: "High" },
    MEDIUM: { color: "bg-medium text-background", label: "Medium" },
    LOW: { color: "bg-low text-background", label: "Low" },
    INFO: { color: "bg-info text-background", label: "Info" },
  };

  // Validate severity and provide fallback
  const normalizedSeverity = severity?.toUpperCase() as Severity;
  const config = severityConfig[normalizedSeverity] || severityConfig.INFO;

  return (
    <Badge className={`${config.color} font-semibold`}>
      {config.label}
    </Badge>
  );
};
