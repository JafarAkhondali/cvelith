import { LucideIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface MetricCardProps {
  title: string;
  value: string | number;
  change?: string;
  changeType?: "positive" | "negative" | "neutral";
  icon: LucideIcon;
}

export const MetricCard = ({ title, value, change, changeType = "neutral", icon: Icon }: MetricCardProps) => {
  const changeColor = {
    positive: "text-low",
    negative: "text-critical",
    neutral: "text-muted-foreground"
  }[changeType];

  return (
    <Card className="glass-card border-border/50 group relative overflow-hidden animate-fade-in cursor-pointer">
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2 relative">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <div className="p-2 rounded-full bg-primary/10 group-hover:bg-primary/20 transition-colors">
          <Icon className="h-4 w-4 text-primary" />
        </div>
      </CardHeader>
      <CardContent className="relative">
        <div className="text-3xl font-bold gradient-text">{value}</div>
        {change && (
          <p className={`text-xs ${changeColor} mt-1 flex items-center gap-1`}>
            {change}
          </p>
        )}
      </CardContent>
    </Card>
  );
};
