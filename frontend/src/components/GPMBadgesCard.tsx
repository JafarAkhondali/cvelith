import { LucideIcon } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

interface GPMBadgesCardProps {
  title: string;
  avgGpm: number;
  medianGpm: number;
  icon: LucideIcon;
}

export const GPMBadgesCard = ({ title, avgGpm, medianGpm, icon: Icon }: GPMBadgesCardProps) => {
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
        <div className="flex flex-col gap-1">
          <div className="text-3xl font-bold gradient-text">{avgGpm.toFixed(1)}</div>
          <p className="text-xs text-muted-foreground">
            Median: <span className="font-semibold text-foreground">{medianGpm.toFixed(1)}</span>
          </p>
        </div>
      </CardContent>
    </Card>
  );
};

