import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { SeverityBadge } from "./SeverityBadge";
import { ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

interface CVECardProps {
  id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  description: string;
  publishedDate: string;
  gpm: number;
}

export const CVECard = ({ id, severity, description, publishedDate, gpm }: CVECardProps) => {
  return (
    <Link to={`/cve/${id}`}>
      <Card className="glass-card border-border/50 cursor-pointer group animate-fade-in relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-accent/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
        <CardHeader className="relative">
          <div className="flex items-center justify-between">
            <CardTitle className="text-lg font-semibold text-foreground group-hover:text-primary transition-colors">
              {id}
            </CardTitle>
            <SeverityBadge severity={severity} />
          </div>
          <CardDescription className="text-muted-foreground">
            Published: {publishedDate}
          </CardDescription>
        </CardHeader>
        <CardContent className="relative">
          <p className="text-sm text-foreground/90 mb-4 line-clamp-2">{description}</p>
          <div className="flex items-center justify-between">
            <div className="text-sm px-3 py-1 rounded-full bg-primary/10 border border-primary/20">
              <span className="text-muted-foreground">GPM: </span>
              <span className="font-semibold text-primary">{gpm.toFixed(2)}</span>
            </div>
            <ArrowRight className="h-4 w-4 text-primary group-hover:translate-x-2 transition-all duration-300" />
          </div>
        </CardContent>
      </Card>
    </Link>
  );
};
