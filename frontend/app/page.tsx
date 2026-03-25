import Link from "next/link";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Search, Code2, Terminal, ArrowRight } from "lucide-react";

// Trigger rebuild
export default function HomePage() {
  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh]">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Hero */}
      <div className="text-center mb-12">
        <h1 className="text-5xl font-bold tracking-tight mb-4 font-mono">
          <span className="text-hacker-green glitch-text">VULNRIX</span>
        </h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
          AI-Powered Static Code Analysis (SAST) & Digital Footprint Scanner
        </p>
        <p className="text-sm text-hacker-green/70 font-mono mt-2">
          {">"} The modern alternative to CodeQL
        </p>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 w-full max-w-5xl">
        <Link href="/osint">
          <Card className="terminal-border bg-black h-full hover:bg-hacker-green/5 transition-colors cursor-pointer group">
            <CardHeader>
              <div className="w-12 h-12 rounded-lg bg-hacker-green/20 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <Search className="w-6 h-6 text-hacker-green" />
              </div>
              <CardTitle className="text-hacker-green">OSINT Scanner</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                Scan emails, usernames, domains, phone numbers
              </p>
              <span className="text-hacker-green text-sm flex items-center gap-1">
                Start scan <ArrowRight className="w-4 h-4" />
              </span>
            </CardContent>
          </Card>
        </Link>

        <Link href="/scan">
          <Card className="terminal-border bg-black h-full hover:bg-hacker-green/5 transition-colors cursor-pointer group">
            <CardHeader>
              <div className="w-12 h-12 rounded-lg bg-hacker-green/20 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <Code2 className="w-6 h-6 text-hacker-green" />
              </div>
              <CardTitle className="text-hacker-green">Code Scanner</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                SAST vulnerability detection with AI verification
              </p>
              <span className="text-hacker-green text-sm flex items-center gap-1">
                Scan code <ArrowRight className="w-4 h-4" />
              </span>
            </CardContent>
          </Card>
        </Link>

        <Link href="/repo">
          <Card className="terminal-border bg-black h-full hover:bg-hacker-green/5 transition-colors cursor-pointer group">
            <CardHeader>
              <div className="w-12 h-12 rounded-lg bg-hacker-green/20 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <Terminal className="w-6 h-6 text-hacker-green" />
              </div>
              <CardTitle className="text-hacker-green">Repo Scan</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                Clone and scan GitHub repositories
              </p>
              <span className="text-hacker-green text-sm flex items-center gap-1">
                Scan repo <ArrowRight className="w-4 h-4" />
              </span>
            </CardContent>
          </Card>
        </Link>

        <Link href="/dashboard">
          <Card className="terminal-border bg-black h-full hover:bg-hacker-green/5 transition-colors cursor-pointer group">
            <CardHeader>
              <div className="w-12 h-12 rounded-lg bg-hacker-green/20 flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                <Shield className="w-6 h-6 text-hacker-green" />
              </div>
              <CardTitle className="text-hacker-green">Dashboard</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-muted-foreground mb-4">
                View scan history and security metrics
              </p>
              <span className="text-hacker-green text-sm flex items-center gap-1">
                View dashboard <ArrowRight className="w-4 h-4" />
              </span>
            </CardContent>
          </Card>
        </Link>
      </div>

      {/* Quick Scan Input */}
      <div className="mt-12 w-full max-w-md">
        <Card className="terminal-border bg-black">
          <CardContent className="p-6">
            <h3 className="text-hacker-green font-mono text-sm mb-4">
              QUICK_SCAN
            </h3>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="Enter email, domain, IP, or username..."
                className="flex-1 bg-black border border-hacker-green/30 rounded-md px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-hacker-green"
              />
              <Button variant="hacker">SCAN</Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
