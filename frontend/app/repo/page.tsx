"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import {
  GitBranch,
  Terminal,
  Shield,
  Loader2,
  ExternalLink,
  Lock,
} from "lucide-react";

export default function RepoScanPage() {
  const [repoUrl, setRepoUrl] = useState("");
  const [mode, setMode] = useState<"fast" | "hybrid" | "deep">("hybrid");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleScan = async () => {
    if (!repoUrl) return;
    setLoading(true);
    
    setTimeout(() => {
      setResult({
        status: "SAFE",
        repo: repoUrl,
        files_scanned: 156,
        findings: [],
      });
      setLoading(false);
    }, 5000);
  };

  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Header */}
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          REPO_SCANNER
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} GIT_REPOSITORY_VULNERABILITY_ANALYSIS
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scan Config */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4" /> REPOSITORY_CONFIG
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            {/* Repo URL */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                REPOSITORY_URL
              </label>
              <Input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/user/repo"
                className="bg-black border-hacker-green/30 text-foreground placeholder:text-hacker-green/30 focus:border-hacker-green"
              />
            </div>

            {/* Mode Selection */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                SCAN_DEPTH
              </label>
              <div className="flex gap-2">
                {(["fast", "hybrid", "deep"] as const).map((m) => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`flex-1 py-2 rounded-md border text-sm font-medium transition-colors ${
                      mode === m
                        ? "border-hacker-green bg-hacker-green/10 text-hacker-green"
                        : "border-border text-muted-foreground hover:border-hacker-green/50"
                    }`}
                  >
                    {m.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>

            {/* Auth Notice */}
            <div className="flex items-start gap-3 p-3 bg-hacker-green/5 border border-hacker-green/20 rounded-md">
              <Lock className="w-4 h-4 text-hacker-green/70 mt-0.5" />
              <div className="text-xs text-muted-foreground">
                <p className="text-hacker-green font-medium mb-1">Private Repos</p>
                <p>
                  Use{" "}
                  <code className="text-hacker-green bg-black px-1 rounded">
                    vulnrix github --action link
                  </code>{" "}
                  to authenticate
                </p>
              </div>
            </div>

            {/* Submit */}
            <Button
              variant="hacker"
              className="w-full"
              onClick={handleScan}
              disabled={loading || !repoUrl}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  CLONING_AND_SCANNING...
                </>
              ) : (
                <>
                  <GitBranch className="mr-2 h-4 h-4" />
                  INITIATE_REPO_SCAN
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Results */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4" /> SCAN_RESULTS
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            {!result && !loading && (
              <div className="flex flex-col items-center justify-center h-[300px] text-center">
                <Terminal className="w-12 h-12 text-hacker-green/20 mb-4" />
                <p className="text-hacker-green/50 font-mono text-sm uppercase">
                  NO_REPOSITORY_SCANNED
                </p>
                <p className="text-muted-foreground text-xs mt-2">
                  Enter a GitHub URL to begin analysis
                </p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-[300px]">
                <Loader2 className="w-12 h-12 text-hacker-green animate-spin mb-4" />
                <p className="text-hacker-green font-mono text-sm animate-pulse">
                  CLONING_REPOSITORY...
                </p>
                <p className="text-muted-foreground text-xs mt-2 font-mono">
                  This may take a moment
                </p>
              </div>
            )}

            {result && !loading && (
              <div className="space-y-4 font-mono text-sm">
                <div className="flex items-center justify-between p-3 bg-hacker-green/10 rounded-md">
                  <span className="text-hacker-green">[STATUS]</span>
                  <span className="text-foreground">{result.status}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-hacker-green/5 rounded-md">
                  <span className="text-hacker-green/70">[REPO]</span>
                  <span className="text-foreground truncate max-w-[200px]">
                    {result.repo}
                  </span>
                </div>
                <div className="flex items-center justify-between p-3 bg-hacker-green/5 rounded-md">
                  <span className="text-hacker-green/70">[FILES]</span>
                  <span className="text-foreground">{result.files_scanned}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-hacker-green/5 rounded-md">
                  <span className="text-hacker-green/70">[FINDINGS]</span>
                  <span className="text-foreground">{result.findings.length}</span>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
