"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Code2,
  FolderOpen,
  Zap,
  Shield,
  Loader2,
  AlertTriangle,
  CheckCircle,
} from "lucide-react";

type ScanMode = "fast" | "hybrid" | "deep";

export default function CodeScanPage() {
  const [path, setPath] = useState(".");
  const [mode, setMode] = useState<ScanMode>("hybrid");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const modes: { mode: ScanMode; label: string; desc: string }[] = [
    { mode: "fast", label: "FAST", desc: "Regex + Semantic (no AI)" },
    { mode: "hybrid", label: "HYBRID", desc: "Regex + AI Verification" },
    { mode: "deep", label: "DEEP", desc: "Full analysis + AI" },
  ];

  const handleScan = async () => {
    if (!path) return;
    setLoading(true);
    
    // API call would go here
    setTimeout(() => {
      setResult({
        status: "SAFE",
        files_scanned: 42,
        findings: [],
        summary: {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
        },
      });
      setLoading(false);
    }, 3000);
  };

  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Header */}
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          CODE_SCANNER
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} SAST_VULNERABILITY_DETECTION_ENGINE
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scan Config */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Code2 className="w-4 h-4" /> SCAN_CONFIGURATION
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            {/* Path Input */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                TARGET_DIRECTORY
              </label>
              <div className="flex gap-2">
                <Input
                  type="text"
                  value={path}
                  onChange={(e) => setPath(e.target.value)}
                  placeholder="./src"
                  className="bg-black border-hacker-green/30 text-foreground placeholder:text-hacker-green/30 focus:border-hacker-green"
                />
                <Button variant="outline" size="icon">
                  <FolderOpen className="w-4 h-4" />
                </Button>
              </div>
            </div>

            {/* Scan Mode */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                SCAN_MODE
              </label>
              <div className="grid grid-cols-3 gap-2">
                {modes.map(({ mode: m, label, desc }) => (
                  <button
                    key={m}
                    onClick={() => setMode(m)}
                    className={`flex flex-col items-center p-3 rounded-md border transition-colors ${
                      mode === m
                        ? "border-hacker-green bg-hacker-green/10 text-hacker-green"
                        : "border-border text-muted-foreground hover:border-hacker-green/50"
                    }`}
                  >
                    {m === "fast" && <Zap className="w-4 h-4 mb-1" />}
                    {m === "hybrid" && <Shield className="w-4 h-4 mb-1" />}
                    {m === "deep" && <Code2 className="w-4 h-4 mb-1" />}
                    <span className="text-xs font-bold">{label}</span>
                    <span className="text-[10px] text-muted-foreground mt-1">
                      {desc}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Options */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                FAIL_THRESHOLD
              </label>
              <select
                className="w-full bg-black border border-hacker-green/30 rounded-md px-3 py-2 text-sm text-foreground focus:outline-none focus:border-hacker-green"
              >
                <option value="">None</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>

            {/* Submit */}
            <Button
              variant="hacker"
              className="w-full"
              onClick={handleScan}
              disabled={loading || !path}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  SCANNING_FILES...
                </>
              ) : (
                <>
                  <Code2 className="mr-2 h-4 w-4" />
                  INITIATE_CODE_SCAN
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
                <Code2 className="w-12 h-12 text-hacker-green/20 mb-4" />
                <p className="text-hacker-green/50 font-mono text-sm uppercase">
                  NO_SCAN_RESULTS
                </p>
                <p className="text-muted-foreground text-xs mt-2">
                  Configure and run a scan to see results
                </p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-[300px]">
                <Loader2 className="w-12 h-12 text-hacker-green animate-spin mb-4" />
                <p className="text-hacker-green font-mono text-sm animate-pulse">
                  ANALYZING_CODEBASE...
                </p>
              </div>
            )}

            {result && !loading && (
              <div className="space-y-4 font-mono text-sm">
                {/* Status */}
                <div
                  className={`flex items-center justify-between p-3 rounded-md ${
                    result.status === "SAFE"
                      ? "bg-hacker-green/10"
                      : "bg-hacker-red/10"
                  }`}
                >
                  <span
                    className={
                      result.status === "SAFE"
                        ? "text-hacker-green"
                        : "text-hacker-red"
                    }
                  >
                    [STATUS]
                  </span>
                  <span className="flex items-center gap-2">
                    {result.status === "SAFE" ? (
                      <CheckCircle className="w-4 h-4 text-hacker-green" />
                    ) : (
                      <AlertTriangle className="w-4 h-4 text-hacker-red" />
                    )}
                    {result.status}
                  </span>
                </div>

                <div className="flex items-center justify-between p-3 bg-hacker-green/5 rounded-md">
                  <span className="text-hacker-green/70">[FILES]</span>
                  <span className="text-foreground">{result.files_scanned}</span>
                </div>

                {/* Summary */}
                <div className="border border-hacker-green/20 rounded-md p-4">
                  <div className="text-xs text-hacker-green/70 uppercase mb-3">
                    VULNERABILITY_SUMMARY
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div className="flex justify-between p-2 bg-hacker-red/10 rounded">
                      <span className="text-hacker-red">Critical</span>
                      <span className="font-bold">{result.summary.critical}</span>
                    </div>
                    <div className="flex justify-between p-2 bg-orange-500/10 rounded">
                      <span className="text-orange-500">High</span>
                      <span className="font-bold">{result.summary.high}</span>
                    </div>
                    <div className="flex justify-between p-2 bg-yellow-500/10 rounded">
                      <span className="text-yellow-500">Medium</span>
                      <span className="font-bold">{result.summary.medium}</span>
                    </div>
                    <div className="flex justify-between p-2 bg-hacker-green/10 rounded">
                      <span className="text-hacker-green">Low</span>
                      <span className="font-bold">{result.summary.low}</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
