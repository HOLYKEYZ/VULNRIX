"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Shield,
  Upload,
  FileCheck,
  Loader2,
  AlertTriangle,
  CheckCircle,
  ExternalLink,
} from "lucide-react";

export default function VirusTotalPage() {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    
    const formData = new FormData();
    formData.append("file", file);
    
    try {
      const response = await fetch("/api/v1/virustotal/scan", {
        method: "POST",
        body: formData,
      });
      const data = await response.json();
      setResult(data);
    } catch (err) {
      console.error(err);
    }
    
    setLoading(false);
  };

  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Header */}
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          VIRUSTOTAL_CHECK
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} FILE_MALWARE_SCANNING_ENGINE
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Upload className="w-4 h-4" /> UPLOAD_FILE
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            {/* Drag & Drop Zone */}
            <div className="border-2 border-dashed border-hacker-green/30 rounded-lg p-8 text-center hover:border-hacker-green/60 transition-colors">
              <Upload className="w-12 h-12 text-hacker-green/30 mx-auto mb-4" />
              <p className="text-muted-foreground mb-4">
                Drag and drop a file here, or click to select
              </p>
              <input
                type="file"
                id="file-upload"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              <label htmlFor="file-upload">
                <Button variant="outline" asChild>
                  <span className="cursor-pointer">SELECT_FILE</span>
                </Button>
              </label>
            </div>

            {/* Selected File */}
            {file && (
              <div className="flex items-center justify-between p-3 bg-hacker-green/10 rounded-md">
                <div className="flex items-center gap-2">
                  <FileCheck className="w-4 h-4 text-hacker-green" />
                  <span className="text-sm">{file.name}</span>
                </div>
                <span className="text-xs text-muted-foreground">
                  {(file.size / 1024).toFixed(2)} KB
                </span>
              </div>
            )}

            {/* Submit */}
            <Button
              variant="hacker"
              className="w-full"
              onClick={handleUpload}
              disabled={loading || !file}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  SCANNING...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  SCAN_WITH_VIRUSTOTAL
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
                <Shield className="w-12 h-12 text-hacker-green/20 mb-4" />
                <p className="text-hacker-green/50 font-mono text-sm uppercase">
                  NO_FILE_SCANNED
                </p>
                <p className="text-muted-foreground text-xs mt-2">
                  Upload a file to scan with VirusTotal
                </p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-[300px]">
                <Loader2 className="w-12 h-12 text-hacker-green animate-spin mb-4" />
                <p className="text-hacker-green font-mono text-sm animate-pulse">
                  ANALYZING_FILE...
                </p>
              </div>
            )}

            {result && !loading && (
              <div className="space-y-4 font-mono text-sm">
                <div
                  className={`flex items-center justify-between p-3 rounded-md ${
                    result.malicious > 0 ? "bg-hacker-red/10" : "bg-hacker-green/10"
                  }`}
                >
                  <span className={result.malicious > 0 ? "text-hacker-red" : "text-hacker-green"}>
                    [STATUS]
                  </span>
                  {result.malicious > 0 ? (
                    <span className="flex items-center gap-2 text-hacker-red">
                      <AlertTriangle className="w-4 h-4" /> DETECTED
                    </span>
                  ) : (
                    <span className="flex items-center gap-2 text-hacker-green">
                      <CheckCircle className="w-4 h-4" /> CLEAN
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-2">
                  <div className="p-3 bg-hacker-red/10 rounded">
                    <div className="text-xs text-hacker-red/70 mb-1">MALICIOUS</div>
                    <div className="text-xl font-bold text-hacker-red">{result.malicious || 0}</div>
                  </div>
                  <div className="p-3 bg-yellow-500/10 rounded">
                    <div className="text-xs text-yellow-500/70 mb-1">SUSPICIOUS</div>
                    <div className="text-xl font-bold text-yellow-500">{result.suspicious || 0}</div>
                  </div>
                  <div className="p-3 bg-hacker-green/10 rounded">
                    <div className="text-xs text-hacker-green/70 mb-1">UNDETECTED</div>
                    <div className="text-xl font-bold text-hacker-green">{result.undetected || 0}</div>
                  </div>
                  <div className="p-3 bg-hacker-green/10 rounded">
                    <div className="text-xs text-hacker-green/70 mb-1">TOTAL</div>
                    <div className="text-xl font-bold text-hacker-green">{result.total || 0}</div>
                  </div>
                </div>

                {result.permalink && (
                  <a
                    href={result.permalink}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 p-3 border border-hacker-green/30 rounded-md hover:bg-hacker-green/10 transition-colors"
                  >
                    <ExternalLink className="w-4 h-4" />
                    VIEW_FULL_REPORT
                  </a>
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
