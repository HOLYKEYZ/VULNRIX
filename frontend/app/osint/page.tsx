"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import {
  Search,
  Mail,
  User,
  Globe,
  Phone,
  Shield,
  Loader2,
} from "lucide-react";

type ScanType = "email" | "username" | "domain" | "phone";

export default function OsintScanPage() {
  const [scanType, setScanType] = useState<ScanType>("email");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<any>(null);

  const scanTypes: { type: ScanType; label: string; icon: any; placeholder: string }[] = [
    { type: "email", label: "Email", icon: Mail, placeholder: "user@example.com" },
    { type: "username", label: "Username", icon: User, placeholder: "johndoe" },
    { type: "domain", label: "Domain", icon: Globe, placeholder: "example.com" },
    { type: "phone", label: "Phone", icon: Phone, placeholder: "+1234567890" },
  ];

  const handleScan = async () => {
    if (!value) return;
    setLoading(true);
    
    // API call would go here
    setTimeout(() => {
      setResult({
        status: "completed",
        type: scanType,
        value: value,
        findings: [],
      });
      setLoading(false);
    }, 2000);
  };

  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Header */}
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          OSINT_SCANNER
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} DIGITAL_FOOTPRINT_ANALYSIS_MODULE
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Scan Form */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Search className="w-4 h-4" /> INITIATE_SCAN
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            {/* Scan Type Selector */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                SCAN_TARGET_TYPE
              </label>
              <div className="grid grid-cols-2 gap-2">
                {scanTypes.map(({ type, label, icon: Icon }) => (
                  <button
                    key={type}
                    onClick={() => setScanType(type)}
                    className={`flex items-center gap-2 p-3 rounded-md border transition-colors ${
                      scanType === type
                        ? "border-hacker-green bg-hacker-green/10 text-hacker-green"
                        : "border-border text-muted-foreground hover:border-hacker-green/50"
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="text-sm font-medium">{label}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Input */}
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                TARGET_VALUE
              </label>
              <Input
                type="text"
                value={value}
                onChange={(e) => setValue(e.target.value)}
                placeholder={scanTypes.find((t) => t.type === scanType)?.placeholder}
                className="bg-black border-hacker-green/30 text-foreground placeholder:text-hacker-green/30 focus:border-hacker-green"
              />
            </div>

            {/* Options */}
            <div className="flex gap-4">
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" defaultChecked className="accent-hacker-green" />
                Include Dark Web
              </label>
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" defaultChecked className="accent-hacker-green" />
                Include Social Media
              </label>
            </div>

            {/* Submit */}
            <Button
              variant="hacker"
              className="w-full"
              onClick={handleScan}
              disabled={loading || !value}
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  SCANNING...
                </>
              ) : (
                <>
                  <Search className="mr-2 h-4 w-4" />
                  INITIATE_SCAN
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
                <Search className="w-12 h-12 text-hacker-green/20 mb-4" />
                <p className="text-hacker-green/50 font-mono text-sm uppercase">
                  AWAITING_SCAN_INPUT
                </p>
                <p className="text-muted-foreground text-xs mt-2">
                  Enter a target and initiate scan to see results
                </p>
              </div>
            )}

            {loading && (
              <div className="flex flex-col items-center justify-center h-[300px]">
                <Loader2 className="w-12 h-12 text-hacker-green animate-spin mb-4" />
                <p className="text-hacker-green font-mono text-sm animate-pulse">
                  SCANNING_IN_PROGRESS...
                </p>
              </div>
            )}

            {result && !loading && (
              <div className="space-y-4 font-mono text-sm">
                <div className="flex items-center justify-between p-3 bg-hacker-green/10 rounded-md">
                  <span className="text-hacker-green">[STATUS]</span>
                  <span className="text-foreground">SCAN_COMPLETE</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-hacker-green/5 rounded-md">
                  <span className="text-hacker-green/70">[TYPE]</span>
                  <span className="text-foreground uppercase">{result.type}</span>
                </div>
                <div className="flex items-center justify-between p-3 bg-hacker-green/5 rounded-md">
                  <span className="text-hacker-green/70">[TARGET]</span>
                  <span className="text-foreground">{result.value}</span>
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
