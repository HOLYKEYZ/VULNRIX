"use client";

import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "../../components/ui/card";
import { Button } from "../../components/ui/button";
import { Input } from "../../components/ui/input";
import {
  RefreshCw,
  Plus,
  Shield,
  AlertTriangle,
  CheckCircle,
  Activity,
  Wifi,
  Server,
  Clock,
} from "lucide-react";
import Link from "next/link";

interface Stats {
  total_scans: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export default function DashboardPage() {
  const [stats, setStats] = useState<Stats>({
    total_scans: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  return (
    <div className="min-h-screen relative">
      {/* Scanline effect */}
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Header */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-end mb-8 border-b border-hacker-green/30 pb-4 gap-4">
        <div>
          <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono glitch-text text-hacker-green">
            DIGITAL_FOOTPRINT
          </h1>
          <p className="text-muted-foreground font-mono text-xs">
            {">"} MONITORING_TARGETS_ACTIVE
          </p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" onClick={() => window.location.reload()}>
            <RefreshCw className="mr-2 h-4 w-4" /> Refresh
          </Button>
          <Link href="/osint">
            <Button variant="hacker">
              <Plus className="mr-2 h-4 w-4" /> New Assessment
            </Button>
          </Link>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8 font-mono">
        {/* Scan Activity Chart */}
        <Card className="terminal-border bg-black overflow-hidden">
          <CardHeader className="terminal-header p-4">
            <div className="flex justify-between items-center">
              <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4" /> SIGNAL_ACTIVITY_FREQ
              </CardTitle>
              <div className="text-[10px] text-hacker-green border border-hacker-green px-2 py-0.5 animate-pulse">
                LIVE_MONITOR
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-6 h-[240px] flex items-center justify-center">
            {stats.total_scans === 0 ? (
              <div className="flex flex-col items-center justify-center text-center">
                <Wifi className="w-8 h-8 text-hacker-green/30 mb-3 animate-pulse" />
                <p className="text-hacker-green/50 text-xs font-mono uppercase">
                  NO_SIGNAL_DETECTED
                </p>
                <Link href="/osint">
                  <Button
                    variant="outline"
                    className="mt-3 border-hacker-green text-hacker-green hover:bg-hacker-green hover:text-black"
                  >
                    INITIATE_FIRST_SEQ
                  </Button>
                </Link>
              </div>
            ) : (
              <div className="w-full h-full bg-gradient-to-r from-hacker-green/10 to-transparent rounded-lg" />
            )}
          </CardContent>
        </Card>

        {/* Severity Distribution */}
        <Card className="terminal-border bg-black overflow-hidden">
          <CardHeader className="terminal-header p-4">
            <div className="flex justify-between items-center">
              <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
                <Shield className="w-4 h-4" /> THREAT_DISTRIBUTION_MATRIX
              </CardTitle>
              <div className="text-right">
                <div className="text-xl font-bold text-hacker-red leading-none">
                  {stats.critical}
                </div>
                <div className="text-[9px] text-hacker-green/50 uppercase tracking-wider">
                  CRITICAL_VULNS
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-6 h-[240px] flex items-center justify-center">
            <div className="text-center">
              <div className="text-4xl font-bold text-hacker-green font-mono">
                {stats.total_scans}
              </div>
              <div className="text-[10px] text-hacker-green/50 uppercase font-mono">
                TOTAL_OPS
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8 font-mono">
        {/* Security Score */}
        <Card className="terminal-border bg-black p-4">
          <div className="flex justify-between items-start mb-2">
            <span className="text-[10px] font-bold text-hacker-green uppercase tracking-wider">
              NET_SECURITY_INTEGRITY
            </span>
            <Shield className="w-4 h-4 text-hacker-green/30" />
          </div>
          <div className="mt-4 flex items-end gap-2">
            <span className="text-3xl font-bold text-hacker-green">
              {stats.low}
            </span>
            <span className="text-xs text-hacker-green/50 mb-1">
              / {stats.total_scans} PASSED
            </span>
          </div>
          <div className="w-full bg-hacker-green/10 h-1 mt-4 rounded-full overflow-hidden">
            <div
              className="bg-hacker-green h-full"
              style={{
                width: `${stats.total_scans > 0 ? (stats.low / stats.total_scans) * 100 : 0}%`,
              }}
            />
          </div>
        </Card>

        {/* Critical Issues */}
        <Card className="border border-hacker-red/50 bg-black p-4 hover:border-hacker-red transition-colors">
          <div className="flex justify-between items-start">
            <div>
              <div className="text-[10px] font-bold text-hacker-red uppercase tracking-wider mb-1">
                CRITICAL_VULNERABILITIES
              </div>
              <div className="text-3xl font-bold text-hacker-red glitch-text">
                {stats.critical}
              </div>
            </div>
            <div className="p-2 border border-hacker-red/30 bg-hacker-red/10 text-hacker-red">
              <AlertTriangle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 text-[10px] font-medium text-hacker-red/70 flex items-center gap-1 uppercase">
            <Activity className="w-3 h-3" /> Immediate_Remediation_Req
          </div>
        </Card>

        {/* Clean Sectors */}
        <Card className="terminal-border bg-black p-4">
          <div className="flex justify-between items-start">
            <div>
              <div className="text-[10px] font-bold text-hacker-green uppercase tracking-wider mb-1">
                CLEAN_SECTORS
              </div>
              <div className="text-3xl font-bold text-hacker-green">
                {stats.low}
              </div>
            </div>
            <div className="p-2 border border-hacker-green/30 bg-hacker-green/10 text-hacker-green">
              <CheckCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-4 text-[10px] font-medium text-hacker-green/70 flex items-center gap-1 uppercase">
            <Shield className="w-3 h-3" /> System_Stable
          </div>
        </Card>

        {/* System Telemetry */}
        <Card className="terminal-border bg-black p-4">
          <div className="flex justify-between items-start mb-4">
            <div className="text-[10px] font-bold text-hacker-green uppercase tracking-wider">
              SYSTEM_TELEMETRY
            </div>
            <div className="flex items-center gap-1.5">
              <span className="status-indicator" />
              <span className="text-[9px] font-medium text-hacker-green tracking-widest">
                ONLINE
              </span>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <div className="text-[9px] text-hacker-green/50 uppercase mb-1">
                UPTIME
              </div>
              <div className="text-sm font-bold text-hacker-green">
                99.9%
              </div>
            </div>
            <div>
              <div className="text-[9px] text-hacker-green/50 uppercase mb-1">
                LATENCY
              </div>
              <div className="text-sm font-bold text-hacker-green">
                24ms
              </div>
            </div>
          </div>
        </Card>
      </div>

      {/* Recent Activity */}
      <Card className="terminal-border bg-black">
        <CardHeader className="terminal-header p-4">
          <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
            <Clock className="w-4 h-4" /> RECENT_ACTIVITY_LOG
          </CardTitle>
        </CardHeader>
        <CardContent className="p-4">
          <div className="space-y-2 font-mono text-xs">
            <div className="flex items-center gap-3 p-2 rounded bg-hacker-green/5">
              <span className="text-hacker-green">[INFO]</span>
              <span className="text-muted-foreground">
                System initialized successfully
              </span>
              <span className="ml-auto text-hacker-green/50">2m ago</span>
            </div>
            <div className="flex items-center gap-3 p-2 rounded hover:bg-hacker-green/5">
              <span className="text-hacker-green">[SCAN]</span>
              <span className="text-muted-foreground">
                No recent scans found
              </span>
              <span className="ml-auto text-hacker-green/50">--</span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
