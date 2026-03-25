"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Link2,
  Shield,
  RefreshCw,
  ExternalLink,
  CheckCircle,
  Loader2,
  GitBranch,
  Terminal,
} from "lucide-react";

interface Repo {
  name: string;
  full_name: string;
  private: boolean;
  html_url: string;
}

export default function GitHubIntegrationPage() {
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [scanning, setScanning] = useState<string | null>(null);

  const handleConnect = () => {
    // Redirect to GitHub OAuth
    const clientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID;
    const redirectUri = `${window.location.origin}/api/auth/callback/github`;
    window.location.href = `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=repo,read:user&redirect_uri=${redirectUri}`;
  };

  const handleScanRepo = async (repoUrl: string) => {
    setScanning(repoUrl);
    try {
      await fetch("/api/v1/scan/repo/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl }),
      });
    } catch (err) {
      console.error(err);
    }
    setScanning(null);
  };

  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />

      {/* Header */}
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          GITHUB_INTEGRATION
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} AUTOMATED_REPO_SCANNING_PIPELINE
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Connection */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4" /> ACCOUNT_CONNECTION
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            {!connected ? (
              <>
                <div className="text-center py-8">
                  <Terminal className="w-16 h-16 text-hacker-green/30 mx-auto mb-4" />
                  <p className="text-muted-foreground mb-4">
                    Connect your GitHub account to enable automated repository scanning
                  </p>
                  <Button variant="hacker" onClick={handleConnect}>
                    <Link2 className="mr-2 h-4 w-4" />
                    CONNECT_GITHUB
                  </Button>
                </div>

                <div className="border border-hacker-green/20 rounded-md p-4">
                  <h4 className="text-hacker-green font-medium mb-2">Permissions Required:</h4>
                  <ul className="text-sm text-muted-foreground space-y-1">
                    <li className="flex items-center gap-2">
                      <CheckCircle className="w-3 h-3 text-hacker-green" />
                      Read access to repositories
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="w-3 h-3 text-hacker-green" />
                      Read user profile information
                    </li>
                    <li className="flex items-center gap-2">
                      <CheckCircle className="w-3 h-3 text-hacker-green" />
                      Webhook notifications for scans
                    </li>
                  </ul>
                </div>
              </>
            ) : (
              <>
                <div className="flex items-center justify-between p-4 bg-hacker-green/10 rounded-md">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-6 h-6 text-hacker-green" />
                    <div>
                      <p className="text-hacker-green font-medium">Connected</p>
                      <p className="text-xs text-muted-foreground">@username</p>
                    </div>
                  </div>
                  <Button variant="outline" size="sm">
                    DISCONNECT
                  </Button>
                </div>

                <div>
                  <h4 className="text-sm text-hacker-green/70 uppercase tracking-wider mb-3">
                    INSTALLED_REPOS
                  </h4>
                  <div className="space-y-2">
                    {repos.map((repo) => (
                      <div
                        key={repo.full_name}
                        className="flex items-center justify-between p-3 border border-hacker-green/20 rounded-md"
                      >
                        <div className="flex items-center gap-2">
                          <GitBranch className="w-4 h-4 text-hacker-green/70" />
                          <span className="text-sm">{repo.name}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <a
                            href={repo.html_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-hacker-green/70 hover:text-hacker-green"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleScanRepo(repo.html_url)}
                            disabled={scanning === repo.html_url}
                          >
                            {scanning === repo.html_url ? (
                              <Loader2 className="w-4 h-4 animate-spin" />
                            ) : (
                              "SCAN"
                            )}
                          </Button>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Quick Scan */}
        <Card className="terminal-border bg-black">
          <CardHeader className="terminal-header p-4">
            <CardTitle className="text-sm font-bold text-hacker-green uppercase tracking-wider flex items-center gap-2">
              <Shield className="w-4 h-4" /> QUICK_REPO_SCAN
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6 space-y-6">
            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                REPOSITORY_URL
              </label>
              <Input
                type="text"
                placeholder="https://github.com/user/repo"
                className="bg-black border-hacker-green/30 text-foreground placeholder:text-hacker-green/30 focus:border-hacker-green"
              />
            </div>

            <div>
              <label className="text-xs text-hacker-green/70 uppercase tracking-wider mb-2 block">
                SCAN_DEPTH
              </label>
              <div className="flex gap-2">
                <button className="flex-1 py-2 rounded-md border border-hacker-green bg-hacker-green/10 text-hacker-green text-sm font-medium">
                  FAST
                </button>
                <button className="flex-1 py-2 rounded-md border border-border text-muted-foreground text-sm font-medium">
                  HYBRID
                </button>
                <button className="flex-1 py-2 rounded-md border border-border text-muted-foreground text-sm font-medium">
                  DEEP
                </button>
              </div>
            </div>

            <div className="border border-hacker-green/20 rounded-md p-4 bg-hacker-green/5">
              <p className="text-xs text-muted-foreground">
                <span className="text-hacker-green font-medium">Note:</span> Public repos can be
                scanned without authentication. Private repos require GitHub connection.
              </p>
            </div>

            <Button variant="hacker" className="w-full">
              <Shield className="mr-2 h-4 w-4" />
              INITIATE_SCAN
            </Button>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
