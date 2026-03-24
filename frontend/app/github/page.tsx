export default function GitHubIntegrationPage() {
  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          GITHUB_INTEGRATION
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} AUTOMATED_REPO_SCANNING
        </p>
      </div>
      <p className="text-muted-foreground">Connect your GitHub account for automated scanning...</p>
    </div>
  );
}
