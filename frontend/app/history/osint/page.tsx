export default function OsintHistoryPage() {
  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          OSINT_HISTORY
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} PREVIOUS_OSINT_SCANS
        </p>
      </div>
      <p className="text-muted-foreground">No scan history yet...</p>
    </div>
  );
}
