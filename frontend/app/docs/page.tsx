export default function DocsPage() {
  return (
    <div className="min-h-screen">
      <div className="scanline fixed inset-0 pointer-events-none z-50" />
      <div className="mb-8 border-b border-hacker-green/30 pb-4">
        <h1 className="text-3xl font-bold tracking-tight mb-1 font-mono text-hacker-green">
          DOCUMENTATION
        </h1>
        <p className="text-muted-foreground font-mono text-xs">
          {">"} API_REFERENCE_AND_GUIDES
        </p>
      </div>
      <p className="text-muted-foreground">Documentation coming soon...</p>
    </div>
  );
}
