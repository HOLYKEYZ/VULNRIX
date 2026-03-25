"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "../lib/utils";
import {
  Shield,
  Search,
  Code2,
  Terminal,
  FileCode2,
  Globe,
  Clock,
  LogOut,
  Bug,
  X,
} from "lucide-react";
import Image from "next/image";

const navigation = [
  {
    name: "MAIN",
    items: [
      { name: "Dashboard", href: "/dashboard", icon: Shield },
      { name: "Documentation", href: "/docs", icon: FileCode2 },
    ],
  },
  {
    name: "DEV TOOLS",
    items: [
      { name: "Code Scanner", href: "/scan", icon: Code2 },
      { name: "New Repo Scan", href: "/repo", icon: Terminal },
      { name: "VirusTotal Check", href: "/virustotal", icon: Bug },
      { name: "GitHub Integration", href: "/github", icon: Terminal },
    ],
  },
  {
    name: "OSINT SCANNER",
    items: [
      { name: "New OSINT Scan", href: "/osint", icon: Search },
      { name: "Digital Footprint", href: "/footprint", icon: Globe },
    ],
  },
  {
    name: "HISTORY",
    items: [
      { name: "OSINT History", href: "/history/osint", icon: Clock },
      { name: "Vuln History", href: "/history/vuln", icon: Clock },
    ],
  },
];

interface SidebarProps {
  isOpen?: boolean;
  onClose?: () => void;
}

export function Sidebar({ isOpen, onClose }: SidebarProps) {
  const pathname = usePathname();

  return (
    <>
      {/* Mobile overlay */}
      {isOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={cn(
          "fixed top-0 left-0 h-full w-64 bg-card border-r border-border z-50 flex flex-col p-4 transition-transform duration-200 lg:translate-x-0",
          isOpen ? "translate-x-0" : "-translate-x-full"
        )}
      >
        {/* Brand */}
        <Link href="/dashboard" className="flex items-center gap-2 mb-6 px-2">
          <div className="w-8 h-8 rounded-lg bg-hacker-green/20 flex items-center justify-center">
            <Shield className="w-5 h-5 text-hacker-green" />
          </div>
          <span className="text-xl font-bold text-hacker-green">VULNRIX</span>
        </Link>

        {/* Green accent bar */}
        <div className="w-full h-0.5 bg-gradient-to-r from-hacker-green via-hacker-green/50 to-transparent mb-6" />

        {/* Mobile close button */}
        <button
          onClick={onClose}
          className="absolute top-4 right-4 p-2 text-muted-foreground hover:text-foreground lg:hidden"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Navigation */}
        <nav className="flex-1 space-y-6 mt-4 overflow-y-auto">
          {navigation.map((section) => (
            <div key={section.name}>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2 px-3">
                {section.name}
              </h3>
              <div className="space-y-1">
                {section.items.map((item) => {
                  const isActive = pathname === item.href;
                  return (
                    <Link
                      key={item.name}
                      href={item.href}
                      onClick={onClose}
                      className={cn(
                        "flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium transition-colors",
                        isActive
                          ? "bg-hacker-green/10 text-hacker-green"
                          : "text-muted-foreground hover:text-foreground hover:bg-accent"
                      )}
                    >
                      <item.icon className="w-4 h-4" />
                      {item.name}
                    </Link>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Logout */}
        <div className="mt-auto pt-4 border-t border-border">
          <Link
            href="/logout"
            className="flex items-center gap-3 px-3 py-2 rounded-md text-sm font-medium text-destructive hover:bg-destructive/10 transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </Link>
        </div>
      </aside>
    </>
  );
}
