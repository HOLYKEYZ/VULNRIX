"use client";

import { Menu, User, LogOut, Settings } from "lucide-react";
import { Button } from "../ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";

interface TopbarProps {
  onMenuClick?: () => void;
}

export function Topbar({ onMenuClick }: TopbarProps) {
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center justify-between gap-4 border-b border-border bg-card/95 backdrop-blur px-4 lg:px-6">
      {/* Mobile menu button */}
      <Button
        variant="outline"
        size="icon"
        className="lg:hidden"
        onClick={onMenuClick}
      >
        <Menu className="h-5 w-5" />
        <span className="sr-only">Toggle menu</span>
      </Button>

      {/* Logo for mobile */}
      <div className="lg:hidden font-bold text-lg text-hacker-green">
        VULNRIX
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Profile dropdown */}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="icon">
            <User className="h-4 w-4" />
            <span className="sr-only">User menu</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuLabel>
            <div className="flex flex-col space-y-1">
              <p className="text-sm font-medium">Signed in as</p>
              <p className="text-xs text-muted-foreground truncate">
                user@example.com
              </p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem>
            <Settings className="mr-2 h-4 w-4" />
            Settings
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem className="text-destructive focus:text-destructive">
            <LogOut className="mr-2 h-4 w-4" />
            Logout
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </header>
  );
}
