"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Loader2 } from "lucide-react";

export default function LogoutPage() {
  const router = useRouter();

  useEffect(() => {
    // Clear any auth tokens
    localStorage.removeItem("token");
    sessionStorage.clear();
    
    // Redirect to home after a brief delay
    const timer = setTimeout(() => {
      router.push("/");
    }, 1500);

    return () => clearTimeout(timer);
  }, [router]);

  return (
    <div className="flex flex-col items-center justify-center min-h-[80vh]">
      <Loader2 className="w-12 h-12 text-hacker-green animate-spin mb-4" />
      <p className="text-hacker-green font-mono text-sm">LOGGING_OUT...</p>
    </div>
  );
}
