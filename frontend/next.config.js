/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**',
      },
    ],
  },
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'}/api/:path*`,
      },
    ];
  },
  experimental: {
    turbo: {
      resolveAlias: {
        '@/lib/utils': './lib/utils',
        '@/components/lib/utils': './components/lib/utils',
        '@/components': './components',
      },
    },
  },
};

module.exports = nextConfig;
