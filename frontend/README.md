# VULNRIX Frontend

Modern TypeScript frontend built with Next.js, Tailwind CSS, and shadcn/ui.

## Tech Stack

- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Utility-first styling
- **shadcn/ui** - UI components (Radix primitives)
- **Lucide Icons** - Icon library

## Design

The frontend uses the same hacker-themed design as the original:
- Dark backgrounds with zinc color scale
- Cyan/teal accent color (#00d4d4)
- Terminal-style borders and animations
- JetBrains Mono font for code elements
- Glitch effects and scanline animations

## Setup

```bash
# Install dependencies
npm install

# Copy environment variables
cp .env.example .env.local

# Start development server
npm run dev
```

## Environment Variables

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXTAUTH_URL=http://localhost:3000
NEXTAUTH_SECRET=your-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

## Project Structure

```
frontend/
├── app/                 # Next.js App Router pages
│   ├── layout.tsx       # Root layout with sidebar
│   ├── page.tsx         # Home page
│   ├── dashboard/       # Dashboard page
│   ├── osint/           # OSINT scanner page
│   ├── scan/            # Code scanner page
│   └── repo/            # Repo scanner page
├── components/
│   ├── ui/              # shadcn/ui components
│   │   ├── button.tsx
│   │   ├── card.tsx
│   │   └── input.tsx
│   └── layout/          # Layout components
│       ├── sidebar.tsx
│       └── topbar.tsx
├── lib/
│   └── utils.ts         # Utility functions (cn)
└── tailwind.config.ts   # Tailwind configuration
```

## Deployment

The frontend is configured for Render deployment via `render.yaml`.

## CLI Usage

You can also use the Python CLI for terminal operations:

```bash
# OSINT scan
python cli/vulnrix.py osint --email user@example.com

# Code scan
python cli/vulnrix.py code --path ./src --mode hybrid

# Repo scan
python cli/vulnrix.py repo --url https://github.com/user/repo

# GitHub OAuth
python cli/vulnrix.py github --action login
```
