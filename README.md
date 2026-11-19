# StreamFinder

Twitch streamer finder with **multi-key support** and **OAuth followers filter**.
Keys and tokens are managed **only from the admin panel** — never hardcoded, never in the repo.

## Features

- Multi-user login (admin + members)
- Members can create sub-IDs (admin controls limit)
- **Multiple Twitch API keys** — added from admin panel, round-robin load balancing, auto failover
- **Twitch OAuth** for followers filter — connect once from admin panel, auto-refresh
- Zero-duplicate saved streamers (`saved.json`)
- Dark mode support

## Setup (local)

1. Node.js 18+ install karein
2. Repo clone karein
3. `.env.example` ko `.env` mein copy karein aur edit karein:
