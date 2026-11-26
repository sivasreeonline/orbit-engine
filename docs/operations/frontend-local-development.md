# Frontend Local Development

## Requirements
- Node.js >= 22.12.0 (the developer machine currently reports Node 24.13.0).
- npm 11.x.
- Git.

## First install
From the repository root:

```powershell
cd apps/web
npm install
```

This generates apps/web/package-lock.json. Commit the lockfile on the feature branch after reviewing it. Once the lockfile is committed, change CI installation from `npm install` to `npm ci` for deterministic builds.

## Commands
```powershell
npm run dev
npm run typecheck
npm test
npm run build
```

## Important
The frontend can be developed independently of the Linux runner by using the preview adapter. The preview adapter is not an execution service and must not be used to claim a student's program passed.
