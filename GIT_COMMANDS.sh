#!/bin/bash
# Git commands to commit and push the signed webhooks feature

cd /c/Users/RAVE/Desktop/aimer2/earnproof-backend

# Configure git user
git config user.name "aimer6022"
git config user.email "aimer6022@users.noreply.github.com"

# Create feature branch
git checkout -b feat/signed-webhooks

# Stage all new/modified files
git add prisma/schema.prisma
git add prisma/migrations/20260824000000_signed_webhooks/migration.sql
git add src/webhooks/
git add src/proofs/proofs.service.ts
git add src/proofs/proofs.module.ts
git add src/app.module.ts
git add PR_DESCRIPTION.md

# Commit with the specified message
git commit -m "feat(api): add signed webhook delivery"

# Push to remote with upstream tracking
git push -u origin feat/signed-webhooks

echo "✓ Branch created, changes committed, and pushed to origin"
echo "✓ Branch: feat/signed-webhooks"
echo "✓ Commit message: feat(api): add signed webhook delivery"
