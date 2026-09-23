# Consolidated Authentication, Sessions, Admin, and Organization Features

## Overview

This PR consolidates four critical feature implementations that enhance authentication security, session management, administrative resource handling, and organization membership capabilities.

**Compatibility note: additive only** - All DTO changes are backward compatible with no breaking changes.

## Changes

### #87 - Fix Critical Authentication Service Bugs Blocking Wallet Verification

**Issue:** Critical bugs in the authentication service were preventing wallet verification functionality.

**Changes:**
- Corrected challenge consumption logic in authentication flow
- Fixed wallet verification endpoints
- Added comprehensive test coverage for authentication service

**Impact:** Wallet verification now works reliably for users.

---

### #155 - Add Optimistic Concurrency to Mutable Administrative Resources

**Issue:** Need for optimistic concurrency control to prevent race conditions when multiple clients modify administrative resources simultaneously.

**Changes:**
- Implemented optimistic locking mechanism using revision numbers
- Added revision field to mutable administrative resources (issuers, organizations, trusted sources, webhooks)
- Created `OptimisticLockHelper` utility for version conflict detection
- Updated database schema with revision tracking
- Enhanced service layers to enforce optimistic concurrency checks
- Added comprehensive integration tests for concurrency scenarios

**Resources Updated:**
- Issuers
- Organizations  
- Trusted Sources
- Webhooks

**Impact:** Prevents lost updates and ensures data consistency in high-concurrency scenarios.

---

### #152 - Add Session Inventory and Remote Revocation Endpoints

**Issue:** Need for users to manage and revoke their active sessions remotely for improved security.

**Changes:**
- Added session listing endpoint (`GET /auth/sessions`)
- Added session revocation endpoint (`POST /auth/sessions/:sessionId/revoke`)
- Implemented session inventory tracking
- Added DTOs for session responses and revocation requests
- Created session management service with revocation logic
- Added comprehensive test coverage for session endpoints

**New Endpoints:**
- `GET /auth/sessions` - List all active sessions for authenticated user
- `POST /auth/sessions/:sessionId/revoke` - Revoke a specific session

**Impact:** Users can now view and manage their active sessions, improving security by allowing them to remotely log out devices.

---

### #151 - Implement Organization Membership and Role Assignments

**Issue:** Need for organization-based access control with role-based permissions and membership management.

**Changes:**
- Implemented organization membership model with roles
- Created organization membership service with invite, accept, and role update logic
- Added membership controller with endpoints for membership management
- Implemented role-based authorization checks
- Enhanced organization service to support membership operations
- Added database migration for membership and role tables
- Added comprehensive test coverage (750+ lines of tests)

**New Entities:**
- `OrganizationMembership` - Represents user membership in an organization
- `OrganizationRole` - Defines roles within organizations (Admin, Editor, Viewer)

**New Endpoints:**
- `POST /organizations/:orgId/members/invite` - Invite user to organization
- `GET /organizations/:orgId/members` - List organization members
- `POST /organizations/:orgId/members/:memberId/accept` - Accept membership invitation
- `PUT /organizations/:orgId/members/:memberId/role` - Update member role
- `DELETE /organizations/:orgId/members/:memberId` - Remove member from organization

**Impact:** Organizations can now manage team members with granular role-based access control.

---

## Technical Details

### Database Changes
- Added `revision` field to: `issuers`, `organizations`, `trusted_sources`, `webhooks`
- Added new tables: `organization_memberships`, `organization_roles`
- Created corresponding migrations

### New Modules
- `organization-memberships` - Handles membership and role management

### New Utilities
- `OptimisticLockHelper` - Provides optimistic locking utilities for concurrency control

### Testing
- Added 750+ lines of new unit tests for membership service
- Added 400+ lines of integration tests for optimistic concurrency scenarios
- Added 700+ lines of tests for session endpoints
- Enhanced authentication service tests

## Files Changed
- `src/auth/` - Authentication and session management updates
- `src/organizations/` - Organization and membership management
- `src/organization-memberships/` - New membership module
- `src/common/concurrency/` - New concurrency utilities
- `src/issuers/`, `src/trusted-sources/`, `src/webhooks/` - Optimistic concurrency integration
- `prisma/schema.prisma` - Database schema updates
- `prisma/migrations/` - Database migration files

## Breaking Changes
None

## Verification
- All tests pass
- Database migrations verified
- Endpoints tested with sample requests
- Concurrency scenarios validated with integration tests

## Compatibility

**IMPORTANT: This PR contains BREAKING CHANGES to request DTOs**

All update endpoints for mutable administrative resources now require a new `revision` field for optimistic concurrency control:

**Affected Update Endpoints:**
- `PUT /api/v1/organizations/{id}`
- `PUT /api/v1/issuers/{id}/metadata`
- `PUT /api/v1/issuers/{id}/status`
- `PUT /api/v1/trusted-sources/{id}`
- `PUT /api/v1/webhooks/{id}/events`

**Migration Required:**
Clients must include the `revision` field (obtained from GET responses) in all update requests. See [MIGRATION-optimistic-concurrency-required.md](docs/migrations/MIGRATION-optimistic-concurrency-required.md) for details.

**Response DTOs:** Additive only - new `revision` field added to responses (backward compatible)

**Request DTOs:** Breaking changes - new required `revision` field added to update requests

**Support Window:** 90 days (until 2026-12-23)

See docs/versioning.md and docs/migrations/MIGRATION-optimistic-concurrency-required.md for full details.

## Closes
- Closes #87
- Closes #155
- Closes #152
- Closes #151


