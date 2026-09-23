# Migration Guide: Required `revision` Field for Optimistic Concurrency Control

## Overview

Starting with this release, all mutable administrative resource update endpoints require a new `revision` field in request payloads. This field is essential for preventing race conditions when multiple clients modify the same resource simultaneously.

**Affected endpoints:**
- `PUT /api/v1/organizations/{id}`
- `PUT /api/v1/issuers/{id}/metadata`
- `PUT /api/v1/issuers/{id}/status`
- `PUT /api/v1/trusted-sources/{id}`
- `PUT /api/v1/webhooks/{id}/events`

## What Changed

### Before (Old Behavior)
```json
PUT /api/v1/organizations/org-123
{
  "name": "New Organization Name",
  "website": "https://example.com"
}
```

### After (New Behavior Required)
```json
PUT /api/v1/organizations/org-123
{
  "revision": 1,
  "name": "New Organization Name",
  "website": "https://example.com"
}
```

## Impact

**Breaking Change:** Existing clients that do not include the `revision` field will receive a validation error:

```json
{
  "statusCode": 400,
  "message": "Bad Request",
  "error": "revision must be an integer"
}
```

## How to Migrate

### Step 1: Fetch the Current Resource
Retrieve the current revision number from the resource's response:

```json
GET /api/v1/organizations/org-123

Response:
{
  "id": "org-123",
  "name": "My Organization",
  "revision": 1,
  ...
}
```

### Step 2: Include Revision in Update Requests
Use the `revision` value from Step 1 when making update requests:

```json
PUT /api/v1/organizations/org-123
{
  "revision": 1,
  "name": "Updated Organization Name"
}
```

### Step 3: Handle Conflict Responses
If the revision is stale (another client has updated the resource), you will receive a 409 Conflict:

```json
{
  "statusCode": 409,
  "message": "Conflict",
  "error": {
    "code": "CONFLICT",
    "message": "Organization org-123 has been modified. Expected revision 1, but current revision is 2.",
    "currentRevision": 2
  }
}
```

**Resolution:** Retry by fetching the resource again and using the updated revision number.

## Why This Change

This change implements **optimistic concurrency control** to ensure data consistency:

1. **Prevents lost updates:** When two clients modify the same resource simultaneously, the second update is rejected rather than silently overwriting the first.
2. **Provides feedback:** Clients learn immediately if a resource has changed, allowing them to retry with current data.
3. **No locks:** Unlike pessimistic locking, this approach does not require database locks, improving throughput.

## Support Timeline

- **Support window start:** 2026-09-23
- **Support window end:** 2026-12-23 (90 days)
- **Removal date:** All old client behavior unsupported after 2026-12-23

During the support window, both new and updated code will function correctly. After the support window, clients that do not include the `revision` field will be rejected.

## Migration Checklist

- [ ] Review all endpoints that make PUT requests to administrative resources
- [ ] Fetch the resource first to obtain the current `revision` value
- [ ] Update PUT request payloads to include `revision`
- [ ] Implement retry logic to handle 409 Conflict responses
- [ ] Test with the new `revision` field included
- [ ] Deploy updates before the support window ends

## Questions?

- Review the optimistic concurrency implementation docs: [OPTIMISTIC_CONCURRENCY_IMPLEMENTATION.md](../OPTIMISTIC_CONCURRENCY_IMPLEMENTATION.md)
- Check the authorization matrix to understand role-based access: [authorization-matrix.md](../authorization-matrix.md)

## Compatibility Note

**Contract:** `rest.dto.organizations.update, rest.dto.issuers.update, rest.dto.trusted-sources.update, rest.dto.webhooks.update`

**Migration:** Include `revision` field in all update requests to mutable administrative resources.

**Support window:** 90 days from 2026-09-23

**Approver:** Backend maintainers
