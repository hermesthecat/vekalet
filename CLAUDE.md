# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## High-Level Architecture

This is a **PHP-based authority delegation system** with JSON file storage implementing a sophisticated role-based access control (RBAC) system. Users can delegate specific permissions to other users for defined time periods with built-in security measures.

### Core System Components

**Authentication & Session Management:**

- JSON file-based user storage with bcrypt password hashing
- Secure session management with signature validation to prevent hijacking
- CSRF protection on all forms with token rotation
- Rate limiting on login/registration attempts

**Authority Delegation Engine:**

- **Atomic Operations:** File locking mechanisms prevent race conditions during delegation creation/revocation
- **Circular Delegation Prevention:** Recursive checks prevent A→B→C→A delegation chains
- **Permission Inheritance:** Users can only delegate permissions they currently possess
- **Selective Permission Delegation:** Users can choose specific permissions to delegate rather than all permissions
- **Authority Blocking:** Users with active outgoing delegations cannot perform actions in their own name until delegation is revoked

**Role-Based Permission System:**

- 4 predefined roles: Super Admin (all permissions), Admin, Manager, User
- 11 granular permissions across categories: system, delegation, reports, profile
- Permission validation occurs at multiple levels (role + delegation)
- Bulk permission resolution to prevent N+1 query problems

**Performance & Caching:**

- **Two-tier caching:** APCu (in-memory) with file-based fallback
- **Bulk loading patterns:** Resolve multiple user names and permissions in single operations
- **Static caching:** In-memory caching for frequently accessed data
- Memory usage monitoring with warnings at 80% of PHP memory limit

### File Structure & Data Flow

```bash
data/
├── users.json          # User accounts with role assignments
├── roles.json          # Role definitions with permission arrays
├── permissions.json    # Granular permission definitions
├── delegations.json    # Authority delegation records
└── security.log        # Security event logging
```

**Critical Files:**

- `functions.php`: Core system logic (1500+ lines) - contains all business logic
- `dashboard.php`: Main user interface with delegation management
- `admin.php`: Administrative interface for user/role management  
- `system-status.php`: Real-time monitoring dashboard

### Security Architecture

**Multi-layered Security:**

1. **Input Validation:** Comprehensive validation for all user inputs with whitelist approaches
2. **CSRF Protection:** Per-form tokens with HMAC validation
3. **Session Security:** Signature-based validation prevents session hijacking  
4. **Atomic Operations:** File locking prevents data corruption during concurrent operations
5. **Security Logging:** All authentication attempts and critical actions are logged
6. **Permission Escalation Prevention:** Real-time permission validation before each action

**UTC Time Standardization:** All timestamps stored in UTC to prevent timezone-related bugs.

### Business Logic Patterns

**Authority Switching:**

- Users can "switch" to operate on behalf of someone who delegated authority to them
- All actions taken show clear indication of "acting as [username]"
- Permission checks use the active authority context

**Delegation Lifecycle:**

- Create → Validate permissions → Check for circular delegation → Atomic file write
- Active delegations block the delegator from self-actions until revoked
- Expired delegations are automatically cleaned up via system heartbeat

## Development Commands

**No build system required** - this is a standard PHP application.

### Local Development

```bash
# Start local development server
php -S localhost:8000

# Check syntax of all PHP files
php -l *.php

# View security logs in real-time  
tail -f data/security.log
```

### File Permissions Setup

```bash
# Set secure permissions for production
chmod 755 .
chmod 700 data/
chmod 600 data/*.json
```

### System Monitoring

- Access `system-status.php` to view real-time system metrics
- Monitor `data/security.log` for security events
- Check data integrity via the system status dashboard

## Key Implementation Details

### Atomic Delegation Operations

```php
// Critical pattern used throughout - file locking for atomicity
$lockFile = dirname(DELEGATIONS_FILE) . '/delegation.lock';
$lockHandle = fopen($lockFile, 'c+');
if (!$lockHandle || !flock($lockHandle, LOCK_EX)) {
    return ['error' => 'System busy, please retry'];
}
// ... perform operations ...
flock($lockHandle, LOCK_UN);
fclose($lockHandle);
```

### Permission Resolution Pattern

The system uses bulk loading to avoid N+1 queries:

```php
// Load all users/permissions once, resolve many IDs efficiently
$userMap = loadAllUsersMap();
$resolved = resolveUserNames($userIds);  // Batch operation
```

### Security Event Logging

All security-relevant actions are logged with structured data:

```php
logSecurityEvent('LOGIN_FAILED', [
    'username' => $username,
    'ip' => $_SERVER['REMOTE_ADDR']
], 'WARNING');
```

## Common Workflows

1. **User Registration/Login** → Validate → Hash password → Create session signature
2. **Authority Delegation** → Validate permissions → Check circular delegation → Atomic write → Cache invalidation
3. **Authority Switching** → Validate delegation exists → Update session context → Show active authority indicator
4. **System Maintenance** → Run heartbeat → Clean expired delegations → Check data integrity → Log metrics

The system is production-ready with comprehensive error handling, security logging, and performance optimizations.
