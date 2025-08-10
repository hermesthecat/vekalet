# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a PHP-based user authority delegation system with JSON file storage. The application allows users to:

- Register and login with username/password
- Delegate their authority to other users with expiration dates
- Switch between acting on their own behalf or on behalf of others
- Manage and revoke delegated authorities
- Automatic blocking when users have active delegations

## Architecture

### Core Files Structure

```bash
vekalet/
├── index.php          # Landing/login page
├── login.php           # Login processing
├── register.php        # User registration page and logic
├── dashboard.php       # Main dashboard with authority management
├── logout.php          # Session termination
├── functions.php       # Core system functions and business logic
├── style.css           # Frontend styles
└── data/              # JSON data storage (auto-created)
    ├── users.json     # User accounts
    └── delegations.json # Authority delegations
```

### Key Components

**Session Management**: PHP sessions are used throughout for user authentication and maintaining active authority context.

**Data Storage**: All data is stored in JSON files in the `data/` directory. The system automatically creates this directory and initializes empty JSON arrays if files don't exist.

**Authority System**: Users can delegate their authority to others with expiration dates. The system tracks:

- Active delegations (from user to another)
- Received delegations (from others to user)
- Authority switching (acting on behalf of others)
- Automatic blocking when users have active outgoing delegations

**Security Features**:

- CSRF protection on all forms with token validation
- Input sanitization with htmlspecialchars()
- Session-based authentication
- Automatic token refresh after successful operations

### Core Functions (functions.php)

**Data Operations**:

- `readJsonFile($filename)` - Safe JSON file reading with auto-creation
- `writeJsonFile($filename, $data)` - Safe JSON file writing
- `getUserById()`, `getUserByUsername()`, `getAllUsers()` - User lookup operations

**Authority Management**:

- `delegateAuthority()` - Create new authority delegation with validation
- `getUserDelegations()` - Get user's outgoing delegations
- `getUserReceivedDelegations()` - Get user's incoming delegations
- `revokeDelegation()` - Cancel existing delegation
- `hasActiveDelegationTo()` - Check for existing delegation to specific user
- `canUserPerformActions()` - Validate if user can act on their own behalf

**Security**:

- `generateCSRFToken()`, `validateCSRFToken()`, `refreshCSRFToken()` - CSRF protection
- `getCSRFField()` - Generate hidden CSRF form field

## Development Environment

### Requirements

- PHP 7.0+ with session support
- Web server (Apache/Nginx)
- File system write permissions for data/ directory

### Local Development Setup

```bash
# Set up permissions (Linux/macOS)
chmod 755 /path/to/vekalet/
chmod 777 /path/to/vekalet/data/

# For Windows with XAMPP/WAMP, ensure web server has write access to data/ folder
```

### Testing

This is a simple PHP application without formal testing framework. Test manually by:

1. **User Registration**: Create users through register.php
2. **Authentication**: Verify login/logout functionality
3. **Authority Delegation**: Test delegation creation with various scenarios
4. **Authority Switching**: Test switching between user contexts
5. **Blocking Logic**: Verify users with active delegations cannot act on own behalf
6. **CSRF Protection**: Verify forms fail without proper tokens

### Common Operations

**Reset Data**: Delete contents of data/ directory to clear all users and delegations

**Debug Issues**: Check web server error logs for PHP errors. Common issues:

- File permissions on data/ directory
- Session configuration
- JSON encoding/decoding errors

## Important Notes

**Security Considerations**: This system stores passwords in plain text and is designed for educational purposes. For production use:

- Implement password hashing (bcrypt)
- Add HTTPS enforcement
- Implement rate limiting
- Add input validation beyond basic sanitization
- Consider database storage instead of JSON files
- Add proper error logging

**Authority Logic**: The system enforces a "single active delegation" rule - users cannot create multiple active delegations to the same recipient. Users with active outgoing delegations are blocked from performing actions in their own name until they revoke the delegation.

**Data Persistence**: All data is stored in JSON files. The system automatically handles file creation and maintains data integrity, but consider implementing proper backup strategies for production use.
