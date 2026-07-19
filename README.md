# Laika Auth

Multi-guard authentication package for the Laika PHP MVC Framework.

## Features

- Session, Cookie, and Token guards
- Google & Facebook OAuth login
- Browser/IP/token tracking per session (`auth_tokens` table)
- Token issue, validate, revoke, revoke-all
- Config-driven guard and provider resolution

## Installation

```bash
composer require laikait/laika-auth
```

Run the migration in `database/migrations` to create the `auth_tokens` and `oauth_accounts` tables.

## Configuration

Publish and edit `config/auth.php` to set guards and OAuth credentials.

```php
'guards' => [
    'web' => ['driver' => 'session', 'provider' => 'users'],
    'api' => ['driver' => 'token'],
],
'oauth' => [
    'google' => [
        'client_id' => 'GOOGLE_CLIENT_ID',
        'client_secret' => 'GOOGLE_CLIENT_SECRET',
        'user_model' => '\\App\\Models\\User::class',
    ],
],
```

## Usage

### Token guard

```php
$auth = new AuthManager($config);
$guard = $auth->guard('api');

$issued = $guard->issueToken($userId);
$user = $guard->validateToken($plainToken);
$guard->revoke($plainToken);
```

### OAuth login

```php
$oauth = $auth->oauth('google');

// Step 1: redirect
header('Location: ' . $oauth->redirect($redirectUri));

// Step 2: callback
$result = $oauth->callback($_GET['code'], $redirectUri);
// $result['user'], $result['token']
```

## Database Tables

- `auth_tokens` — user_id, guard, browser, ip, user_agent, token, refresh_token, expires_at, revoked_at
- `oauth_accounts` — user_id, provider, provider_user_id, access_token, refresh_token, email, avatar

## License

MIT
