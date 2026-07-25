<?php
/**
 * Laika Auth
 * Author: Showket Ahmed
 * Email: riyadhtayf@gmail.com
 * License: MIT
 * This file is part of the Laika PHP MVC Framework.
 * For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 */

declare(strict_types=1);

namespace Laika\Auth\Guards;

use Laika\Model\Model;
use Laika\Service\Visitor;
use Laika\Auth\Model\AuthModel;
use Laika\Auth\Exceptions\AuthException;

class TokenGuard
{
    /** @var string Guard Name */
    protected string $guardName;

    /** @var Model Provider Model */
    protected Model $provider;

    /** @var AuthModel Model */
    protected AuthModel $model;

    public function __construct(string $provider, string $guardName)
    {
        $this->guardName = strtolower($guardName);
        $this->provider = new $provider();
        $this->model = new AuthModel();
    }

    /**
     * Issue Tiken
     * @param int $userId
     * @param ?int $ttl
     * @return array
     * @throws AuthException
     */
    public function issueToken(int $userId, ?int $ttl = null): array
    {
        $token = bin2hex(random_bytes(64));
        $hashed = hash('sha256', $token);
        $row = [
            'user_id' => $userId,
            'guard' => $this->guardName,
            'browser' => Visitor::browser(),
            'ip' => Visitor::ip(),
            'user_agent' => Visitor::userAgent(),
            'token' => $hashed,
            'refresh_token' => bin2hex(random_bytes(64)),
            'expires_at' => $ttl ? date('Y-m-d H:i:s', time() + $ttl) : null,
            'revoked_at' => null,
            'created_at' => date('Y-m-d H:i:s')
        ];

        try {
            $this->model->transaction(function (AuthModel $m) use ($row) {
                $m->insert($row);
            });
        } catch (\Throwable $th) {
            throw new AuthException("Auth token issue failed!", 500, $th);
        }
        return ['token' => $token, 'hashed' => $hashed];
    }


    /**
     * Validate Token
     * @param ?int $ttl Default is 3600 (1 Hour)
     * @param ?string $token
     * @param bool $strict Default is false
     * @return ?array
     */
    public function validateToken(?string $token, ?int $ttl = null, bool $strict = false): ?array
    {
        if (empty($token)) return null;
        $hashed = hash('sha256', $token);
        $row = $this->model
                    ->select(['expires_at', 'user_id', 'browser', 'ip', 'user_agent'])
                    ->where(['token' => $hashed, 'guard' => $this->guardName])
                    ->isNull('revoked_at')
                    ->first();

        // Check Has Row
        if (empty($row)) return null;

        // Check Not Expired
        if ($row['expires_at']) {
            if (strtotime($row['expires_at']) < time()) return null;
            $ttl = $ttl ?: 3600;
            $this->model
                ->where(['token' => $hashed, 'guard' => $this->guardName])
                ->update(['expires_at' => date('Y-m-d H:i:s', time() + $ttl)]);
        }

        // Validate Visitor Info
        if ($strict) {
            // Validate Browser
            if ($row['browser'] != Visitor::browser()) return null;

            // Validate Browser
            if ($row['user_agent'] != Visitor::userAgent()) return null;

            // Validate Browser
            if ($row['ip'] != Visitor::ip()) return null;
        }

        $user = $this->provider->find($row['user_id']);

        // Check Has User
        if (empty($user)) return null;
        return $user;
    }

    /**
     * Revoke Tiken
     * @param string $plainToken
     * @return bool
     */
    public function revoke(string $plainToken): bool
    {
        return (bool) $this->model
                            ->where(['token' => hash('sha256', $plainToken), 'guard' => $this->guardName])
                            ->update(['revoked_at' => date('Y-m-d H:i:s')]);
    }

    /**
     * Revoke Tiken
     * @param int $userId
     * @return bool
     */
    public function revokeAllForUser(int $userId): bool
    {
        return (bool) $this->model
                            ->where(['user_id' => $userId, 'guard' => $this->guardName])
                            ->update(['revoked_at' => date('Y-m-d H:i:s')]);
    }
}
