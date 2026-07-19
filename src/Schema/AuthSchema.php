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

// Namespace
namespace Laika\Auth\Schema;

// Deny Direct Access
defined('APP_PATH') || http_response_code(403) . die('403 Direct Access Denied!');

use Laika\Model\Schema\Schema;
use Laika\Model\Schema\Blueprint;
use Laika\Core\Abstracts\SchemaAbstract;

class AuthSchema extends SchemaAbstract
{
    protected string $table = 'auth_tokens';

    public function up(): void
    {
        Schema::on()->createIfNotExists($this->table, function (Blueprint $t) {
            $t->bigId();
            $t->bigInteger('user_id')->unsigned();
            $t->string('guard', 50);
            $t->string('browser', 50)->nullable();
            $t->string('ip', 50)->nullable();
            $t->string('user_agent', 50)->nullable();
            $t->string('token');
            $t->string('refresh_token')->default(NULL);
            $t->timestamp('expires_at')->default(NULL);
            $t->timestamp('revoked_at')->default(NULL);
            $t->timestamp('created_at');
            
            // Indexes
            $t->index(['user_id', 'guard'], 'user_guard');
            $t->unique('token');
        });
    }
}
