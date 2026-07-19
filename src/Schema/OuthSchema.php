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

class OuthSchema extends SchemaAbstract
{
    protected string $table = 'oauth_accounts';

    public function up(): void
    {
        Schema::on()->createIfNotExists($this->table, function (Blueprint $t) {
            $t->bigId();
            $t->bigInteger('user_id')->unsigned();
            $t->string('provider', 30);
            $t->string('provider_user_id');
            $t->string('access_token')->nullable();
            $t->string('refresh_token')->nullable();
            $t->string('avatar')->nullable();
            $t->string('email', 100)->nullable();
            $t->string('name', 100)->nullable();
            $t->timestamp('expires_at')->nullable();
            $t->timestamp('created_at');
            
            // Indexes
            $t->unique(['provider', 'provider_user_id'], 'provider_user');
        });
    }
}
