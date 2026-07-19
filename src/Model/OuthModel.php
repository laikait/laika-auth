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

namespace Laika\Auth\Model;

use Laika\Model\Model;

class OuthModel extends Model
{
    /** @var string Table Name */
    protected string $table = 'oauth_accounts';

    /** @var string Primary Column Name */
    protected string $id = 'id';
}
