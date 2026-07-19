<?php
/**
 * Laika Framework
 * Author: Showket Ahmed
 * Email: riyadhtayf@gmail.com
 * License: MIT
 * This file is part of the Laika Framework.
 * For the full copyright and license information, please view the LICENSE file that was distributed with this source code.
 */

declare(strict_types=1);

use Laika\Core\App\Resource;

Resource::register('models', repo_dir('laikait/laika-auth'), "Laika\\Auth\\Model");
Resource::register('schemas', repo_dir('laikait/laika-auth', "Laika\\Auth\\Schema"));