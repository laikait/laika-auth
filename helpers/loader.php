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

// Register Model Class
Resource::register('models', __DIR__ . '/../src/Model', '\\Laika\\Auth\\Model');

// Register Schema Class
Resource::register('schemas', __DIR__ . '/../src/Schema', '\\Laika\\Auth\\Schema');