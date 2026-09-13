<?php
declare(strict_types=1);

namespace Lock\Server\Tests\Support\Realms;

/**
 * Marker for a test file that serves every realm below /realms/{realm}. The routing
 * mode is fixed when the routes are registered, so FeatureTestCase reads it before boot.
 */
trait RoutesRealmsByPath {}
