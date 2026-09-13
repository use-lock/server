<?php

declare(strict_types=1);

namespace Lock\Server\Tests\Support\Realms;

/**
 * Marker for a test file that serves every realm from its own host. The
 * routing mode is fixed when the routes are registered, so FeatureTestCase reads it
 * before boot.
 */
trait RoutesRealmsByDomain {}
