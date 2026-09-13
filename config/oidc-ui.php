<?php

declare(strict_types=1);

return [
    /*
     * Name of the Lattice SVG-sprite icon rendered at the top of the auth
     * layout. The consuming app's sprite must contain a matching symbol.
     */
    'brand_icon' => env('OIDC_UI_BRAND_ICON', 'logo'),

    /*
     * Name of the host app's logout route rendered on the verify-email page.
     * The link is omitted when no such route exists.
     */
    'logout_route' => env('OIDC_UI_LOGOUT_ROUTE', 'logout'),

    /*
     * Sprite icon per social login button, keyed by provider. Defaults to the
     * provider key itself (again resolved against the app's sprite); set a
     * provider to '' to render its button without an icon.
     */
    'social_icons' => [],
];
