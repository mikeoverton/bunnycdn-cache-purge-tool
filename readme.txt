=== BunnyCDN Manager ===
Contributors: michaeloverton
Donate link: https://overton.cloud
Tags: bunnycdn, cdn, cache, purge, performance
Requires at least: 6.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Manage your BunnyCDN integration from WordPress. Cache purging, CDN URL rewriting, usage statistics, WP Rocket compatibility, and Bunny Fonts.

== Description ==

A complete BunnyCDN integration for WordPress. Automatically purge cache when content changes, rewrite URLs to serve assets through your CDN, monitor bandwidth usage, and keep WP Rocket in sync.

= Features =

**Cache Management**

* Purge entire CDN cache with one click
* Purge specific URLs or bulk purge multiple URLs
* Auto-purge when posts, pages, or custom post types are updated
* Purges related URLs (homepage, categories, tags, author archives)
* Admin bar button for quick access from anywhere
* Activity log tracks all purge actions

**CDN URL Rewriting**

* Automatically rewrite static asset URLs to your CDN hostname
* Configurable included directories (themes, uploads, plugins)
* Exclude specific paths or file patterns
* CORS header support for fonts and assets
* Option to disable CDN for logged-in admins (debugging)

**Usage Statistics**

* Dashboard widget showing bandwidth and requests
* 30-day usage chart
* Cache hit rate monitoring
* Settings page with detailed statistics

**WP Rocket Compatibility**

* Sync cache purges between WP Rocket and BunnyCDN
* Serves WP Rocket optimised files through CDN
* Admin bar shortcuts for WP Rocket actions
* Clear Used CSS, Critical CSS, and Priority Elements

**Bunny Fonts**

* Replace Google Fonts with privacy-friendly Bunny Fonts
* Automatic URL rewriting (no code changes needed)
* GDPR compliant alternative to Google Fonts

**Security**

* API key encrypted at rest using WordPress salts
* Masked API key display in settings
* Nonce verification on all actions
* Capability checks (manage_options required)

= Requirements =

* WordPress 6.0 or higher
* PHP 7.4 or higher
* A BunnyCDN account with at least one Pull Zone

== Installation ==

1. Upload the `bunnycdn-cache-purge` folder to `/wp-content/plugins/`
2. Activate the plugin through the Plugins menu
3. Go to **BunnyCDN Cache** in the admin menu
4. Enter your BunnyCDN API key and select your Pull Zone
5. Configure CDN rewriting if desired
6. Save settings

= Finding Your API Key =

1. Log into your BunnyCDN dashboard
2. Go to Account Settings
3. Click on the API section
4. Copy your API key

= Setting Up CDN Rewriting =

1. Enable CDN URL rewriting in the plugin settings
2. Enter your CDN hostname (e.g., cdn.example.com)
3. Configure which directories to include
4. Test your site to ensure assets load correctly

== Frequently Asked Questions ==

= Where do I find my BunnyCDN API key? =

Log into your BunnyCDN dashboard, go to Account Settings, then the API section. Your API key is listed there.

= What's the difference between purging all and purging a URL? =

Purging all clears every cached file in your pull zone. This is useful after major site changes. Purging a specific URL only invalidates that one page, which is faster and uses fewer API calls.

= Does auto-purge work with custom post types? =

Yes, the auto-purge feature works with any published post type.

= Will this slow down my site? =

No. The plugin only makes API calls when you explicitly purge or when content is updated. CDN rewriting happens during page generation with minimal overhead.

= Can I use this with WP Rocket? =

Yes. Enable the WP Rocket compatibility option to sync cache purges and serve WP Rocket optimised files through your CDN. You should disable WP Rocket's own CDN feature to avoid conflicts.

= Is my API key secure? =

Yes. The API key is encrypted using AES-256-CBC with your WordPress salts before being stored in the database. It's never exposed in page source.

= What about GDPR and Google Fonts? =

Enable Bunny Fonts to automatically replace Google Fonts URLs with Bunny Fonts, which is GDPR compliant and doesn't track users.

== Screenshots ==

1. Main settings page with API configuration
2. CDN rewriting options
3. Usage statistics and charts
4. Dashboard widget
5. Admin bar purge menu

== Changelog ==

= 1.0.0 =
* Initial release
* Cache purging (full zone and specific URLs)
* CDN URL rewriting with configurable directories
* Auto-purge on content updates
* WP Rocket compatibility
* Bunny Fonts integration
* Usage statistics dashboard
* Admin bar integration
* Encrypted API key storage
* Activity logging

== Upgrade Notice ==

= 1.0.0 =
Initial release.
