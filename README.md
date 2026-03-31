# BunnyCDN Manager

A complete BunnyCDN integration for WordPress. Automatically purge cache when content changes, rewrite URLs to serve assets through your CDN, monitor bandwidth usage, and keep WP Rocket in sync.

![Banner](assets/images/banner-772x250.png)

## Features

### Cache Management
- Purge entire CDN cache with one click
- Purge specific URLs or bulk purge multiple URLs
- Auto-purge when posts, pages, or custom post types are updated
- Purges related URLs (homepage, categories, tags, author archives)
- Admin bar button for quick access from anywhere
- Activity log tracks all purge actions

### CDN URL Rewriting
- Automatically rewrite static asset URLs to your CDN hostname
- Configurable included directories (themes, uploads, plugins)
- Exclude specific paths or file patterns
- CORS header support for fonts and assets
- Option to disable CDN for logged-in admins (debugging)

### Usage Statistics
- Dashboard widget showing bandwidth and requests
- 30-day usage chart
- Cache hit rate monitoring
- Settings page with detailed statistics

### WP Rocket Compatibility
- Sync cache purges between WP Rocket and BunnyCDN
- Serves WP Rocket optimised files through CDN
- Admin bar shortcuts for WP Rocket actions
- Clear Used CSS, Critical CSS, and Priority Elements

### Bunny Fonts
- Replace Google Fonts with privacy-friendly Bunny Fonts
- Automatic URL rewriting (no code changes needed)
- GDPR compliant alternative to Google Fonts

### Security
- API key encrypted at rest using WordPress salts
- Masked API key display in settings
- Nonce verification on all actions
- Capability checks (manage_options required)

## Requirements

- WordPress 6.0 or higher
- PHP 7.4 or higher
- A BunnyCDN account with at least one Pull Zone

## Installation

1. Download the latest release
2. Upload to `/wp-content/plugins/bunnycdn-cache-purge/`
3. Activate the plugin
4. Go to **BunnyCDN Manager** in the admin menu
5. Enter your API key and select your Pull Zone

### Finding Your API Key

1. Log into your BunnyCDN dashboard
2. Go to Account Settings
3. Click on the API section
4. Copy your API key

## Screenshots

Coming soon.

## Changelog

### 1.0.0
- Initial release
- Cache purging (full zone and specific URLs)
- CDN URL rewriting with configurable directories
- Auto-purge on content updates
- WP Rocket compatibility
- Bunny Fonts integration
- Usage statistics dashboard
- Admin bar integration
- Encrypted API key storage
- Activity logging

## License

GPL v2 or later. See [LICENSE](https://www.gnu.org/licenses/gpl-2.0.html).

## Author

[Michael Overton](https://overton.cloud)
