<?php
/**
 * Plugin Name: BunnyCDN Manager
 * Plugin URI: https://overton.cloud/plugins/bunnycdn-manager
 * Description: Manage your BunnyCDN integration from WordPress. Cache purging, CDN URL rewriting, usage statistics, WP Rocket compatibility, and Bunny Fonts.
 * Version: 1.0.0
 * Author: Michael Overton
 * Author URI: https://overton.cloud
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: bunnycdn-cache-purge
 */

if (!defined('ABSPATH')) {
    exit;
}

class BunnyCDN_Cache_Purge {

    private $api_key;
    private $pull_zone_id;
    
    // CDN Rewriting settings
    private $cdn_enabled;
    private $cdn_hostname;
    private $site_url;
    private $excluded_paths;
    private $included_directories;
    private $cors_enabled;
    private $cors_extensions;
    private $disable_for_admin;
    private $bunny_fonts_enabled;
    private $wp_rocket_compat;

    public function __construct() {
        // Decrypt API key when loading
        $encrypted_key = get_option('bunnycdn_api_key', '');
        $this->api_key = $this->decrypt_api_key($encrypted_key);
        
        $this->pull_zone_id = get_option('bunnycdn_pull_zone_id', '');
        
        // CDN Rewriting options
        $this->cdn_enabled = get_option('bunnycdn_cdn_enabled', false);
        $this->cdn_hostname = get_option('bunnycdn_cdn_hostname', '');
        $this->site_url = get_option('bunnycdn_site_url', home_url());
        $this->excluded_paths = get_option('bunnycdn_excluded_paths', ['*.php']);
        $this->included_directories = get_option('bunnycdn_included_directories', ['wp-includes/', 'wp-content/themes/', 'wp-content/uploads/']);
        $this->cors_enabled = get_option('bunnycdn_cors_enabled', true);
        $this->cors_extensions = get_option('bunnycdn_cors_extensions', ['eot', 'ttf', 'woff', 'woff2', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg']);
        $this->disable_for_admin = get_option('bunnycdn_disable_for_admin', false);
        $this->bunny_fonts_enabled = get_option('bunnycdn_bunny_fonts', false);
        $this->wp_rocket_compat = get_option('bunnycdn_wp_rocket_compat', false);
        
        // If WP Rocket compat is enabled, add cache directory to included directories
        if ($this->wp_rocket_compat && !in_array('wp-content/cache/', $this->included_directories)) {
            $this->included_directories[] = 'wp-content/cache/';
        }

        // Admin menu
        add_action('admin_menu', [$this, 'add_admin_menu']);

        // Settings link on plugins page
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_settings_link']);

        // Settings
        add_action('admin_init', [$this, 'register_settings']);
        
        // Handle URL-based purge actions (admin bar)
        add_action('admin_init', [$this, 'handle_purge_actions']);
        add_action('template_redirect', [$this, 'handle_purge_actions']);
        
        // AJAX handler for fetching pull zones
        add_action('wp_ajax_bunnycdn_get_pullzones', [$this, 'ajax_get_pullzones']);
        add_action('wp_ajax_bunnycdn_get_hostnames', [$this, 'ajax_get_hostnames']);

        // Admin bar button
        add_action('admin_bar_menu', [$this, 'add_admin_bar_button'], 100);

        // AJAX handlers (for settings page)
        add_action('wp_ajax_bunnycdn_purge_all', [$this, 'ajax_purge_all']);
        add_action('wp_ajax_bunnycdn_purge_url', [$this, 'ajax_purge_url']);
        add_action('wp_ajax_bunnycdn_clear_log', [$this, 'ajax_clear_log']);

        // Auto-purge on post update
        add_action('save_post', [$this, 'auto_purge_post'], 10, 3);

        // Admin notices
        add_action('admin_notices', [$this, 'admin_notices']);
        add_action('wp_head', [$this, 'frontend_notices']);

        // Dashboard widget
        add_action('wp_dashboard_setup', [$this, 'add_dashboard_widget']);

        // Enqueue admin scripts
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);
        add_action('wp_enqueue_scripts', [$this, 'enqueue_admin_bar_scripts']);
        
        // CDN URL Rewriting - defer to wp action when WordPress is fully loaded
        if ($this->cdn_enabled && !empty($this->cdn_hostname)) {
            add_action('wp', [$this, 'setup_cdn_rewriting']);
        }
        
        // WP Rocket integration - purge BunnyCDN when WP Rocket purges
        if ($this->wp_rocket_compat) {
            add_action('after_rocket_clean_domain', [$this, 'purge_all_cache']);
            add_action('after_rocket_clean_post', [$this, 'wp_rocket_purge_post'], 10, 3);
            add_action('after_rocket_clean_files', [$this, 'purge_all_cache']);
        }
        
        // Bunny Fonts rewriting
        if ($this->bunny_fonts_enabled) {
            add_filter('style_loader_src', [$this, 'rewrite_google_fonts'], 10, 2);
            add_filter('script_loader_src', [$this, 'rewrite_google_fonts'], 10, 2);
            add_action('wp_head', [$this, 'rewrite_preconnect_hints'], 1);
        }
    }
    
    /**
     * Setup CDN rewriting hooks (called on 'wp' action when WordPress is fully loaded)
     */
    public function setup_cdn_rewriting() {
        // Don't run in admin
        if (is_admin()) {
            return;
        }
        
        // Check if user is admin and should be excluded
        if ($this->disable_for_admin && is_user_logged_in() && current_user_can('manage_options')) {
            return;
        }
        
        // Rewrite script and style URLs (final enqueued URLs only)
        add_filter('script_loader_src', [$this, 'rewrite_asset_url'], 999, 2);
        add_filter('style_loader_src', [$this, 'rewrite_asset_url'], 999, 2);
        
        // Rewrite content URLs (images in posts, etc.)
        add_filter('the_content', [$this, 'rewrite_content_urls'], 999);
        add_filter('widget_text', [$this, 'rewrite_content_urls'], 999);
        
        // Rewrite srcset for responsive images
        add_filter('wp_calculate_image_srcset', [$this, 'rewrite_srcset'], 999, 5);
        
        // Rewrite attachment URLs
        add_filter('wp_get_attachment_url', [$this, 'rewrite_attachment_url'], 999, 2);
        add_filter('wp_get_attachment_image_src', [$this, 'rewrite_attachment_image_src'], 999, 4);
        
        // Use output buffering to catch anything the filters miss (like minified assets)
        // Start very late so other plugins have finished their work
        add_action('template_redirect', [$this, 'start_output_buffer'], 9999);
    }
    
    /**
     * Start output buffering for final HTML rewriting
     */
    public function start_output_buffer() {
        ob_start([$this, 'rewrite_html_urls']);
    }
    
    /**
     * Rewrite URLs in final HTML output
     */
    public function rewrite_html_urls($html) {
        if (empty($html) || empty($this->cdn_hostname)) {
            return $html;
        }
        
        $site_url = untrailingslashit($this->site_url);
        $cdn_url = 'https://' . rtrim($this->cdn_hostname, '/');
        
        // Get included directories
        $directories = array_filter($this->included_directories);
        if (empty($directories)) {
            return $html;
        }
        
        foreach ($directories as $dir) {
            $dir = trim($dir, '/');
            if (empty($dir)) continue;
            
            // Only rewrite URLs that aren't already on the CDN
            // Pattern: src="https://origin.com/wp-content/..." or href="https://origin.com/wp-content/..."
            // But NOT: src="https://cdn.hostname/..."
            
            // Absolute URLs with site URL
            $pattern = '#((?:src|href|data-src|data-lazy-src)=["\'])(' . preg_quote($site_url, '#') . ')(/'. preg_quote($dir, '#') . '/[^"\']+)(["\'])#i';
            $html = preg_replace_callback($pattern, function($matches) use ($cdn_url) {
                $path = $matches[3];
                if ($this->is_excluded_path($path)) {
                    return $matches[0];
                }
                return $matches[1] . $cdn_url . $path . $matches[4];
            }, $html);
            
            // Relative URLs starting with /wp-content/...
            $pattern = '#((?:src|href|data-src|data-lazy-src)=["\'])(/'. preg_quote($dir, '#') . '/[^"\']+)(["\'])#i';
            $html = preg_replace_callback($pattern, function($matches) use ($cdn_url) {
                $path = $matches[2];
                if ($this->is_excluded_path($path)) {
                    return $matches[0];
                }
                return $matches[1] . $cdn_url . $path . $matches[3];
            }, $html);
            
            // CSS url() references with site URL
            $pattern = '#(url\s*\(\s*["\']?)(' . preg_quote($site_url, '#') . ')(/'. preg_quote($dir, '#') . '/[^"\')\s]+)(["\']?\s*\))#i';
            $html = preg_replace_callback($pattern, function($matches) use ($cdn_url) {
                $path = $matches[3];
                if ($this->is_excluded_path($path)) {
                    return $matches[0];
                }
                return $matches[1] . $cdn_url . $path . $matches[4];
            }, $html);
            
            // CSS url() references with relative paths
            $pattern = '#(url\s*\(\s*["\']?)(/'. preg_quote($dir, '#') . '/[^"\')\s]+)(["\']?\s*\))#i';
            $html = preg_replace_callback($pattern, function($matches) use ($cdn_url) {
                $path = $matches[2];
                if ($this->is_excluded_path($path)) {
                    return $matches[0];
                }
                return $matches[1] . $cdn_url . $path . $matches[3];
            }, $html);
        }
        
        return $html;
    }
    
    /**
     * Rewrite a single URL to CDN if it matches included directories
     */
    private function maybe_rewrite_url($url) {
        if (empty($url) || empty($this->cdn_hostname)) {
            return $url;
        }
        
        $site_url = untrailingslashit($this->site_url);
        $cdn_url = 'https://' . rtrim($this->cdn_hostname, '/');
        
        // Check if URL is from this site
        if (strpos($url, $site_url) !== 0 && strpos($url, '/') !== 0) {
            return $url;
        }
        
        // Get the path from the URL
        $path = $url;
        if (strpos($url, $site_url) === 0) {
            $path = substr($url, strlen($site_url));
        }
        
        // Check if path is in included directories
        $directories = array_filter($this->included_directories);
        $should_rewrite = false;
        
        foreach ($directories as $dir) {
            $dir = '/' . trim($dir, '/') . '/';
            if (strpos($path, $dir) === 0 || strpos($path, ltrim($dir, '/')) === 0) {
                $should_rewrite = true;
                break;
            }
        }
        
        if (!$should_rewrite) {
            return $url;
        }
        
        // Check exclusions
        if ($this->is_excluded_path($path)) {
            return $url;
        }
        
        // Rewrite to CDN
        if (strpos($url, $site_url) === 0) {
            return $cdn_url . $path;
        } else {
            return $cdn_url . $path;
        }
    }
    
    /**
     * Rewrite script/style asset URLs
     */
    public function rewrite_asset_url($src, $handle) {
        return $this->maybe_rewrite_url($src);
    }
    
    /**
     * Rewrite URLs in post content
     */
    public function rewrite_content_urls($content) {
        if (empty($content)) {
            return $content;
        }
        
        $site_url = untrailingslashit($this->site_url);
        $cdn_url = 'https://' . rtrim($this->cdn_hostname, '/');
        
        // Match src and href attributes
        $pattern = '/(src|href)=["\'](' . preg_quote($site_url, '/') . ')?(\/?wp-content\/uploads\/[^"\']+)["\']/i';
        
        $content = preg_replace_callback($pattern, function($matches) use ($cdn_url) {
            $attr = $matches[1];
            $path = $matches[3];
            
            if (strpos($path, '/') !== 0) {
                $path = '/' . $path;
            }
            
            if ($this->is_excluded_path($path)) {
                return $matches[0];
            }
            
            return $attr . '="' . $cdn_url . $path . '"';
        }, $content);
        
        return $content;
    }
    
    /**
     * Rewrite srcset URLs for responsive images
     */
    public function rewrite_srcset($sources, $size_array, $image_src, $image_meta, $attachment_id) {
        if (!is_array($sources)) {
            return $sources;
        }
        
        foreach ($sources as $width => $source) {
            $sources[$width]['url'] = $this->maybe_rewrite_url($source['url']);
        }
        
        return $sources;
    }
    
    /**
     * Rewrite attachment URLs
     */
    public function rewrite_attachment_url($url, $attachment_id) {
        return $this->maybe_rewrite_url($url);
    }
    
    /**
     * Rewrite attachment image src
     */
    public function rewrite_attachment_image_src($image, $attachment_id, $size, $icon) {
        if (is_array($image) && !empty($image[0])) {
            $image[0] = $this->maybe_rewrite_url($image[0]);
        }
        return $image;
    }
    
    /**
     * Rewrite theme directory URLs
     */
    public function rewrite_directory_url($url, $theme_directory = '', $theme = '') {
        return $this->maybe_rewrite_url($url);
    }
    
    /**
     * Rewrite includes URL
     */
    public function rewrite_includes_url($url, $path) {
        return $this->maybe_rewrite_url($url);
    }
    
    /**
     * Check if a path should be excluded from CDN rewriting
     */
    private function is_excluded_path($path) {
        if (empty($this->excluded_paths)) {
            return false;
        }
        
        foreach ($this->excluded_paths as $pattern) {
            $pattern = trim($pattern);
            if (empty($pattern)) continue;
            
            // Convert wildcard pattern to regex
            $regex = str_replace('\*', '.*', preg_quote($pattern, '#'));
            
            if (preg_match('#' . $regex . '#i', $path)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Rewrite Google Fonts URLs to Bunny Fonts
     */
    public function rewrite_google_fonts($src, $handle) {
        if (empty($src)) {
            return $src;
        }
        
        // Replace Google Fonts with Bunny Fonts
        $google_fonts_domains = [
            'fonts.googleapis.com',
            'fonts.gstatic.com',
        ];
        
        foreach ($google_fonts_domains as $domain) {
            if (strpos($src, $domain) !== false) {
                $src = str_replace($domain, 'fonts.bunny.net', $src);
            }
        }
        
        return $src;
    }
    
    /**
     * Rewrite preconnect hints for Google Fonts
     */
    public function rewrite_preconnect_hints() {
        // Remove Google Fonts preconnect and add Bunny Fonts
        remove_action('wp_head', 'wp_preload_resources', 1);
        
        echo '<link rel="preconnect" href="https://fonts.bunny.net" crossorigin>' . "\n";
    }

    /**
     * Handle URL-based purge actions from admin bar
     */
    public function handle_purge_actions() {
        if (!isset($_GET['bunnycdn_action'])) {
            return;
        }

        if (!current_user_can('manage_options')) {
            return;
        }

        $action = sanitize_text_field($_GET['bunnycdn_action']);
        $nonce = isset($_GET['_wpnonce']) ? $_GET['_wpnonce'] : '';

        // Verify nonce
        if (!wp_verify_nonce($nonce, 'bunnycdn_' . $action)) {
            $this->set_admin_notice('error', 'Security check failed. Please try again.');
            $this->redirect_back();
            return;
        }

        switch ($action) {
            case 'purge_all':
                $result = $this->purge_cache();
                if ($result['success']) {
                    $this->set_admin_notice('success', 'Entire cache purged successfully.');
                } else {
                    $this->set_admin_notice('error', 'Cache purge failed: ' . $result['message']);
                }
                break;

            case 'purge_url':
                $url = isset($_GET['purge_url']) ? esc_url_raw($_GET['purge_url']) : '';
                if (empty($url)) {
                    $this->set_admin_notice('error', 'No URL provided.');
                } else {
                    $result = $this->purge_url($url);
                    if ($result['success']) {
                        $this->set_admin_notice('success', 'Page cache purged: ' . esc_html($url));
                    } else {
                        $this->set_admin_notice('error', 'Purge failed: ' . $result['message']);
                    }
                }
                break;
                
            case 'wprocket_clear_preload':
                if (function_exists('rocket_clean_domain')) {
                    rocket_clean_domain();
                    // Trigger preload if available
                    if (function_exists('run_rocket_bot')) {
                        run_rocket_bot();
                    } elseif (function_exists('rocket_preload_cache')) {
                        rocket_preload_cache();
                    }
                    // Also purge BunnyCDN
                    $this->purge_cache();
                    $this->set_admin_notice('success', 'WP Rocket cache cleared and preload triggered. BunnyCDN cache also purged.');
                } else {
                    $this->set_admin_notice('error', 'WP Rocket is not active.');
                }
                break;
                
            case 'wprocket_clear_usedcss':
                if (function_exists('rocket_clean_used_css')) {
                    rocket_clean_used_css();
                    $this->set_admin_notice('success', 'WP Rocket Used CSS cleared.');
                } elseif (class_exists('\WP_Rocket\Engine\Optimization\RUCSS\Controller\UsedCSS')) {
                    // Alternative method for newer WP Rocket versions
                    global $wpdb;
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                    // Safe: table name uses only $wpdb->prefix which comes from wp-config.php, no user input
                    $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}wpr_rucss_used_css");
                    // Clear the cache folder
                    $upload_dir = wp_upload_dir();
                    $rucss_path = $upload_dir['basedir'] . '/wp-rocket/used-css/';
                    if (is_dir($rucss_path)) {
                        $this->delete_directory_contents($rucss_path);
                    }
                    $this->set_admin_notice('success', 'WP Rocket Used CSS cleared.');
                } else {
                    $this->set_admin_notice('error', 'WP Rocket Used CSS feature not available.');
                }
                break;
                
            case 'wprocket_clear_critical':
                // Clear Critical CSS / Above the Fold
                $cleared = false;
                
                // Try clearing critical CSS
                if (function_exists('rocket_clean_critical_css')) {
                    rocket_clean_critical_css();
                    $cleared = true;
                }
                
                // Clear Above the Fold (priority elements) for newer versions
                if (class_exists('\WP_Rocket\Engine\Optimization\AboveTheFold\Database\Queries\AboveTheFold')) {
                    global $wpdb;
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
                    // Safe: table name uses only $wpdb->prefix which comes from wp-config.php, no user input
                    $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}wpr_above_the_fold");
                    $cleared = true;
                }
                
                // Clear the critical CSS folder
                $upload_dir = wp_upload_dir();
                $critical_path = $upload_dir['basedir'] . '/wp-rocket/critical-css/';
                if (is_dir($critical_path)) {
                    $this->delete_directory_contents($critical_path);
                    $cleared = true;
                }
                
                if ($cleared) {
                    $this->set_admin_notice('success', 'WP Rocket Priority Elements / Critical CSS cleared.');
                } else {
                    $this->set_admin_notice('error', 'WP Rocket Critical CSS feature not available.');
                }
                break;
        }

        $this->redirect_back();
    }
    
    /**
     * Delete contents of a directory (with path traversal protection)
     */
    private function delete_directory_contents($dir) {
        if (!is_dir($dir)) {
            return;
        }
        
        // Security: only allow deletion within wp-content/uploads
        $upload_dir = wp_upload_dir();
        $uploads_base = realpath($upload_dir['basedir']);
        $target_dir = realpath($dir);
        
        if ($uploads_base === false || $target_dir === false) {
            return;
        }
        
        // Ensure target is within uploads directory
        if (strpos($target_dir, $uploads_base) !== 0) {
            return;
        }
        
        $files = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );
        
        foreach ($files as $file) {
            if ($file->isDir()) {
                rmdir($file->getRealPath());
            } else {
                unlink($file->getRealPath());
            }
        }
    }

    /**
     * Set a transient notice to display after redirect
     */
    private function set_admin_notice($type, $message) {
        set_transient('bunnycdn_notice_' . get_current_user_id(), [
            'type'    => $type,
            'message' => $message,
        ], 30);
    }

    /**
     * Redirect back to the referring page
     */
    private function redirect_back() {
        $redirect = isset($_GET['redirect_to']) ? esc_url_raw($_GET['redirect_to']) : wp_get_referer();
        
        if (!$redirect) {
            $redirect = admin_url();
        }

        // Remove our query args from redirect URL
        $redirect = remove_query_arg(['bunnycdn_action', '_wpnonce', 'purge_url', 'redirect_to'], $redirect);

        wp_safe_redirect($redirect);
        exit;
    }

    /**
     * Add admin menu page
     */
    public function add_admin_menu() {
        add_menu_page(
            'BunnyCDN Cache',
            'BunnyCDN Cache',
            'manage_options',
            'bunnycdn-cache-purge',
            [$this, 'render_admin_page'],
            $this->get_icon_svg(),
            80
        );
    }

    /**
     * Get the BunnyCDN icon as a base64 encoded SVG
     */
    private function get_icon_svg() {
        $svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 39 43" fill="#a7aaad"><path d="M3.9,26.4C4.1,22 7.1,18.2 11.3,16.9C11.388,16.856 11.496,16.831 11.614,16.809C12.81,16.485 14.005,16.4 15.2,16.4C17,16.5 18.8,17.1 20.4,18C22.035,18.916 23.072,19.104 24.069,18.705C24.26,18.626 24.45,18.528 24.642,18.411C24.98,18.203 25.325,17.931 25.7,17.6C26.7,16.8 27.8,14.1 26.1,13.5C25.5,13.3 25,13.2 24.4,13.1C21.3,12.5 15.8,11.9 13.8,10.8C10.6,9 8.4,5.3 9.7,1.8L30.7,13.2L31.3,13.5C31.34,13.532 31.38,13.567 31.42,13.604L37.3,16.8C38,17.1 38.2,17.9 37.9,18.6C37.8,18.9 37.6,19.1 37.3,19.2C35.2,20.5 32.9,21.4 30.5,21.8L24.7,33.6C24.7,33.6 22.9,37.7 17.9,36.1C19.978,34.022 22.448,32.14 22.5,29C22.5,28.967 22.5,28.933 22.5,28.9C22.5,27.43 21.995,26.091 21.148,25.045C20.051,23.728 18.383,22.9 16.5,22.9C16.103,22.9 15.715,22.937 15.34,23.007C15.46,23.002 15.58,23 15.7,23C12.7,23.4 10.4,25.9 10.4,29C10.4,31.074 11.424,32.563 12.738,33.888C13.746,34.888 14.911,35.799 15.91,36.807C16.263,37.158 16.598,37.519 16.9,37.9C17.701,38.992 17.813,40.349 17.351,41.507C17.186,41.971 16.942,42.402 16.6,42.8C16,42.2 15.1,41.3 14.2,40.5C11.9,38.3 9.1,35.8 7.2,33.6C7.191,33.549 7.183,33.497 7.174,33.446C6.688,32.899 6.256,32.379 5.9,31.9C4.6,30.4 3.9,28.4 3.9,26.4ZM21,6.8C20,4.6 20.3,2 21.8,0L30.9,12.2L21,6.8ZM16.5,26.7C17.7,26.7 18.7,27.7 18.7,29C18.7,30.2 17.7,31.2 16.4,31.2C15.2,31.2 14.2,30.2 14.2,29C14.3,27.8 15.3,26.7 16.5,26.7ZM2.3,14.8C3.5,14.8 4.6,15.8 4.6,17.1L4.6,19.4L2.3,19.4C1.1,19.4 0,18.4 0,17.1C0,15.9 1,14.8 2.3,14.8Z"/></svg>';
        return 'data:image/svg+xml;base64,' . base64_encode($svg);
    }

    /**
     * Add settings link to plugins page
     */
    public function add_settings_link($links) {
        $settings_link = '<a href="' . admin_url('admin.php?page=bunnycdn-cache-purge') . '">Settings</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    /**
     * AJAX handler: Get pull zones from API
     */
    public function ajax_get_pullzones() {
        check_ajax_referer('bunnycdn_purge_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }

        $api_key = isset($_POST['api_key']) ? sanitize_text_field($_POST['api_key']) : '';

        if (empty($api_key)) {
            wp_send_json_error(['message' => 'No API key provided.']);
        }

        $pullzones = $this->fetch_pullzones($api_key);

        if ($pullzones['success']) {
            wp_send_json_success(['pullzones' => $pullzones['data']]);
        } else {
            wp_send_json_error(['message' => $pullzones['message']]);
        }
    }

    /**
     * Fetch pull zones from BunnyCDN API
     */
    public function fetch_pullzones($api_key = null) {
        $api_key = $api_key ?: $this->api_key;

        if (empty($api_key)) {
            return [
                'success' => false,
                'message' => 'API key not configured.',
            ];
        }

        $response = wp_remote_get(
            'https://api.bunny.net/pullzone',
            [
                'headers' => [
                    'AccessKey'    => $api_key,
                    'Content-Type' => 'application/json',
                ],
                'timeout' => 30,
            ]
        );

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => $response->get_error_message(),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($code === 200) {
            $data = json_decode($body, true);
            
            if (is_array($data)) {
                $pullzones = array_map(function($zone) {
                    // Collect all hostnames
                    $hostnames = [];
                    $primary_hostname = '';
                    
                    if (!empty($zone['Hostnames']) && is_array($zone['Hostnames'])) {
                        foreach ($zone['Hostnames'] as $host) {
                            if (!empty($host['Value'])) {
                                $hostnames[] = $host['Value'];
                                // Prefer custom hostname, fall back to bunny.net hostname
                                if (strpos($host['Value'], '.b-cdn.net') === false) {
                                    if (empty($primary_hostname)) {
                                        $primary_hostname = $host['Value'];
                                    }
                                } elseif (empty($primary_hostname)) {
                                    $primary_hostname = $host['Value'];
                                }
                            }
                        }
                    }
                    
                    return [
                        'id'        => $zone['Id'],
                        'name'      => $zone['Name'],
                        'url'       => $primary_hostname ? 'https://' . $primary_hostname : '',
                        'hostnames' => $hostnames,
                    ];
                }, $data);

                return [
                    'success' => true,
                    'data'    => $pullzones,
                ];
            }
        }

        return [
            'success' => false,
            'message' => "API returned status {$code}: {$body}",
        ];
    }

    /**
     * Fetch statistics from BunnyCDN API
     */
    public function fetch_statistics() {
        if (empty($this->api_key) || empty($this->pull_zone_id)) {
            return ['success' => false, 'message' => 'Not configured'];
        }
        
        // Cache stats for 5 minutes to avoid hammering the API
        $cache_key = 'bunnycdn_stats_' . $this->pull_zone_id;
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return $cached;
        }
        
        // Get stats for last 30 days
        $date_from = date('Y-m-d\TH:i:s\Z', strtotime('-30 days'));
        $date_to = date('Y-m-d\TH:i:s\Z');
        
        $url = add_query_arg([
            'dateFrom'   => $date_from,
            'dateTo'     => $date_to,
            'pullZone'   => $this->pull_zone_id,
            'hourly'     => 'false',
        ], 'https://api.bunny.net/statistics');
        
        $response = wp_remote_get($url, [
            'headers' => [
                'AccessKey'    => $this->api_key,
                'Content-Type' => 'application/json',
            ],
            'timeout' => 30,
        ]);
        
        if (is_wp_error($response)) {
            return ['success' => false, 'message' => $response->get_error_message()];
        }
        
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($code !== 200) {
            return ['success' => false, 'message' => "API returned status {$code}"];
        }
        
        $data = json_decode($body, true);
        if (!is_array($data)) {
            return ['success' => false, 'message' => 'Invalid response'];
        }
        
        // Calculate totals
        $bandwidth_total = isset($data['TotalBandwidthUsed']) ? (int)$data['TotalBandwidthUsed'] : 0;
        $bandwidth_cached = isset($data['CacheHitRate']) ? $bandwidth_total * ($data['CacheHitRate'] / 100) : 0;
        $requests_total = isset($data['TotalRequestsServed']) ? (int)$data['TotalRequestsServed'] : 0;
        $cache_hit_rate = isset($data['CacheHitRate']) ? round((float)$data['CacheHitRate'], 1) : 0;
        
        // Calculate cached requests (approximate based on cache hit rate)
        $requests_cached = round($requests_total * ($cache_hit_rate / 100));
        
        $result = [
            'success'                   => true,
            'bandwidth'                 => $bandwidth_total,
            'bandwidth_formatted'       => $this->format_bytes($bandwidth_total),
            'bandwidth_cached'          => $bandwidth_cached,
            'bandwidth_cached_formatted'=> $this->format_bytes($bandwidth_cached),
            'requests'                  => $requests_total,
            'requests_formatted'        => $this->format_number($requests_total),
            'requests_cached'           => $requests_cached,
            'requests_cached_formatted' => $this->format_number($requests_cached),
            'cache_hit_rate'            => $cache_hit_rate,
        ];
        
        // Cache for 5 minutes
        set_transient($cache_key, $result, 5 * MINUTE_IN_SECONDS);
        
        return $result;
    }
    
    /**
     * Format bytes to human readable
     */
    private function format_bytes($bytes) {
        if ($bytes >= 1099511627776) {
            return round($bytes / 1099511627776, 2) . ' TB';
        } elseif ($bytes >= 1073741824) {
            return round($bytes / 1073741824, 2) . ' GB';
        } elseif ($bytes >= 1048576) {
            return round($bytes / 1048576, 2) . ' MB';
        } elseif ($bytes >= 1024) {
            return round($bytes / 1024, 2) . ' KB';
        }
        return $bytes . ' B';
    }
    
    /**
     * Format number with K/M suffix
     */
    private function format_number($num) {
        if ($num >= 1000000) {
            return round($num / 1000000, 1) . 'M';
        } elseif ($num >= 1000) {
            return round($num / 1000, 1) . 'K';
        }
        return number_format($num);
    }
    
    /**
     * Fetch statistics with daily breakdown for charts
     */
    public function fetch_statistics_chart($days = 30) {
        if (empty($this->api_key) || empty($this->pull_zone_id)) {
            return ['success' => false, 'message' => 'Not configured'];
        }
        
        // Cache chart stats for 15 minutes
        $cache_key = 'bunnycdn_chart_stats_' . $this->pull_zone_id . '_' . $days;
        $cached = get_transient($cache_key);
        if ($cached !== false) {
            return $cached;
        }
        
        // Get stats for last N days
        $date_from = date('Y-m-d', strtotime("-{$days} days")) . 'T00:00:00Z';
        $date_to = date('Y-m-d') . 'T23:59:59Z';
        
        // Build URL manually to control encoding
        $url = 'https://api.bunny.net/statistics?dateFrom=' . urlencode($date_from) 
             . '&dateTo=' . urlencode($date_to)
             . '&pullZone=' . intval($this->pull_zone_id);
        
        $response = wp_remote_get($url, [
            'headers' => [
                'AccessKey'    => $this->api_key,
                'Content-Type' => 'application/json',
                'Accept'       => 'application/json',
            ],
            'timeout' => 30,
        ]);
        
        if (is_wp_error($response)) {
            return ['success' => false, 'message' => $response->get_error_message()];
        }
        
        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        
        if ($code !== 200) {
            return ['success' => false, 'message' => "API returned status {$code}: " . substr($body, 0, 100)];
        }
        
        $data = json_decode($body, true);
        if (!is_array($data)) {
            return ['success' => false, 'message' => 'Invalid response'];
        }
        
        // Extract daily bandwidth data
        $bandwidth_chart = [];
        $requests_chart = [];
        $cache_hit_chart = [];
        
        if (!empty($data['BandwidthUsedChart']) && is_array($data['BandwidthUsedChart'])) {
            foreach ($data['BandwidthUsedChart'] as $timestamp => $value) {
                // Convert timestamp to date
                $date = date('Y-m-d', strtotime($timestamp));
                $bandwidth_chart[$date] = (int)$value;
            }
        }
        
        if (!empty($data['RequestsServedChart']) && is_array($data['RequestsServedChart'])) {
            foreach ($data['RequestsServedChart'] as $timestamp => $value) {
                $date = date('Y-m-d', strtotime($timestamp));
                $requests_chart[$date] = (int)$value;
            }
        }
        
        if (!empty($data['CacheHitRateChart']) && is_array($data['CacheHitRateChart'])) {
            foreach ($data['CacheHitRateChart'] as $timestamp => $value) {
                $date = date('Y-m-d', strtotime($timestamp));
                $cache_hit_chart[$date] = round((float)$value, 1);
            }
        }
        
        // If no cache hit chart data, calculate from bandwidth (cached vs total)
        if (empty($cache_hit_chart) && !empty($data['BandwidthCachedChart']) && !empty($data['BandwidthUsedChart'])) {
            foreach ($data['BandwidthUsedChart'] as $timestamp => $total) {
                $date = date('Y-m-d', strtotime($timestamp));
                $cached = isset($data['BandwidthCachedChart'][$timestamp]) ? (float)$data['BandwidthCachedChart'][$timestamp] : 0;
                $total = (float)$total;
                $cache_hit_chart[$date] = $total > 0 ? round(($cached / $total) * 100, 1) : 0;
            }
        }
        
        // Last fallback: use overall cache hit rate for all days
        if (empty($cache_hit_chart) && !empty($bandwidth_chart)) {
            $overall_rate = isset($data['CacheHitRate']) ? round((float)$data['CacheHitRate'], 1) : 0;
            foreach ($bandwidth_chart as $date => $value) {
                $cache_hit_chart[$date] = $overall_rate;
            }
        }
        
        // Sort by date
        ksort($bandwidth_chart);
        ksort($requests_chart);
        ksort($cache_hit_chart);
        
        // Calculate totals
        $bandwidth_total = isset($data['TotalBandwidthUsed']) ? (int)$data['TotalBandwidthUsed'] : 0;
        $requests_total = isset($data['TotalRequestsServed']) ? (int)$data['TotalRequestsServed'] : 0;
        $cache_hit_rate = isset($data['CacheHitRate']) ? round((float)$data['CacheHitRate'], 1) : 0;
        $bandwidth_cached = $bandwidth_total * ($cache_hit_rate / 100);
        $requests_cached = round($requests_total * ($cache_hit_rate / 100));
        
        $result = [
            'success'                    => true,
            'bandwidth'                  => $bandwidth_total,
            'bandwidth_formatted'        => $this->format_bytes($bandwidth_total),
            'bandwidth_cached'           => $bandwidth_cached,
            'bandwidth_cached_formatted' => $this->format_bytes($bandwidth_cached),
            'requests'                   => $requests_total,
            'requests_formatted'         => $this->format_number($requests_total),
            'requests_cached'            => $requests_cached,
            'requests_cached_formatted'  => $this->format_number($requests_cached),
            'cache_hit_rate'             => $cache_hit_rate,
            'bandwidth_chart'            => $bandwidth_chart,
            'requests_chart'             => $requests_chart,
            'cache_hit_chart'            => $cache_hit_chart,
            'days'                       => $days,
        ];
        
        // Cache for 15 minutes
        set_transient($cache_key, $result, 15 * MINUTE_IN_SECONDS);
        
        return $result;
    }

    /**
     * Register plugin settings
     */
    public function register_settings() {
        // Core API settings
        register_setting('bunnycdn_cache_purge', 'bunnycdn_api_key', [
            'type' => 'string',
            'sanitize_callback' => [$this, 'sanitize_api_key'],
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_pull_zone_id', [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_auto_purge', [
            'type' => 'boolean',
            'default' => true,
        ]);
        
        // CDN Rewriting settings
        register_setting('bunnycdn_cache_purge', 'bunnycdn_cdn_enabled', [
            'type' => 'boolean',
            'default' => false,
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_cdn_hostname', [
            'type' => 'string',
            'sanitize_callback' => 'sanitize_text_field',
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_site_url', [
            'type' => 'string',
            'sanitize_callback' => 'esc_url_raw',
            'default' => home_url(),
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_excluded_paths', [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_array_setting'],
            'default' => ['*.php'],
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_included_directories', [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_array_setting'],
            'default' => ['wp-includes/', 'wp-content/themes/', 'wp-content/uploads/'],
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_cors_enabled', [
            'type' => 'boolean',
            'default' => true,
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_cors_extensions', [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_array_setting'],
            'default' => ['eot', 'ttf', 'woff', 'woff2', 'css', 'js', 'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'svg'],
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_disable_for_admin', [
            'type' => 'boolean',
            'default' => false,
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_bunny_fonts', [
            'type' => 'boolean',
            'default' => false,
        ]);
        register_setting('bunnycdn_cache_purge', 'bunnycdn_wp_rocket_compat', [
            'type' => 'boolean',
            'default' => false,
        ]);
    }
    
    /**
     * Sanitize array settings
     */
    public function sanitize_array_setting($value) {
        if (is_string($value)) {
            // Handle JSON input from JS
            $decoded = json_decode(stripslashes($value), true);
            if (is_array($decoded)) {
                return array_map('sanitize_text_field', $decoded);
            }
            // Handle comma-separated input
            return array_map('trim', array_filter(explode(',', $value)));
        }
        
        if (is_array($value)) {
            return array_map('sanitize_text_field', $value);
        }
        
        return [];
    }
    
    /**
     * Sanitize API key - encrypt before storing, preserve existing if placeholder
     */
    public function sanitize_api_key($value) {
        $value = sanitize_text_field($value);
        
        // If the placeholder token is submitted, keep the existing encrypted key
        if ($value === '••••••••••••••••') {
            return get_option('bunnycdn_api_key', '');
        }
        
        // If empty, return empty
        if (empty($value)) {
            return '';
        }
        
        // Encrypt the new key before storing
        return $this->encrypt_api_key($value);
    }
    
    /**
     * Encrypt API key using WordPress salts
     */
    private function encrypt_api_key($plaintext) {
        if (empty($plaintext)) {
            return '';
        }
        
        // Check if OpenSSL is available
        if (!function_exists('openssl_encrypt')) {
            // Fallback: return as-is (not ideal, but functional)
            return $plaintext;
        }
        
        $method = 'AES-256-CBC';
        
        // Use AUTH_KEY and AUTH_SALT for encryption key derivation
        $key = hash('sha256', AUTH_KEY . AUTH_SALT, true);
        
        // Generate a random IV
        $iv_length = openssl_cipher_iv_length($method);
        $iv = openssl_random_pseudo_bytes($iv_length);
        
        // Encrypt
        $encrypted = openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv);
        
        if ($encrypted === false) {
            return $plaintext; // Fallback on failure
        }
        
        // Return base64 encoded IV + encrypted data with a prefix to identify encrypted values
        return 'enc:' . base64_encode($iv . $encrypted);
    }
    
    /**
     * Decrypt API key using WordPress salts
     */
    private function decrypt_api_key($encrypted) {
        if (empty($encrypted)) {
            return '';
        }
        
        // Check if this is an encrypted value (has our prefix)
        if (strpos($encrypted, 'enc:') !== 0) {
            // Not encrypted (legacy value), return as-is
            return $encrypted;
        }
        
        // Check if OpenSSL is available
        if (!function_exists('openssl_decrypt')) {
            return ''; // Can't decrypt without OpenSSL
        }
        
        $method = 'AES-256-CBC';
        
        // Use AUTH_KEY and AUTH_SALT for encryption key derivation
        $key = hash('sha256', AUTH_KEY . AUTH_SALT, true);
        
        // Decode the encrypted value (remove prefix first)
        $data = base64_decode(substr($encrypted, 4));
        
        if ($data === false) {
            return '';
        }
        
        // Extract IV and encrypted data
        $iv_length = openssl_cipher_iv_length($method);
        $iv = substr($data, 0, $iv_length);
        $encrypted_data = substr($data, $iv_length);
        
        // Decrypt
        $decrypted = openssl_decrypt($encrypted_data, $method, $key, OPENSSL_RAW_DATA, $iv);
        
        if ($decrypted === false) {
            return '';
        }
        
        return $decrypted;
    }
    
    /**
     * Get masked API key for display in hidden fields
     */
    private function get_masked_api_key() {
        if (empty($this->api_key)) {
            return '';
        }
        return '••••••••••••••••';
    }
    
    /**
     * AJAX handler: Get hostnames for a pull zone
     */
    public function ajax_get_hostnames() {
        check_ajax_referer('bunnycdn_purge_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied']);
        }

        $pull_zone_id = isset($_POST['pull_zone_id']) ? sanitize_text_field($_POST['pull_zone_id']) : '';
        
        if (empty($pull_zone_id)) {
            wp_send_json_error(['message' => 'No pull zone ID provided']);
        }

        $pullzones = $this->fetch_pullzones();
        
        if (!$pullzones['success']) {
            wp_send_json_error(['message' => $pullzones['message']]);
        }
        
        $hostnames = [];
        foreach ($pullzones['data'] as $zone) {
            if ($zone['id'] == $pull_zone_id && !empty($zone['hostnames'])) {
                $hostnames = $zone['hostnames'];
                break;
            }
        }
        
        wp_send_json_success(['hostnames' => $hostnames]);
    }

    /**
     * Add purge button to admin bar
     */
    public function add_admin_bar_button($wp_admin_bar) {
        if (!current_user_can('manage_options')) {
            return;
        }

        if (empty($this->api_key) || empty($this->pull_zone_id)) {
            return;
        }

        // Inline SVG icon
        $icon_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 39 43" width="20" height="20" style="fill:currentColor;vertical-align:middle;margin-right:6px;position:relative;top:-1px;"><path d="M3.9,26.4C4.1,22 7.1,18.2 11.3,16.9C11.388,16.856 11.496,16.831 11.614,16.809C12.81,16.485 14.005,16.4 15.2,16.4C17,16.5 18.8,17.1 20.4,18C22.035,18.916 23.072,19.104 24.069,18.705C24.26,18.626 24.45,18.528 24.642,18.411C24.98,18.203 25.325,17.931 25.7,17.6C26.7,16.8 27.8,14.1 26.1,13.5C25.5,13.3 25,13.2 24.4,13.1C21.3,12.5 15.8,11.9 13.8,10.8C10.6,9 8.4,5.3 9.7,1.8L30.7,13.2L31.3,13.5C31.34,13.532 31.38,13.567 31.42,13.604L37.3,16.8C38,17.1 38.2,17.9 37.9,18.6C37.8,18.9 37.6,19.1 37.3,19.2C35.2,20.5 32.9,21.4 30.5,21.8L24.7,33.6C24.7,33.6 22.9,37.7 17.9,36.1C19.978,34.022 22.448,32.14 22.5,29C22.5,28.967 22.5,28.933 22.5,28.9C22.5,27.43 21.995,26.091 21.148,25.045C20.051,23.728 18.383,22.9 16.5,22.9C16.103,22.9 15.715,22.937 15.34,23.007C15.46,23.002 15.58,23 15.7,23C12.7,23.4 10.4,25.9 10.4,29C10.4,31.074 11.424,32.563 12.738,33.888C13.746,34.888 14.911,35.799 15.91,36.807C16.263,37.158 16.598,37.519 16.9,37.9C17.701,38.992 17.813,40.349 17.351,41.507C17.186,41.971 16.942,42.402 16.6,42.8C16,42.2 15.1,41.3 14.2,40.5C11.9,38.3 9.1,35.8 7.2,33.6C7.191,33.549 7.183,33.497 7.174,33.446C6.688,32.899 6.256,32.379 5.9,31.9C4.6,30.4 3.9,28.4 3.9,26.4ZM21,6.8C20,4.6 20.3,2 21.8,0L30.9,12.2L21,6.8ZM16.5,26.7C17.7,26.7 18.7,27.7 18.7,29C18.7,30.2 17.7,31.2 16.4,31.2C15.2,31.2 14.2,30.2 14.2,29C14.3,27.8 15.3,26.7 16.5,26.7ZM2.3,14.8C3.5,14.8 4.6,15.8 4.6,17.1L4.6,19.4L2.3,19.4C1.1,19.4 0,18.4 0,17.1C0,15.9 1,14.8 2.3,14.8Z"/></svg>';

        // Build purge all URL with nonce
        $purge_all_url = wp_nonce_url(
            add_query_arg([
                'bunnycdn_action' => 'purge_all',
            ], admin_url()),
            'bunnycdn_purge_all'
        );

        $wp_admin_bar->add_node([
            'id'    => 'bunnycdn-purge',
            'title' => $icon_svg . 'Purge BunnyCDN',
            'href'  => $purge_all_url,
            'meta'  => [
                'title' => 'Purge BunnyCDN Cache',
            ],
        ]);

        $wp_admin_bar->add_node([
            'id'     => 'bunnycdn-purge-all',
            'parent' => 'bunnycdn-purge',
            'title'  => 'Purge Entire Cache',
            'href'   => $purge_all_url,
        ]);

        // Add purge current page option - works on frontend and in admin when editing
        $current_url = $this->get_current_page_url();
        if ($current_url) {
            $purge_page_url = wp_nonce_url(
                add_query_arg([
                    'bunnycdn_action' => 'purge_url',
                    'purge_url'       => urlencode($current_url),
                ], admin_url()),
                'bunnycdn_purge_url'
            );

            $wp_admin_bar->add_node([
                'id'     => 'bunnycdn-purge-current',
                'parent' => 'bunnycdn-purge',
                'title'  => 'Purge This Page',
                'href'   => $purge_page_url,
            ]);
        }
        
        // WP Rocket options (only if WP Rocket is active and compat mode is on)
        if ($this->wp_rocket_compat && function_exists('rocket_clean_domain')) {
            // Clear cache & preload
            $wp_admin_bar->add_node([
                'id'     => 'bunnycdn-wprocket-clear-preload',
                'parent' => 'bunnycdn-purge',
                'title'  => 'WP Rocket: Clear & Preload',
                'href'   => wp_nonce_url(
                    add_query_arg(['bunnycdn_action' => 'wprocket_clear_preload'], admin_url()),
                    'bunnycdn_wprocket_clear_preload'
                ),
            ]);
            
            // Clear used CSS
            $wp_admin_bar->add_node([
                'id'     => 'bunnycdn-wprocket-clear-usedcss',
                'parent' => 'bunnycdn-purge',
                'title'  => 'WP Rocket: Clear Used CSS',
                'href'   => wp_nonce_url(
                    add_query_arg(['bunnycdn_action' => 'wprocket_clear_usedcss'], admin_url()),
                    'bunnycdn_wprocket_clear_usedcss'
                ),
            ]);
            
            // Clear critical CSS / priority elements
            $wp_admin_bar->add_node([
                'id'     => 'bunnycdn-wprocket-clear-critical',
                'parent' => 'bunnycdn-purge',
                'title'  => 'WP Rocket: Clear Priority Elements',
                'href'   => wp_nonce_url(
                    add_query_arg(['bunnycdn_action' => 'wprocket_clear_critical'], admin_url()),
                    'bunnycdn_wprocket_clear_critical'
                ),
            ]);
        }

        // Settings link
        $wp_admin_bar->add_node([
            'id'     => 'bunnycdn-settings',
            'parent' => 'bunnycdn-purge',
            'title'  => 'Settings',
            'href'   => admin_url('admin.php?page=bunnycdn-cache-purge'),
        ]);
    }

    /**
     * Get the current page URL for purging
     */
    private function get_current_page_url() {
        // Frontend - use the current URL
        if (!is_admin()) {
            $request_uri = isset($_SERVER['REQUEST_URI']) ? esc_url_raw($_SERVER['REQUEST_URI']) : '/';
            return home_url($request_uri);
        }

        // Admin - check if we're editing a post/page
        global $pagenow, $post;

        if (in_array($pagenow, ['post.php', 'post-new.php']) && !empty($post)) {
            $permalink = get_permalink($post->ID);
            if ($permalink && $post->post_status === 'publish') {
                return $permalink;
            }
        }

        return null;
    }

    /**
     * Enqueue admin scripts and styles
     */
    public function enqueue_admin_scripts($hook) {
        if ($hook === 'toplevel_page_bunnycdn-cache-purge' || is_admin_bar_showing()) {
            $this->enqueue_scripts();
        }
    }

    /**
     * Enqueue scripts for admin bar on frontend
     */
    public function enqueue_admin_bar_scripts() {
        if (is_admin_bar_showing() && current_user_can('manage_options')) {
            $this->enqueue_scripts();
        }
    }

    /**
     * Shared script enqueue
     */
    private function enqueue_scripts() {
        wp_enqueue_script(
            'bunnycdn-cache-purge',
            plugin_dir_url(__FILE__) . 'assets/js/admin.js',
            ['jquery'],
            '1.0.0',
            true
        );

        wp_localize_script('bunnycdn-cache-purge', 'bunnyCDN', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce'    => wp_create_nonce('bunnycdn_purge_nonce'),
        ]);

        wp_enqueue_style(
            'bunnycdn-cache-purge',
            plugin_dir_url(__FILE__) . 'assets/css/admin.css',
            [],
            '1.0.0'
        );
    }

    /**
     * Render admin page
     */
    public function render_admin_page() {
        if (!current_user_can('manage_options')) {
            return;
        }
        
        $is_connected = !empty($this->api_key) && !empty($this->pull_zone_id);
        $pullzone_name = '';
        $pullzones_data = [];
        $cdn_stats = null;
        
        if (!empty($this->api_key)) {
            $pullzones = $this->fetch_pullzones();
            if ($pullzones['success'] && !empty($pullzones['data'])) {
                $pullzones_data = $pullzones['data'];
                foreach ($pullzones_data as $zone) {
                    if ($zone['id'] == $this->pull_zone_id) {
                        $pullzone_name = $zone['name'];
                        break;
                    }
                }
            }
            
            // Fetch CDN statistics with chart data
            if ($is_connected) {
                $cdn_stats = $this->fetch_statistics_chart(30);
            }
        }
        
        $last_purge = $this->get_last_purge();
        $auto_purge = get_option('bunnycdn_auto_purge', true);
        ?>
        <div class="wrap bunnycdn-wrap">
            
            <!-- Header -->
            <div class="bunnycdn-header">
                <div class="bunnycdn-header-icon">
                    <svg viewBox="0 0 39 43"><path d="M3.9,26.4C4.1,22 7.1,18.2 11.3,16.9C11.388,16.856 11.496,16.831 11.614,16.809C12.81,16.485 14.005,16.4 15.2,16.4C17,16.5 18.8,17.1 20.4,18C22.035,18.916 23.072,19.104 24.069,18.705C24.26,18.626 24.45,18.528 24.642,18.411C24.98,18.203 25.325,17.931 25.7,17.6C26.7,16.8 27.8,14.1 26.1,13.5C25.5,13.3 25,13.2 24.4,13.1C21.3,12.5 15.8,11.9 13.8,10.8C10.6,9 8.4,5.3 9.7,1.8L30.7,13.2L31.3,13.5C31.34,13.532 31.38,13.567 31.42,13.604L37.3,16.8C38,17.1 38.2,17.9 37.9,18.6C37.8,18.9 37.6,19.1 37.3,19.2C35.2,20.5 32.9,21.4 30.5,21.8L24.7,33.6C24.7,33.6 22.9,37.7 17.9,36.1C19.978,34.022 22.448,32.14 22.5,29C22.5,28.967 22.5,28.933 22.5,28.9C22.5,27.43 21.995,26.091 21.148,25.045C20.051,23.728 18.383,22.9 16.5,22.9C16.103,22.9 15.715,22.937 15.34,23.007C15.46,23.002 15.58,23 15.7,23C12.7,23.4 10.4,25.9 10.4,29C10.4,31.074 11.424,32.563 12.738,33.888C13.746,34.888 14.911,35.799 15.91,36.807C16.263,37.158 16.598,37.519 16.9,37.9C17.701,38.992 17.813,40.349 17.351,41.507C17.186,41.971 16.942,42.402 16.6,42.8C16,42.2 15.1,41.3 14.2,40.5C11.9,38.3 9.1,35.8 7.2,33.6C7.191,33.549 7.183,33.497 7.174,33.446C6.688,32.899 6.256,32.379 5.9,31.9C4.6,30.4 3.9,28.4 3.9,26.4ZM21,6.8C20,4.6 20.3,2 21.8,0L30.9,12.2L21,6.8ZM16.5,26.7C17.7,26.7 18.7,27.7 18.7,29C18.7,30.2 17.7,31.2 16.4,31.2C15.2,31.2 14.2,30.2 14.2,29C14.3,27.8 15.3,26.7 16.5,26.7ZM2.3,14.8C3.5,14.8 4.6,15.8 4.6,17.1L4.6,19.4L2.3,19.4C1.1,19.4 0,18.4 0,17.1C0,15.9 1,14.8 2.3,14.8Z"/></svg>
                </div>
                <div class="bunnycdn-header-text">
                    <h1>BunnyCDN cache</h1>
                    <p>Purge and manage your CDN cache</p>
                </div>
                <div class="bunnycdn-header-status">
                    <span class="bunnycdn-status-badge <?php echo $is_connected ? '' : 'disconnected'; ?>">
                        <?php echo $is_connected ? 'Connected' : 'Not configured'; ?>
                    </span>
                </div>
            </div>

            <?php if ($is_connected) : ?>
            <!-- Stats Row -->
            <div class="bunnycdn-stats">
                <div class="bunnycdn-stat-card">
                    <p class="bunnycdn-stat-label">Pull zone</p>
                    <p class="bunnycdn-stat-value"><?php echo esc_html($pullzone_name ?: 'Unknown'); ?></p>
                    <p class="bunnycdn-stat-meta">ID: <?php echo esc_html($this->pull_zone_id); ?></p>
                </div>
                <div class="bunnycdn-stat-card">
                    <p class="bunnycdn-stat-label">Last purge</p>
                    <p class="bunnycdn-stat-value"><?php echo esc_html($last_purge['time'] ?: 'Never'); ?></p>
                    <p class="bunnycdn-stat-meta"><?php echo esc_html($last_purge['type'] ?: '—'); ?></p>
                </div>
                <div class="bunnycdn-stat-card">
                    <p class="bunnycdn-stat-label">Auto-purge</p>
                    <p class="bunnycdn-stat-value <?php echo $auto_purge ? 'success' : ''; ?>"><?php echo $auto_purge ? 'Enabled' : 'Disabled'; ?></p>
                    <p class="bunnycdn-stat-meta">On post update</p>
                </div>
            </div>
            <?php endif; ?>

            <!-- Two Column Layout -->
            <div class="bunnycdn-columns">
                
                <!-- Quick Actions -->
                <div class="bunnycdn-card">
                    <h2 class="bunnycdn-card-title">Quick actions</h2>
                    
                    <?php if ($is_connected) : ?>
                        <button type="button" class="bunnycdn-btn-primary" id="bunnycdn-purge-all-btn" style="margin-bottom: 12px;">
                            <svg viewBox="0 0 24 24"><path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            Purge entire cache
                        </button>
                        
                        <div class="bunnycdn-url-group">
                            <input type="url" id="bunnycdn-purge-url" placeholder="https://example.com/page-to-purge/">
                            <button type="button" id="bunnycdn-purge-url-btn">Purge</button>
                        </div>
                        <p class="bunnycdn-help-text">Enter a full URL to purge a specific page from cache</p>
                    <?php else : ?>
                        <p style="color: #6B7280; font-size: 13px;">Configure your API key and select a pull zone to enable cache purging.</p>
                    <?php endif; ?>
                </div>

                <!-- API Configuration -->
                <div class="bunnycdn-card">
                    <h2 class="bunnycdn-card-title">API configuration</h2>
                    
                    <form method="post" action="options.php" id="bunnycdn-settings-form">
                        <?php settings_fields('bunnycdn_cache_purge'); ?>
                        
                        <div class="bunnycdn-field">
                            <label for="bunnycdn_api_key">API key</label>
                            <div class="bunnycdn-field-row">
                                <input type="password" 
                                       id="bunnycdn_api_key" 
                                       name="bunnycdn_api_key" 
                                       value="<?php echo esc_attr($this->get_masked_api_key()); ?>" 
                                       autocomplete="off"
                                       <?php echo !empty($this->api_key) ? 'readonly' : ''; ?>>
                                <?php if (!empty($this->api_key)) : ?>
                                <button type="button" class="bunnycdn-btn-icon" id="bunnycdn-edit-api-key" title="Change API key">
                                    <svg viewBox="0 0 24 24"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
                                </button>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <div class="bunnycdn-field">
                            <label for="bunnycdn_pull_zone_id">Pull zone</label>
                            <div class="bunnycdn-field-row">
                                <select id="bunnycdn_pull_zone_id" 
                                        name="bunnycdn_pull_zone_id" 
                                        <?php echo empty($this->api_key) ? 'disabled' : ''; ?>>
                                    <option value="">— Select a pull zone —</option>
                                    <?php foreach ($pullzones_data as $zone) :
                                        $label = $zone['name'];
                                        if (!empty($zone['url'])) {
                                            $label .= ' (' . $zone['url'] . ')';
                                        }
                                    ?>
                                        <option value="<?php echo esc_attr($zone['id']); ?>" <?php selected($this->pull_zone_id, $zone['id']); ?>>
                                            <?php echo esc_html($label); ?>
                                        </option>
                                    <?php endforeach; ?>
                                </select>
                                <button type="button" class="bunnycdn-btn-icon" id="bunnycdn-refresh-pullzones" <?php echo empty($this->api_key) ? 'disabled' : ''; ?>>
                                    <svg viewBox="0 0 24 24"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
                                </button>
                            </div>
                        </div>
                        
                        <div class="bunnycdn-toggle-row">
                            <div class="bunnycdn-toggle-label">
                                <p class="title">Auto-purge on publish</p>
                                <p class="desc">Clear cache when posts are updated</p>
                            </div>
                            <label class="bunnycdn-toggle">
                                <input type="checkbox" name="bunnycdn_auto_purge" value="1" <?php checked($auto_purge); ?>>
                                <span class="slider"></span>
                            </label>
                        </div>
                        
                        <div class="bunnycdn-save-row">
                            <button type="submit" class="button-primary">Save settings</button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- CDN Usage Stats -->
            <?php if ($cdn_stats && $cdn_stats['success']) : 
                // Prepare chart data
                $chart_labels = [];
                $chart_bandwidth = [];
                foreach ($cdn_stats['bandwidth_chart'] as $date => $value) {
                    $chart_labels[] = date('j M', strtotime($date));
                    $chart_bandwidth[] = round($value / 1048576, 2); // Convert to MB
                }
                $settings_chart_id = 'bunnycdn-settings-chart-' . uniqid();
            ?>
            <div class="bunnycdn-card bunnycdn-card-full">
                <h2 class="bunnycdn-card-title">Usage (last 30 days)</h2>
                <div class="bunnycdn-stats">
                    <div class="bunnycdn-stat-card">
                        <p class="bunnycdn-stat-label">Bandwidth</p>
                        <p class="bunnycdn-stat-value"><?php echo esc_html($cdn_stats['bandwidth_formatted']); ?></p>
                        <p class="bunnycdn-stat-meta"><?php echo esc_html($cdn_stats['bandwidth_cached_formatted']); ?> cached</p>
                    </div>
                    <div class="bunnycdn-stat-card">
                        <p class="bunnycdn-stat-label">Requests</p>
                        <p class="bunnycdn-stat-value"><?php echo esc_html($cdn_stats['requests_formatted']); ?></p>
                        <p class="bunnycdn-stat-meta"><?php echo esc_html($cdn_stats['requests_cached_formatted']); ?> cached</p>
                    </div>
                    <div class="bunnycdn-stat-card">
                        <p class="bunnycdn-stat-label">Cache hit rate</p>
                        <p class="bunnycdn-stat-value <?php echo $cdn_stats['cache_hit_rate'] >= 80 ? 'success' : ''; ?>"><?php echo esc_html($cdn_stats['cache_hit_rate']); ?>%</p>
                        <p class="bunnycdn-stat-meta">Higher is better</p>
                    </div>
                </div>
                
                <div class="bunnycdn-settings-chart">
                    <canvas id="<?php echo esc_attr($settings_chart_id); ?>" height="200"></canvas>
                </div>
                
                <script>
                (function() {
                    function initSettingsChart() {
                        if (typeof Chart === 'undefined') {
                            var script = document.createElement('script');
                            script.src = '<?php echo esc_url(plugin_dir_url(__FILE__) . "assets/js/chart.min.js"); ?>';
                            script.onload = function() { renderSettingsChart(); };
                            document.head.appendChild(script);
                        } else {
                            renderSettingsChart();
                        }
                    }
                    
                    function renderSettingsChart() {
                        var ctx = document.getElementById('<?php echo esc_js($settings_chart_id); ?>');
                        if (!ctx) return;
                        
                        new Chart(ctx, {
                            type: 'line',
                            data: {
                                labels: <?php echo json_encode($chart_labels); ?>,
                                datasets: [{
                                    label: 'Bandwidth (MB)',
                                    data: <?php echo json_encode($chart_bandwidth); ?>,
                                    borderColor: '#FF9500',
                                    backgroundColor: 'rgba(255, 149, 0, 0.1)',
                                    borderWidth: 2,
                                    fill: true,
                                    tension: 0.3,
                                    pointRadius: 0,
                                    pointHoverRadius: 4
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                interaction: { intersect: false, mode: 'index' },
                                plugins: {
                                    legend: { display: false },
                                    tooltip: {
                                        backgroundColor: '#1d2327',
                                        titleColor: '#fff',
                                        bodyColor: '#fff',
                                        padding: 10,
                                        displayColors: false,
                                        callbacks: {
                                            label: function(context) {
                                                return context.parsed.y.toFixed(2) + ' MB';
                                            }
                                        }
                                    }
                                },
                                scales: {
                                    x: {
                                        display: true,
                                        grid: { display: false },
                                        ticks: { maxTicksLimit: 8, font: { size: 11 }, color: '#9CA3AF' }
                                    },
                                    y: {
                                        display: true,
                                        grid: { color: '#f3f4f6' },
                                        ticks: {
                                            font: { size: 11 },
                                            color: '#9CA3AF',
                                            callback: function(value) {
                                                if (value >= 1000) return (value / 1000).toFixed(1) + ' GB';
                                                return value + ' MB';
                                            }
                                        }
                                    }
                                }
                            }
                        });
                    }
                    
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', initSettingsChart);
                    } else {
                        initSettingsChart();
                    }
                })();
                </script>
            </div>
            <?php endif; ?>

            <!-- CDN Rewriting Settings -->
            <div class="bunnycdn-card bunnycdn-card-full">
                <h2 class="bunnycdn-card-title">CDN URL rewriting</h2>
                <p class="bunnycdn-card-desc">Rewrite static asset URLs to serve them through BunnyCDN.</p>
                
                <form method="post" action="options.php" id="bunnycdn-cdn-form">
                    <?php settings_fields('bunnycdn_cache_purge'); ?>
                    
                    <!-- Hidden fields to preserve other settings -->
                    <input type="hidden" name="bunnycdn_api_key" value="<?php echo esc_attr($this->get_masked_api_key()); ?>">
                    <input type="hidden" name="bunnycdn_pull_zone_id" value="<?php echo esc_attr($this->pull_zone_id); ?>">
                    <input type="hidden" name="bunnycdn_auto_purge" value="<?php echo $auto_purge ? '1' : '0'; ?>">
                    
                    <div class="bunnycdn-toggle-row" style="margin-bottom: 24px;">
                        <div class="bunnycdn-toggle-label">
                            <p class="title">Enable CDN rewriting</p>
                            <p class="desc">Rewrite URLs for static assets to use your CDN hostname</p>
                        </div>
                        <label class="bunnycdn-toggle">
                            <input type="checkbox" name="bunnycdn_cdn_enabled" value="1" <?php checked($this->cdn_enabled); ?>>
                            <span class="slider"></span>
                        </label>
                    </div>
                    
                    <div class="bunnycdn-cdn-settings" id="bunnycdn-cdn-settings" style="<?php echo $this->cdn_enabled ? '' : 'display:none;'; ?>">
                        
                        <div class="bunnycdn-field">
                            <label for="bunnycdn_cdn_hostname">CDN hostname</label>
                            <select id="bunnycdn_cdn_hostname" name="bunnycdn_cdn_hostname" <?php echo empty($pullzones_data) ? 'disabled' : ''; ?>>
                                <option value="">— Select a hostname —</option>
                                <?php 
                                foreach ($pullzones_data as $zone) :
                                    if (!empty($zone['hostnames'])) :
                                        foreach ($zone['hostnames'] as $hostname) :
                                ?>
                                    <option value="<?php echo esc_attr($hostname); ?>" <?php selected($this->cdn_hostname, $hostname); ?>>
                                        <?php echo esc_html($hostname); ?>
                                    </option>
                                <?php 
                                        endforeach;
                                    endif;
                                endforeach; 
                                ?>
                            </select>
                            <p class="bunnycdn-help-text">The hostname used to deliver your files. Configure custom hostnames in <a href="https://dash.bunny.net" target="_blank">dash.bunny.net</a>.</p>
                        </div>
                        
                        <div class="bunnycdn-field">
                            <label for="bunnycdn_site_url">Site URL</label>
                            <input type="url" 
                                   id="bunnycdn_site_url" 
                                   name="bunnycdn_site_url" 
                                   value="<?php echo esc_attr($this->site_url ?: home_url()); ?>" 
                                   placeholder="<?php echo esc_attr(home_url()); ?>">
                            <p class="bunnycdn-help-text">The public URL of your website. This helps determine which URLs to rewrite.</p>
                        </div>
                        
                        <div class="bunnycdn-field">
                            <label for="bunnycdn_included_directories">Included directories</label>
                            <div class="bunnycdn-tags-input" id="included-directories-tags">
                                <input type="text" placeholder="Add directory..." id="bunnycdn-add-directory">
                                <input type="hidden" name="bunnycdn_included_directories" id="bunnycdn_included_directories" value="<?php echo esc_attr(json_encode($this->included_directories)); ?>">
                            </div>
                            <div class="bunnycdn-tags-list" id="included-directories-list">
                                <?php foreach ($this->included_directories as $dir) : ?>
                                    <span class="bunnycdn-tag" data-value="<?php echo esc_attr($dir); ?>">
                                        <?php echo esc_html($dir); ?>
                                        <button type="button" class="bunnycdn-tag-remove">&times;</button>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                            <p class="bunnycdn-help-text">Only files in these directories will be served through the CDN.</p>
                        </div>
                        
                        <div class="bunnycdn-field">
                            <label for="bunnycdn_excluded_paths">Excluded paths</label>
                            <div class="bunnycdn-tags-input" id="excluded-paths-tags">
                                <input type="text" placeholder="Add path..." id="bunnycdn-add-excluded">
                                <input type="hidden" name="bunnycdn_excluded_paths" id="bunnycdn_excluded_paths" value="<?php echo esc_attr(json_encode($this->excluded_paths)); ?>">
                            </div>
                            <div class="bunnycdn-tags-list" id="excluded-paths-list">
                                <?php foreach ($this->excluded_paths as $path) : ?>
                                    <span class="bunnycdn-tag" data-value="<?php echo esc_attr($path); ?>">
                                        <?php echo esc_html($path); ?>
                                        <button type="button" class="bunnycdn-tag-remove">&times;</button>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                            <p class="bunnycdn-help-text">Paths to exclude from CDN rewriting. Use <code>*</code> as a wildcard.</p>
                        </div>
                        
                        <div class="bunnycdn-toggle-row">
                            <div class="bunnycdn-toggle-label">
                                <p class="title">Add CORS headers</p>
                                <p class="desc">Add Cross-Origin Resource Sharing headers for specified file types</p>
                            </div>
                            <label class="bunnycdn-toggle">
                                <input type="checkbox" name="bunnycdn_cors_enabled" value="1" <?php checked($this->cors_enabled); ?>>
                                <span class="slider"></span>
                            </label>
                        </div>
                        
                        <div class="bunnycdn-field" id="cors-extensions-field" style="<?php echo $this->cors_enabled ? '' : 'display:none;'; ?>">
                            <label for="bunnycdn_cors_extensions">CORS extensions</label>
                            <div class="bunnycdn-tags-input" id="cors-extensions-tags">
                                <input type="text" placeholder="Add extension..." id="bunnycdn-add-cors">
                                <input type="hidden" name="bunnycdn_cors_extensions" id="bunnycdn_cors_extensions" value="<?php echo esc_attr(json_encode($this->cors_extensions)); ?>">
                            </div>
                            <div class="bunnycdn-tags-list" id="cors-extensions-list">
                                <?php foreach ($this->cors_extensions as $ext) : ?>
                                    <span class="bunnycdn-tag" data-value="<?php echo esc_attr($ext); ?>">
                                        <?php echo esc_html($ext); ?>
                                        <button type="button" class="bunnycdn-tag-remove">&times;</button>
                                    </span>
                                <?php endforeach; ?>
                            </div>
                            <p class="bunnycdn-help-text">File extensions that will receive CORS headers.</p>
                        </div>
                        
                        <div class="bunnycdn-toggle-row">
                            <div class="bunnycdn-toggle-label">
                                <p class="title">Disable for administrators</p>
                                <p class="desc">Don't rewrite URLs for logged-in admin users</p>
                            </div>
                            <label class="bunnycdn-toggle">
                                <input type="checkbox" name="bunnycdn_disable_for_admin" value="1" <?php checked($this->disable_for_admin); ?>>
                                <span class="slider"></span>
                            </label>
                        </div>
                        
                        <div class="bunnycdn-toggle-row">
                            <div class="bunnycdn-toggle-label">
                                <p class="title">WP Rocket compatibility</p>
                                <p class="desc">Serve WP Rocket's cached and minified files through BunnyCDN. Adds <code>wp-content/cache/</code> to included directories.</p>
                            </div>
                            <label class="bunnycdn-toggle">
                                <input type="checkbox" name="bunnycdn_wp_rocket_compat" value="1" <?php checked($this->wp_rocket_compat); ?>>
                                <span class="slider"></span>
                            </label>
                        </div>
                        
                    </div>
                    
                    <div class="bunnycdn-save-row" style="margin-top: 24px;">
                        <button type="submit" class="button-primary">Save CDN settings</button>
                    </div>
                </form>
            </div>
            
            <!-- Bunny Fonts -->
            <div class="bunnycdn-card bunnycdn-card-full">
                <h2 class="bunnycdn-card-title">Bunny Fonts</h2>
                <p class="bunnycdn-card-desc">Replace Google Fonts with privacy-friendly <a href="https://fonts.bunny.net" target="_blank">Bunny Fonts</a>.</p>
                
                <form method="post" action="options.php" id="bunnycdn-fonts-form">
                    <?php settings_fields('bunnycdn_cache_purge'); ?>
                    
                    <!-- Hidden fields to preserve other settings -->
                    <input type="hidden" name="bunnycdn_api_key" value="<?php echo esc_attr($this->get_masked_api_key()); ?>">
                    <input type="hidden" name="bunnycdn_pull_zone_id" value="<?php echo esc_attr($this->pull_zone_id); ?>">
                    <input type="hidden" name="bunnycdn_auto_purge" value="<?php echo $auto_purge ? '1' : '0'; ?>">
                    <input type="hidden" name="bunnycdn_cdn_enabled" value="<?php echo $this->cdn_enabled ? '1' : '0'; ?>">
                    <input type="hidden" name="bunnycdn_cdn_hostname" value="<?php echo esc_attr($this->cdn_hostname); ?>">
                    <input type="hidden" name="bunnycdn_site_url" value="<?php echo esc_attr($this->site_url); ?>">
                    <input type="hidden" name="bunnycdn_included_directories" value="<?php echo esc_attr(json_encode($this->included_directories)); ?>">
                    <input type="hidden" name="bunnycdn_excluded_paths" value="<?php echo esc_attr(json_encode($this->excluded_paths)); ?>">
                    <input type="hidden" name="bunnycdn_cors_enabled" value="<?php echo $this->cors_enabled ? '1' : '0'; ?>">
                    <input type="hidden" name="bunnycdn_cors_extensions" value="<?php echo esc_attr(json_encode($this->cors_extensions)); ?>">
                    <input type="hidden" name="bunnycdn_disable_for_admin" value="<?php echo $this->disable_for_admin ? '1' : '0'; ?>">
                    <input type="hidden" name="bunnycdn_wp_rocket_compat" value="<?php echo $this->wp_rocket_compat ? '1' : '0'; ?>">
                    
                    <div class="bunnycdn-toggle-row">
                        <div class="bunnycdn-toggle-label">
                            <p class="title">Enable Bunny Fonts</p>
                            <p class="desc">Automatically rewrite Google Fonts URLs to fonts.bunny.net for GDPR compliance</p>
                        </div>
                        <label class="bunnycdn-toggle">
                            <input type="checkbox" name="bunnycdn_bunny_fonts" value="1" <?php checked($this->bunny_fonts_enabled); ?>>
                            <span class="slider"></span>
                        </label>
                    </div>
                    
                    <div class="bunnycdn-save-row" style="margin-top: 24px;">
                        <button type="submit" class="button-primary">Save font settings</button>
                    </div>
                </form>
            </div>

            <!-- Activity Log -->
            <div class="bunnycdn-card">
                <div class="bunnycdn-log-header">
                    <h3>Recent activity</h3>
                    <button type="button" id="bunnycdn-clear-log">Clear log</button>
                </div>
                <div class="bunnycdn-log" id="bunnycdn-log">
                    <?php
                    $log = get_option('bunnycdn_purge_log', []);
                    if (empty($log)) {
                        echo '<div class="bunnycdn-log-empty">No activity yet</div>';
                    } else {
                        foreach (array_slice($log, 0, 10) as $entry) {
                            $time = isset($entry['time']) ? $this->time_ago(strtotime($entry['time'])) : '';
                            $action = isset($entry['action']) ? esc_html($entry['action']) : '';
                            $user = isset($entry['user']) ? esc_html($entry['user']) : '';
                            $status = isset($entry['status']) ? $entry['status'] : 'success';
                            $dot_class = $status === 'error' ? 'error' : '';
                            
                            echo '<div class="bunnycdn-log-entry">';
                            echo '<div class="bunnycdn-log-dot ' . $dot_class . '"></div>';
                            echo '<span class="bunnycdn-log-message">' . $action . '</span>';
                            echo '<span class="bunnycdn-log-time">' . $time . '</span>';
                            if ($user) {
                                echo '<span class="bunnycdn-log-user">' . $user . '</span>';
                            }
                            echo '</div>';
                        }
                    }
                    ?>
                </div>
            </div>
        </div>
        <?php
    }

    /**
     * Get last purge info for display
     */
    private function get_last_purge() {
        $log = get_option('bunnycdn_purge_log', []);
        
        if (empty($log)) {
            return ['time' => null, 'type' => null];
        }
        
        $last = $log[0];
        $time = isset($last['time']) ? $this->time_ago(strtotime($last['time'])) : null;
        
        $type = 'Unknown';
        if (isset($last['action'])) {
            if (strpos($last['action'], 'Full cache') !== false) {
                $type = 'Full cache';
            } elseif (strpos($last['action'], 'URL purge') !== false || strpos($last['action'], 'Auto-purge') !== false) {
                $type = 'URL purge';
            }
        }
        
        return ['time' => $time, 'type' => $type];
    }

    /**
     * Convert timestamp to human readable time ago
     */
    private function time_ago($timestamp) {
        $diff = time() - $timestamp;
        
        if ($diff < 60) {
            return 'Just now';
        } elseif ($diff < 3600) {
            $mins = floor($diff / 60);
            return $mins . ' min' . ($mins > 1 ? 's' : '') . ' ago';
        } elseif ($diff < 86400) {
            $hours = floor($diff / 3600);
            return $hours . ' hour' . ($hours > 1 ? 's' : '') . ' ago';
        } elseif ($diff < 172800) {
            return 'Yesterday';
        } else {
            $days = floor($diff / 86400);
            return $days . ' days ago';
        }
    }

    /**
     * AJAX handler: Purge all cache
     */
    public function ajax_purge_all() {
        check_ajax_referer('bunnycdn_purge_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }

        $result = $this->purge_cache();

        if ($result['success']) {
            wp_send_json_success(['message' => 'Entire cache purged successfully.']);
        } else {
            wp_send_json_error(['message' => $result['message']]);
        }
    }

    /**
     * AJAX handler: Purge specific URL
     */
    public function ajax_purge_url() {
        check_ajax_referer('bunnycdn_purge_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }

        $url = isset($_POST['url']) ? esc_url_raw($_POST['url']) : '';

        if (empty($url)) {
            wp_send_json_error(['message' => 'No URL provided.']);
        }

        $result = $this->purge_url($url);

        if ($result['success']) {
            wp_send_json_success(['message' => "URL purged: {$url}"]);
        } else {
            wp_send_json_error(['message' => $result['message']]);
        }
    }

    /**
     * Purge entire pull zone cache
     */
    public function purge_cache() {
        if (empty($this->api_key) || empty($this->pull_zone_id)) {
            return [
                'success' => false,
                'message' => 'API key or Pull Zone ID not configured.',
            ];
        }

        $response = wp_remote_post(
            "https://api.bunny.net/pullzone/{$this->pull_zone_id}/purgeCache",
            [
                'headers' => [
                    'AccessKey'    => $this->api_key,
                    'Content-Type' => 'application/json',
                ],
                'body'    => '',
                'timeout' => 30,
            ]
        );

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => $response->get_error_message(),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code === 204 || $code === 200) {
            $this->log_purge('Full cache purge');
            return ['success' => true];
        }

        $body = wp_remote_retrieve_body($response);
        return [
            'success' => false,
            'message' => "API returned status {$code}: {$body}",
        ];
    }

    /**
     * Purge specific URL from cache
     */
    public function purge_url($url) {
        if (empty($this->api_key)) {
            return [
                'success' => false,
                'message' => 'API key not configured.',
            ];
        }

        $response = wp_remote_post(
            'https://api.bunny.net/purge',
            [
                'headers' => [
                    'AccessKey'    => $this->api_key,
                    'Content-Type' => 'application/json',
                ],
                'body'    => json_encode(['url' => $url]),
                'timeout' => 30,
            ]
        );

        if (is_wp_error($response)) {
            return [
                'success' => false,
                'message' => $response->get_error_message(),
            ];
        }

        $code = wp_remote_retrieve_response_code($response);

        if ($code === 204 || $code === 200) {
            $this->log_purge("URL purge: {$url}");
            return ['success' => true];
        }

        $body = wp_remote_retrieve_body($response);
        return [
            'success' => false,
            'message' => "API returned status {$code}: {$body}",
        ];
    }

    /**
     * Auto-purge when post is updated
     */
    public function auto_purge_post($post_id, $post, $update) {
        // Only on actual updates, not revisions
        if (wp_is_post_revision($post_id)) {
            return;
        }

        // Check if auto-purge is enabled
        if (!get_option('bunnycdn_auto_purge', true)) {
            return;
        }

        // Only for published posts
        if ($post->post_status !== 'publish') {
            return;
        }

        // Get the permalink
        $permalink = get_permalink($post_id);

        if ($permalink) {
            $this->purge_url($permalink);

            // Also purge the home page and any archive pages
            $this->purge_url(home_url('/'));

            // Purge category archives if applicable
            $categories = get_the_category($post_id);
            foreach ($categories as $cat) {
                $this->purge_url(get_category_link($cat->term_id));
            }

            // Purge tag archives
            $tags = get_the_tags($post_id);
            if ($tags) {
                foreach ($tags as $tag) {
                    $this->purge_url(get_tag_link($tag->term_id));
                }
            }

            // Purge author archive
            $this->purge_url(get_author_posts_url($post->post_author));
        }
    }
    
    /**
     * Purge all cache (alias for WP Rocket integration)
     * Called by after_rocket_clean_domain and after_rocket_clean_files hooks
     */
    public function purge_all_cache() {
        $result = $this->purge_cache();
        if ($result['success']) {
            $this->log_purge('Full cache purge (WP Rocket sync)');
        }
        return $result;
    }
    
    /**
     * Purge post cache when WP Rocket clears a post
     * Called by after_rocket_clean_post hook
     */
    public function wp_rocket_purge_post($post, $purge_urls, $lang) {
        if (!is_object($post) || empty($post->ID)) {
            return;
        }
        
        $permalink = get_permalink($post->ID);
        if ($permalink) {
            $this->purge_url($permalink);
            $this->log_purge("Post cache purge: {$post->post_title} (WP Rocket sync)");
        }
        
        // Also purge any URLs that WP Rocket purged
        if (!empty($purge_urls) && is_array($purge_urls)) {
            foreach ($purge_urls as $url) {
                $this->purge_url($url);
            }
        }
    }

    /**
     * Log purge activity
     */
    private function log_purge($action, $status = 'success') {
        $log = get_option('bunnycdn_purge_log', []);
        
        array_unshift($log, [
            'time'   => current_time('mysql'),
            'action' => $action,
            'user'   => wp_get_current_user()->display_name,
            'status' => $status,
        ]);

        // Keep only last 50 entries
        $log = array_slice($log, 0, 50);

        update_option('bunnycdn_purge_log', $log);
    }

    /**
     * AJAX handler: Clear log
     */
    public function ajax_clear_log() {
        check_ajax_referer('bunnycdn_purge_nonce', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(['message' => 'Permission denied.']);
        }

        update_option('bunnycdn_purge_log', []);
        wp_send_json_success(['message' => 'Log cleared.']);
    }

    /**
     * Admin notices
     */
    public function admin_notices() {
        // Show transient notice from purge action
        $notice = get_transient('bunnycdn_notice_' . get_current_user_id());
        if ($notice) {
            delete_transient('bunnycdn_notice_' . get_current_user_id());
            $type = $notice['type'] === 'success' ? 'success' : 'error';
            ?>
            <div class="notice notice-<?php echo esc_attr($type); ?> is-dismissible">
                <p><strong>BunnyCDN:</strong> <?php echo esc_html($notice['message']); ?></p>
            </div>
            <?php
        }

        // Show setup warning on settings page
        $screen = get_current_screen();
        if ($screen && $screen->id === 'toplevel_page_bunnycdn-cache-purge') {
            if (empty($this->api_key) || empty($this->pull_zone_id)) {
                ?>
                <div class="notice notice-warning">
                    <p><strong>BunnyCDN Manager:</strong> Please configure your API key and Pull Zone to enable cache purging.</p>
                </div>
                <?php
            }
        }
    }

    /**
     * Frontend notices (shown in admin bar area)
     */
    public function frontend_notices() {
        if (!is_admin_bar_showing() || !current_user_can('manage_options')) {
            return;
        }

        $notice = get_transient('bunnycdn_notice_' . get_current_user_id());
        if (!$notice) {
            return;
        }

        delete_transient('bunnycdn_notice_' . get_current_user_id());
        $bg_color = $notice['type'] === 'success' ? '#46b450' : '#dc3232';
        ?>
        <style>
            #bunnycdn-frontend-notice {
                position: fixed;
                top: 40px;
                right: 20px;
                z-index: 999999;
                background: <?php echo esc_attr($bg_color); ?>;
                color: #fff;
                padding: 12px 20px;
                border-radius: 4px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
                font-size: 14px;
                max-width: 350px;
                animation: bunnycdn-fade-in 0.3s ease;
            }
            @keyframes bunnycdn-fade-in {
                from { opacity: 0; transform: translateY(-10px); }
                to { opacity: 1; transform: translateY(0); }
            }
        </style>
        <div id="bunnycdn-frontend-notice">
            <?php echo esc_html($notice['message']); ?>
        </div>
        <script>
            setTimeout(function() {
                var notice = document.getElementById('bunnycdn-frontend-notice');
                if (notice) {
                    notice.style.transition = 'opacity 0.5s ease';
                    notice.style.opacity = '0';
                    setTimeout(function() { notice.remove(); }, 500);
                }
            }, 4000);
        </script>
        <?php
    }

    /**
     * Add dashboard widget
     */
    public function add_dashboard_widget() {
        if (!current_user_can('manage_options')) {
            return;
        }

        wp_add_dashboard_widget(
            'bunnycdn_cache_widget',
            'BunnyCDN Cache',
            [$this, 'render_dashboard_widget']
        );
        
        // Add usage stats widget if connected
        if (!empty($this->api_key) && !empty($this->pull_zone_id)) {
            wp_add_dashboard_widget(
                'bunnycdn_usage_widget',
                'BunnyCDN Usage',
                [$this, 'render_usage_widget']
            );
        }
    }

    /**
     * Render usage stats dashboard widget
     */
    public function render_usage_widget() {
        // Clear transient on first load to test fresh data
        if (isset($_GET['bunnycdn_refresh_stats'])) {
            delete_transient('bunnycdn_chart_stats_' . $this->pull_zone_id . '_30');
        }
        
        $stats = $this->fetch_statistics_chart(30);
        
        if (!$stats['success']) {
            $message = isset($stats['message']) ? $stats['message'] : 'Unknown error';
            echo '<p style="color: #6B7280;">Unable to load usage statistics: ' . esc_html($message) . '</p>';
            return;
        }
        
        // Prepare chart data
        $chart_labels = [];
        $chart_bandwidth = [];
        
        foreach ($stats['bandwidth_chart'] as $date => $value) {
            $chart_labels[] = date('j M', strtotime($date));
            $chart_bandwidth[] = round($value / 1048576, 2); // Convert to MB
        }
        
        $chart_id = 'bunnycdn-usage-chart-' . uniqid();
        ?>
        <div class="bunnycdn-widget">
            <div class="bunnycdn-widget-header">
                <div class="bunnycdn-widget-icon">
                    <svg viewBox="0 0 39 43"><path d="M3.9,26.4C4.1,22 7.1,18.2 11.3,16.9C11.388,16.856 11.496,16.831 11.614,16.809C12.81,16.485 14.005,16.4 15.2,16.4C17,16.5 18.8,17.1 20.4,18C22.035,18.916 23.072,19.104 24.069,18.705C24.26,18.626 24.45,18.528 24.642,18.411C24.98,18.203 25.325,17.931 25.7,17.6C26.7,16.8 27.8,14.1 26.1,13.5C25.5,13.3 25,13.2 24.4,13.1C21.3,12.5 15.8,11.9 13.8,10.8C10.6,9 8.4,5.3 9.7,1.8L30.7,13.2L31.3,13.5C31.34,13.532 31.38,13.567 31.42,13.604L37.3,16.8C38,17.1 38.2,17.9 37.9,18.6C37.8,18.9 37.6,19.1 37.3,19.2C35.2,20.5 32.9,21.4 30.5,21.8L24.7,33.6C24.7,33.6 22.9,37.7 17.9,36.1C19.978,34.022 22.448,32.14 22.5,29C22.5,28.967 22.5,28.933 22.5,28.9C22.5,27.43 21.995,26.091 21.148,25.045C20.051,23.728 18.383,22.9 16.5,22.9C16.103,22.9 15.715,22.937 15.34,23.007C15.46,23.002 15.58,23 15.7,23C12.7,23.4 10.4,25.9 10.4,29C10.4,31.074 11.424,32.563 12.738,33.888C13.746,34.888 14.911,35.799 15.91,36.807C16.263,37.158 16.598,37.519 16.9,37.9C17.701,38.992 17.813,40.349 17.351,41.507C17.186,41.971 16.942,42.402 16.6,42.8C16,42.2 15.1,41.3 14.2,40.5C11.9,38.3 9.1,35.8 7.2,33.6C7.191,33.549 7.183,33.497 7.174,33.446C6.688,32.899 6.256,32.379 5.9,31.9C4.6,30.4 3.9,28.4 3.9,26.4ZM21,6.8C20,4.6 20.3,2 21.8,0L30.9,12.2L21,6.8ZM16.5,26.7C17.7,26.7 18.7,27.7 18.7,29C18.7,30.2 17.7,31.2 16.4,31.2C15.2,31.2 14.2,30.2 14.2,29C14.3,27.8 15.3,26.7 16.5,26.7ZM2.3,14.8C3.5,14.8 4.6,15.8 4.6,17.1L4.6,19.4L2.3,19.4C1.1,19.4 0,18.4 0,17.1C0,15.9 1,14.8 2.3,14.8Z"/></svg>
                </div>
                <span class="bunnycdn-widget-title">BunnyCDN</span>
                <span class="bunnycdn-widget-status">Last 30 days</span>
            </div>
            
            <div class="bunnycdn-widget-body">
                <div class="bunnycdn-widget-stats bunnycdn-widget-stats-3">
                    <div class="bunnycdn-widget-stat">
                        <p class="bunnycdn-widget-stat-label">Bandwidth</p>
                        <p class="bunnycdn-widget-stat-value"><?php echo esc_html($stats['bandwidth_formatted']); ?></p>
                    </div>
                    <div class="bunnycdn-widget-stat">
                        <p class="bunnycdn-widget-stat-label">Requests</p>
                        <p class="bunnycdn-widget-stat-value"><?php echo esc_html($stats['requests_formatted']); ?></p>
                    </div>
                    <div class="bunnycdn-widget-stat">
                        <p class="bunnycdn-widget-stat-label">Cache hit rate</p>
                        <p class="bunnycdn-widget-stat-value <?php echo $stats['cache_hit_rate'] >= 80 ? 'success' : ''; ?>"><?php echo esc_html($stats['cache_hit_rate']); ?>%</p>
                    </div>
                </div>
                
                <div class="bunnycdn-widget-chart">
                    <canvas id="<?php echo esc_attr($chart_id); ?>" height="160"></canvas>
                </div>
            </div>
        </div>
        
        <script>
        (function() {
            function initChart() {
                if (typeof Chart === 'undefined') {
                    var script = document.createElement('script');
                    script.src = '<?php echo esc_url(plugin_dir_url(__FILE__) . "assets/js/chart.min.js"); ?>';
                    script.onload = function() {
                        renderChart();
                    };
                    document.head.appendChild(script);
                } else {
                    renderChart();
                }
            }
            
            function renderChart() {
                var ctx = document.getElementById('<?php echo esc_js($chart_id); ?>');
                if (!ctx) return;
                
                new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: <?php echo json_encode($chart_labels); ?>,
                        datasets: [{
                            label: 'Bandwidth (MB)',
                            data: <?php echo json_encode($chart_bandwidth); ?>,
                            borderColor: '#FF9500',
                            backgroundColor: 'rgba(255, 149, 0, 0.1)',
                            borderWidth: 2,
                            fill: true,
                            tension: 0.3,
                            pointRadius: 0,
                            pointHoverRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {
                            intersect: false,
                            mode: 'index'
                        },
                        plugins: {
                            legend: {
                                display: false
                            },
                            tooltip: {
                                backgroundColor: '#1d2327',
                                titleColor: '#fff',
                                bodyColor: '#fff',
                                padding: 10,
                                displayColors: false,
                                callbacks: {
                                    label: function(context) {
                                        return context.parsed.y.toFixed(2) + ' MB';
                                    }
                                }
                            }
                        },
                        scales: {
                            x: {
                                display: true,
                                grid: {
                                    display: false
                                },
                                ticks: {
                                    maxTicksLimit: 6,
                                    font: {
                                        size: 10
                                    },
                                    color: '#9CA3AF'
                                }
                            },
                            y: {
                                display: true,
                                grid: {
                                    color: '#f3f4f6'
                                },
                                ticks: {
                                    font: {
                                        size: 10
                                    },
                                    color: '#9CA3AF',
                                    callback: function(value) {
                                        if (value >= 1000) {
                                            return (value / 1000).toFixed(1) + ' GB';
                                        }
                                        return value + ' MB';
                                    }
                                }
                            }
                        }
                    }
                });
            }
            
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', initChart);
            } else {
                initChart();
            }
        })();
        </script>
        <?php
    }

    /**
     * Render dashboard widget
     */
    public function render_dashboard_widget() {
        $is_connected = !empty($this->api_key) && !empty($this->pull_zone_id);
        $pullzone_name = '';
        
        if ($is_connected) {
            $pullzones = $this->fetch_pullzones();
            if ($pullzones['success'] && !empty($pullzones['data'])) {
                foreach ($pullzones['data'] as $zone) {
                    if ($zone['id'] == $this->pull_zone_id) {
                        $pullzone_name = $zone['name'];
                        break;
                    }
                }
            }
        }
        
        $last_purge = $this->get_last_purge();
        $purge_all_url = wp_nonce_url(
            add_query_arg(['bunnycdn_action' => 'purge_all'], admin_url()),
            'bunnycdn_purge_all'
        );
        $purge_home_url = wp_nonce_url(
            add_query_arg([
                'bunnycdn_action' => 'purge_url',
                'purge_url' => urlencode(home_url('/')),
            ], admin_url()),
            'bunnycdn_purge_url'
        );
        $settings_url = admin_url('admin.php?page=bunnycdn-cache-purge');
        ?>
        <div class="bunnycdn-widget">
            <div class="bunnycdn-widget-header">
                <div class="bunnycdn-widget-icon">
                    <svg viewBox="0 0 39 43"><path d="M3.9,26.4C4.1,22 7.1,18.2 11.3,16.9C11.388,16.856 11.496,16.831 11.614,16.809C12.81,16.485 14.005,16.4 15.2,16.4C17,16.5 18.8,17.1 20.4,18C22.035,18.916 23.072,19.104 24.069,18.705C24.26,18.626 24.45,18.528 24.642,18.411C24.98,18.203 25.325,17.931 25.7,17.6C26.7,16.8 27.8,14.1 26.1,13.5C25.5,13.3 25,13.2 24.4,13.1C21.3,12.5 15.8,11.9 13.8,10.8C10.6,9 8.4,5.3 9.7,1.8L30.7,13.2L31.3,13.5C31.34,13.532 31.38,13.567 31.42,13.604L37.3,16.8C38,17.1 38.2,17.9 37.9,18.6C37.8,18.9 37.6,19.1 37.3,19.2C35.2,20.5 32.9,21.4 30.5,21.8L24.7,33.6C24.7,33.6 22.9,37.7 17.9,36.1C19.978,34.022 22.448,32.14 22.5,29C22.5,28.967 22.5,28.933 22.5,28.9C22.5,27.43 21.995,26.091 21.148,25.045C20.051,23.728 18.383,22.9 16.5,22.9C16.103,22.9 15.715,22.937 15.34,23.007C15.46,23.002 15.58,23 15.7,23C12.7,23.4 10.4,25.9 10.4,29C10.4,31.074 11.424,32.563 12.738,33.888C13.746,34.888 14.911,35.799 15.91,36.807C16.263,37.158 16.598,37.519 16.9,37.9C17.701,38.992 17.813,40.349 17.351,41.507C17.186,41.971 16.942,42.402 16.6,42.8C16,42.2 15.1,41.3 14.2,40.5C11.9,38.3 9.1,35.8 7.2,33.6C7.191,33.549 7.183,33.497 7.174,33.446C6.688,32.899 6.256,32.379 5.9,31.9C4.6,30.4 3.9,28.4 3.9,26.4ZM21,6.8C20,4.6 20.3,2 21.8,0L30.9,12.2L21,6.8ZM16.5,26.7C17.7,26.7 18.7,27.7 18.7,29C18.7,30.2 17.7,31.2 16.4,31.2C15.2,31.2 14.2,30.2 14.2,29C14.3,27.8 15.3,26.7 16.5,26.7ZM2.3,14.8C3.5,14.8 4.6,15.8 4.6,17.1L4.6,19.4L2.3,19.4C1.1,19.4 0,18.4 0,17.1C0,15.9 1,14.8 2.3,14.8Z"/></svg>
                </div>
                <span class="bunnycdn-widget-title">BunnyCDN</span>
                <span class="bunnycdn-widget-status <?php echo $is_connected ? '' : 'disconnected'; ?>">
                    <?php echo $is_connected ? 'Connected' : 'Setup'; ?>
                </span>
            </div>
            
            <div class="bunnycdn-widget-body">
                <?php if ($is_connected) : ?>
                    <div class="bunnycdn-widget-stats">
                        <div class="bunnycdn-widget-stat">
                            <p class="bunnycdn-widget-stat-label">Pull zone</p>
                            <p class="bunnycdn-widget-stat-value"><?php echo esc_html($pullzone_name ?: 'Unknown'); ?></p>
                        </div>
                        <div class="bunnycdn-widget-stat">
                            <p class="bunnycdn-widget-stat-label">Last purge</p>
                            <p class="bunnycdn-widget-stat-value"><?php echo esc_html($last_purge['time'] ?: 'Never'); ?></p>
                        </div>
                    </div>
                    
                    <div class="bunnycdn-widget-actions">
                        <a href="<?php echo esc_url($purge_all_url); ?>" class="bunnycdn-widget-btn-primary">
                            <svg viewBox="0 0 24 24"><path d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/></svg>
                            Purge entire cache
                        </a>
                        <div class="bunnycdn-widget-btn-row">
                            <a href="<?php echo esc_url($purge_home_url); ?>" class="bunnycdn-widget-btn-secondary">Purge homepage</a>
                            <a href="<?php echo esc_url($settings_url); ?>" class="bunnycdn-widget-btn-secondary">Settings</a>
                        </div>
                    </div>
                    
                    <?php
                    $log = get_option('bunnycdn_purge_log', []);
                    if (!empty($log)) :
                    ?>
                    <div class="bunnycdn-widget-log">
                        <p class="bunnycdn-widget-log-title">Recent activity</p>
                        <div class="bunnycdn-widget-log-entries">
                            <?php foreach (array_slice($log, 0, 2) as $entry) :
                                $time = isset($entry['time']) ? $this->time_ago(strtotime($entry['time'])) : '';
                                $action = isset($entry['action']) ? esc_html($entry['action']) : '';
                                $status = isset($entry['status']) ? $entry['status'] : 'success';
                                
                                // Shorten action text
                                $action = str_replace(['Full cache purge', 'URL purge: ', 'Auto-purge: '], ['Full cache', '', ''], $action);
                                if (strlen($action) > 30) {
                                    $action = substr($action, 0, 27) . '...';
                                }
                            ?>
                            <div class="bunnycdn-widget-log-entry">
                                <div class="dot <?php echo $status === 'error' ? 'error' : ''; ?>"></div>
                                <span class="message"><?php echo $action; ?></span>
                                <span class="time"><?php echo $time; ?></span>
                            </div>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    <?php endif; ?>
                    
                <?php else : ?>
                    <div class="bunnycdn-widget-setup">
                        <p>Configure your API key to enable cache purging.</p>
                        <a href="<?php echo esc_url($settings_url); ?>" class="bunnycdn-widget-btn-primary">
                            Setup BunnyCDN
                        </a>
                    </div>
                <?php endif; ?>
            </div>
        </div>
        <?php
    }
}

// Initialise
new BunnyCDN_Cache_Purge();
