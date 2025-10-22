<?php
/**
 * Plugin Name: BunnyCDN Cache Purge Tool
 * Description: Adds a WordPress toolbar dropdown to purge either the entire BunnyCDN cache or just the current page. A valid BunnyCDN account and API key are required.
 * Version: 2.5.1
 * Requires at least: 6.5
 * Tested up to: 6.8.3
 * Author: Michael Overton
 * Author URI: https://overton.cloud
 */

if (!defined('ABSPATH')) { exit; }

final class BunnyCDN_Cache_Purge_Tool {
    private $option_key = 'bunnycdn_settings';
    private $log_dir;
    private $log_file;

    public function __construct() {
        $uploads = wp_upload_dir();
        $this->log_dir  = trailingslashit($uploads['basedir']) . 'bunnycdn-logs';
        $this->log_file = trailingslashit($this->log_dir) . 'bunnycdn.log';

        add_action('admin_bar_menu', array($this, 'add_toolbar_menu'), 200);
        add_action('admin_post_bunnycdn_purge', array($this, 'handle_purge_request'));
        add_action('admin_post_bunnycdn_purge_url', array($this, 'handle_purge_url_request'));

        add_action('admin_menu', array($this, 'add_settings_page'));
        add_action('admin_init', array($this, 'register_settings'));
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array($this, 'add_plugin_settings_link'));

        add_action('wp_ajax_bunnycdn_fetch_zones', array($this, 'fetch_zones'));
        add_action('wp_ajax_bunnycdn_download_log', array($this, 'download_log'));

        add_action('admin_notices', array($this, 'maybe_show_notice'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_js'));
    }

    /* Utilities */

    private function ensure_log_dir() {
        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
            @chmod($this->log_dir, 0750);
            @file_put_contents(trailingslashit($this->log_dir) . 'index.php', "<?php // Silence is golden.");
            @file_put_contents(trailingslashit($this->log_dir) . '.htaccess', "Require all denied");
        }
    }

    private function rotate_log_if_needed() {
        $this->ensure_log_dir();
        if (file_exists($this->log_file) && filesize($this->log_file) > 1048576) {
            @rename($this->log_file, $this->log_file . '.1');
        }
    }

    private function redact_key($key) {
        $key = (string)$key;
        $len = strlen($key);
        if ($len <= 8) { return str_repeat('*', $len); }
        return substr($key, 0, 4) . str_repeat('*', $len - 8) . substr($key, -4);
    }

    private function write_log($line) {
        $this->rotate_log_if_needed();
        $entry = '[' . current_time('mysql') . '] ' . $line . "\n";
        file_put_contents($this->log_file, $entry, FILE_APPEND | LOCK_EX);
        @chmod($this->log_file, 0640);
    }

    private function encrypt_api_key($plain_text) {
        if (empty($plain_text)) { return ''; }
        if (!defined('SECURE_AUTH_SALT') || !defined('AUTH_SALT')) { return $plain_text; }
        $key = hash('sha256', SECURE_AUTH_SALT, true);
        $iv  = substr(hash('sha256', AUTH_SALT), 0, 16);
        return base64_encode(openssl_encrypt($plain_text, 'AES-256-CBC', $key, 0, $iv));
    }

    private function decrypt_api_key($encrypted_text) {
        if (empty($encrypted_text)) { return ''; }
        if (!defined('SECURE_AUTH_SALT') || !defined('AUTH_SALT')) { return $encrypted_text; }
        $key = hash('sha256', SECURE_AUTH_SALT, true);
        $iv  = substr(hash('sha256', AUTH_SALT), 0, 16);
        return openssl_decrypt(base64_decode($encrypted_text), 'AES-256-CBC', $key, 0, $iv);
    }

    private function get_full_purge_url() {
        $nonce = wp_create_nonce('bunnycdn_purge_nonce');
        return admin_url('admin-post.php?action=bunnycdn_purge&_wpnonce=' . $nonce);
    }

    private function get_url_purge_url($target) {
        $url = admin_url('admin-post.php?action=bunnycdn_purge_url&target=' . rawurlencode($target));
        return wp_nonce_url($url, 'bunnycdn_purge_url_nonce');
    }

    private function is_debug_enabled() {
        $settings = get_option($this->option_key);
        return !empty($settings['debug_logging']);
    }

    /* Toolbar */

    public function add_toolbar_menu($wp_admin_bar) {
        if (!current_user_can('manage_options')) { return; }

        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = isset($settings['zone_id']) ? $settings['zone_id'] : '';
        if (empty($api_key) || empty($zone_id)) { return; }

        $wp_admin_bar->add_node(array(
            'id'    => 'bunnycdn-cache',
            'title' => 'Purge CDN Cache',
            'href'  => false,
        ));

        $wp_admin_bar->add_node(array(
            'id'     => 'bunnycdn-cache-full',
            'parent' => 'bunnycdn-cache',
            'title'  => 'Purge Entire CDN',
            'href'   => esc_url($this->get_full_purge_url()),
        ));

        $scheme = is_ssl() ? 'https://' : 'http://';
        $host   = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
        $uri    = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/';
        $current_url = $scheme . $host . $uri;

        $wp_admin_bar->add_node(array(
            'id'     => 'bunnycdn-cache-url',
            'parent' => 'bunnycdn-cache',
            'title'  => 'Purge This URL',
            'href'   => esc_url($this->get_url_purge_url($current_url)),
        ));
    }

    /* Handlers */

    public function handle_purge_request() {
        if (!current_user_can('manage_options')) { wp_die('Unauthorised', 403); }
        check_admin_referer('bunnycdn_purge_nonce');

        $ok = $this->purge_cache_internal();
        $dest = add_query_arg('bunnycdn_purged', $ok ? '1' : '0', wp_get_referer() ? wp_get_referer() : admin_url('index.php'));
        wp_safe_redirect($dest);
        exit;
    }

    public function handle_purge_url_request() {
        if (!current_user_can('manage_options')) { wp_die('Unauthorised', 403); }
        check_admin_referer('bunnycdn_purge_url_nonce');

        $target = esc_url_raw(isset($_GET['target']) ? $_GET['target'] : '');
        if (!$target) {
            $this->write_log('URL_PURGE FAIL Code=- Message=Missing target');
            wp_safe_redirect(add_query_arg('bunnycdn_purged', '0', wp_get_referer() ? wp_get_referer() : admin_url('index.php')));
            exit;
        }

        $ok = $this->purge_url_internal($target);
        $dest = add_query_arg('bunnycdn_purged', $ok ? '1' : '0', wp_get_referer() ? wp_get_referer() : admin_url('index.php'));
        wp_safe_redirect($dest);
        exit;
    }

    private function purge_cache_internal() {
        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = isset($settings['zone_id']) ? $settings['zone_id'] : '';
        $user     = wp_get_current_user();
        $username = $user ? $user->user_login : 'unknown';

        if (empty($api_key) || empty($zone_id)) {
            $this->write_log('FULL_PURGE FAIL Code=- User=' . $username . ' Message=Missing API or Zone ID');
            return false;
        }

        $endpoint = 'https://api.bunny.net/pullzone/' . rawurlencode($zone_id) . '/purgeCache';
        $response = wp_remote_request($endpoint, array(
            'headers' => array('AccessKey' => $api_key, 'Accept' => 'application/json'),
            'method'  => 'POST',
            'timeout' => 20
        ));

        if (is_wp_error($response)) {
            $this->write_log('FULL_PURGE ERROR Code=- User=' . $username . ' Message=' . $response->get_error_message());
            return false;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($this->is_debug_enabled()) {
            $this->write_log('FULL_PURGE DEBUG Key=' . $this->redact_key($api_key) . ' Code=' . $code . ' Body=' . ($body ? $body : 'No body'));
        }

        if (in_array($code, array(200, 204), true)) {
            $this->write_log('FULL_PURGE SUCCESS Code=' . $code . ' User=' . $username);
            return true;
        }

        $decoded = json_decode($body, true);
        $msg = isset($decoded['Message']) ? $decoded['Message'] : 'Unexpected response';
        $this->write_log('FULL_PURGE FAIL Code=' . $code . ' User=' . $username . ' Message=' . $msg);
        return false;
    }

    private function purge_url_internal($target_url) {
        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = isset($settings['zone_id']) ? $settings['zone_id'] : '';
        $user     = wp_get_current_user();
        $username = $user ? $user->user_login : 'unknown';

        if (empty($api_key) || empty($zone_id)) {
            $this->write_log('URL_PURGE FAIL Code=- User=' . $username . ' Target="' . $target_url . '" Message=Missing API or Zone ID');
            return false;
        }

        $endpoint = 'https://api.bunny.net/pullzone/' . rawurlencode($zone_id) . '/purgeCache?url=' . rawurlencode($target_url);
        $response = wp_remote_request($endpoint, array(
            'headers' => array('AccessKey' => $api_key, 'Accept' => 'application/json'),
            'method'  => 'POST',
            'timeout' => 20
        ));

        if (is_wp_error($response)) {
            $this->write_log('URL_PURGE ERROR Code=- User=' . $username . ' Target="' . $target_url . '" Message=' . $response->get_error_message());
            return false;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($this->is_debug_enabled()) {
            $this->write_log('URL_PURGE DEBUG Key=' . $this->redact_key($api_key) . ' Code=' . $code . ' Target="' . $target_url . '" Body=' . ($body ? $body : 'No body'));
        }

        if (in_array($code, array(200, 204), true)) {
            $this->write_log('URL_PURGE SUCCESS Code=' . $code . ' User=' . $username . ' Target="' . $target_url . '"');
            return true;
        }

        $decoded = json_decode($body, true);
        $msg = isset($decoded['Message']) ? $decoded['Message'] : 'Unexpected response';
        $this->write_log('URL_PURGE FAIL Code=' . $code . ' User=' . $username . ' Target="' . $target_url . '" Message=' . $msg);
        return false;
    }

    /* Settings page */

    public function add_settings_page() {
        add_options_page('CDN Cache Settings', 'CDN Cache', 'manage_options', 'bunnycdn-settings', array($this, 'render_settings_page'));
    }

    public function register_settings() {
        register_setting('bunnycdn_settings_group', $this->option_key, function($input){
            $output = array();
            $output['zone_id'] = isset($input['zone_id']) ? sanitize_text_field($input['zone_id']) : '';
            $output['debug_logging'] = !empty($input['debug_logging']) ? 1 : 0;
            if (!empty($input['api_key'])) {
                $output['api_key'] = $this->encrypt_api_key($input['api_key']);
            } else {
                $existing = get_option($this->option_key);
                if (!empty($existing['api_key'])) { $output['api_key'] = $existing['api_key']; }
            }
            return $output;
        });
    }

    public function enqueue_admin_js($hook) {
        if ($hook !== 'settings_page_bunnycdn-settings') { return; }

        wp_enqueue_script(
            'bunnycdn-admin',
            plugins_url('assets/bunnycdn-admin.js', __FILE__),
            array('jquery'),
            '2.5.1',
            true
        );
        wp_localize_script('bunnycdn-admin', 'bunnycdnAjax', array(
            'ajaxurl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('bunnycdn_fetch_zones_nonce'),
            'action'  => 'bunnycdn_fetch_zones'
        ));
    }

    public function add_plugin_settings_link($links) {
        $url = admin_url('options-general.php?page=bunnycdn-settings');
        $settings_link = '<a href="' . esc_url($url) . '">Settings</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) { return; }

        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = isset($settings['zone_id']) ? $settings['zone_id'] : '';
        $debug_on = !empty($settings['debug_logging']);

        $this->ensure_log_dir();
        $recent = '';
        if (file_exists($this->log_file)) {
            $recent = esc_textarea($this->tail_lines($this->log_file, 100));
        }
        $download_url = wp_nonce_url(admin_url('admin-ajax.php?action=bunnycdn_download_log'), 'bunnycdn_download_log');
        ?>
        <div class="wrap">
            <h1>CDN Cache Settings</h1>
            <p><em>Note: You will need an active <a href="https://bunny.net/" target="_blank" rel="noopener">BunnyCDN account</a> and API key to use this tool.</em></p>

            <form method="post" action="options.php">
                <?php settings_fields('bunnycdn_settings_group'); ?>
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">API Key</th>
                        <td>
                            <input type="text" name="<?php echo esc_attr($this->option_key); ?>[api_key]" value="<?php echo esc_attr($api_key); ?>" class="regular-text" />
                            <button type="button" class="button" id="bunnycdn-fetch-zones">Fetch Zones</button>
                            <p class="description">Paste your Account API Key from BunnyCDN. It is stored encrypted.</p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Pull Zone</th>
                        <td>
                            <select name="<?php echo esc_attr($this->option_key); ?>[zone_id]" id="bunnycdn-zone-select">
                                <option value="">-- Select Zone --</option>
                                <?php if (!empty($zone_id)) : ?>
                                    <option value="<?php echo esc_attr($zone_id); ?>" selected>Zone ID: <?php echo esc_html($zone_id); ?></option>
                                <?php endif; ?>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Debug logging</th>
                        <td>
                            <label>
                                <input type="checkbox" name="<?php echo esc_attr($this->option_key); ?>[debug_logging]" value="1" <?php checked($debug_on, true); ?> />
                                Enable detailed debug logging (includes API responses).
                            </label>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <hr />
            <h2>Recent Logs</h2>
            <textarea readonly rows="14" style="width:100%; font-family:monospace;"><?php echo $recent ? $recent : 'No logs yet.'; ?></textarea>
            <p><a href="<?php echo esc_url($download_url); ?>" class="button">Download Full Log</a></p>
        </div>
        <?php
    }

    /* AJAX */

    public function fetch_zones() {
        check_ajax_referer('bunnycdn_fetch_zones_nonce');
        if (!current_user_can('manage_options')) { wp_send_json(array('success' => false, 'message' => 'Unauthorised.')); }

        $api_key = sanitize_text_field(isset($_POST['api_key']) ? $_POST['api_key'] : '');
        if (!$api_key) {
            $this->write_log('FETCH_ZONES FAIL Message=Missing API key');
            wp_send_json(array('success' => false, 'message' => 'Missing API key.'));
        }

        $response = wp_remote_get('https://api.bunny.net/pullzone', array(
            'headers' => array('AccessKey' => $api_key, 'Accept' => 'application/json'),
            'timeout' => 20
        ));

        if (is_wp_error($response)) {
            $this->write_log('FETCH_ZONES ERROR Code=- Message=' . $response->get_error_message());
            wp_send_json(array('success' => false, 'message' => $response->get_error_message()));
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);

        if ($this->is_debug_enabled()) {
            $this->write_log('FETCH_ZONES DEBUG Key=' . $this->redact_key($api_key) . ' Code=' . $code . ' Body=' . ($body ? $body : 'No body'));
        } else {
            $this->write_log('FETCH_ZONES RESULT Code=' . $code);
        }

        if ($code === 200) {
            $zones = json_decode($body);
            wp_send_json(array('success' => true, 'zones' => $zones));
        } else {
            $decoded = json_decode($body, true);
            $msg = isset($decoded['Message']) ? $decoded['Message'] : 'Unexpected response';
            wp_send_json(array('success' => false, 'message' => 'Bunny returned ' . $code . ' - ' . $msg));
        }
    }

    public function download_log() {
        check_admin_referer('bunnycdn_download_log');
        if (!current_user_can('manage_options')) { wp_die('Unauthorised', 403); }
        $this->ensure_log_dir();
        if (!file_exists($this->log_file)) {
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="bunnycdn.log"');
            echo 'No logs yet.';
            exit;
        }
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="bunnycdn.log"');
        header('Content-Length: ' . filesize($this->log_file));
        readfile($this->log_file);
        exit;
    }

    /* Notices */

    public function maybe_show_notice() {
        if (!isset($_GET['bunnycdn_purged'])) { return; }
        $success = $_GET['bunnycdn_purged'] === '1';
        $class   = $success ? 'notice-success' : 'notice-error';
        $message = $success ? '<strong>BunnyCDN:</strong> CDN cache successfully purged.' : '<strong>BunnyCDN:</strong> Failed to purge CDN cache.';
        echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . wp_kses_post($message) . '</p></div>';
    }

    /* Helpers */

    private function tail_lines($filepath, $lines = 100) {
        if (!file_exists($filepath)) { return ''; }
        $f = @fopen($filepath, 'rb');
        if (!$f) { return ''; }
        $buffer = '';
        $chunk = 4096;
        $lineCount = 0;
        fseek($f, 0, SEEK_END);
        $pos = ftell($f);
        while ($pos > 0 && $lineCount <= $lines) {
            $read = ($pos - $chunk) >= 0 ? $chunk : $pos;
            $pos -= $read;
            fseek($f, $pos);
            $buffer = fread($f, $read) . $buffer;
            $lineCount = substr_count($buffer, "\n");
        }
        fclose($f);
        $parts = explode("\n", $buffer);
        return implode("\n", array_slice($parts, -$lines));
    }
}

/* Instantiate safely after plugins_loaded */
add_action('plugins_loaded', function(){
    if (class_exists('BunnyCDN_Cache_Purge_Tool')) {
        $GLOBALS['bunnycdn_cache_purge_tool'] = new BunnyCDN_Cache_Purge_Tool();
    }
});
