<?php
/**
 * Plugin Name: BunnyCDN Cache Purge Button
 * Description: Adds a WordPress toolbar dropdown to purge either the entire BunnyCDN cache or just the current page. Includes secure API key storage, logging, and admin notices.
 * Version: 2.2
 * Author: Michael Overton
 * Author URI: https://overton.cloud
 */

if (!defined('ABSPATH')) exit;

class BunnyCDNPurgePlugin {

    private $option_key = 'bunnycdn_settings';
    private $log_dir;
    private $log_file;

    public function __construct() {
        $this->log_dir  = WP_CONTENT_DIR . '/bunnycdn-logs';
        $this->log_file = $this->log_dir . '/bunnycdn-purge.log';

        // Toolbar + actions
        add_action('admin_bar_menu', [$this, 'add_toolbar_button'], 999);
        add_action('admin_post_bunnycdn_purge', [$this, 'handle_purge_request']);
        add_action('admin_post_bunnycdn_purge_url', [$this, 'handle_purge_url_request']);

        // Settings UI + helpers
        add_action('admin_menu', [$this, 'add_settings_page']);
        add_action('admin_init', [$this, 'register_settings']);
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'add_plugin_settings_link']);

        // Logs + notice
        add_action('wp_ajax_bunnycdn_fetch_zones', [$this, 'fetch_zones']);
        add_action('wp_ajax_bunnycdn_download_log', [$this, 'download_log']);
        add_action('admin_notices', [$this, 'maybe_show_notice']);
    }

    public function add_plugin_settings_link($links) {
        $url = admin_url('options-general.php?page=bunnycdn-settings');
        $settings_link = '<a href="' . esc_url($url) . '">Settings</a>';
        array_unshift($links, $settings_link);
        return $links;
    }

    private function encrypt_api_key($plain_text) {
        if (empty($plain_text)) return '';
        if (!defined('SECURE_AUTH_SALT') || !defined('AUTH_SALT')) return $plain_text;
        $key = hash('sha256', SECURE_AUTH_SALT, true);
        $iv  = substr(hash('sha256', AUTH_SALT), 0, 16);
        return base64_encode(openssl_encrypt($plain_text, 'AES-256-CBC', $key, 0, $iv));
    }

    private function decrypt_api_key($encrypted_text) {
        if (empty($encrypted_text)) return '';
        if (!defined('SECURE_AUTH_SALT') || !defined('AUTH_SALT')) return $encrypted_text;
        $key = hash('sha256', SECURE_AUTH_SALT, true);
        $iv  = substr(hash('sha256', AUTH_SALT), 0, 16);
        return openssl_decrypt(base64_decode($encrypted_text), 'AES-256-CBC', $key, 0, $iv);
    }

    private function get_purge_url() {
        $nonce = wp_create_nonce('bunnycdn_purge_nonce');
        return admin_url('admin-post.php?action=bunnycdn_purge&_wpnonce=' . $nonce);
    }

    public function add_toolbar_button($wp_admin_bar) {
        if (!current_user_can('manage_options')) return;

        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = $settings['zone_id'] ?? '';
        if (empty($api_key) || empty($zone_id)) return;

        // Main dropdown
        $wp_admin_bar->add_node([
            'id'    => 'bunnycdn-purge-cache',
            'title' => 'Purge CDN Cache',
            'href'  => false,
            'meta'  => ['class' => 'ab-top-secondary']
        ]);

        // Option 1: full purge
        $wp_admin_bar->add_node([
            'id'     => 'bunnycdn-purge-cache-full',
            'parent' => 'bunnycdn-purge-cache',
            'title'  => 'Purge Entire CDN',
            'href'   => esc_url($this->get_purge_url()),
        ]);

        // Option 2: current URL purge
        $current_url = (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
        $nonce_url = wp_nonce_url(
            admin_url('admin-post.php?action=bunnycdn_purge_url&target=' . rawurlencode($current_url)),
            'bunnycdn_purge_url_nonce'
        );

        $wp_admin_bar->add_node([
            'id'     => 'bunnycdn-purge-cache-this',
            'parent' => 'bunnycdn-purge-cache',
            'title'  => 'Purge This URL',
            'href'   => esc_url($nonce_url),
        ]);
    }

    public function handle_purge_request() {
        if (!current_user_can('manage_options')) wp_die('Unauthorised', 403);
        check_admin_referer('bunnycdn_purge_nonce');

        $success = $this->purge_cache_internal();
        $target = add_query_arg('bunnycdn_purged', $success ? '1' : '0', wp_get_referer() ?: admin_url('index.php'));
        wp_safe_redirect($target);
        exit;
    }

    public function handle_purge_url_request() {
        if (!current_user_can('manage_options')) wp_die('Unauthorised', 403);
        check_admin_referer('bunnycdn_purge_url_nonce');

        $target_url = esc_url_raw($_GET['target'] ?? '');
        if (empty($target_url)) {
            wp_safe_redirect(add_query_arg('bunnycdn_purged', '0', wp_get_referer() ?: admin_url()));
            exit;
        }

        $success = $this->purge_url_internal($target_url);
        $redirect = add_query_arg('bunnycdn_purged', $success ? '1' : '0', wp_get_referer() ?: admin_url());
        wp_safe_redirect($redirect);
        exit;
    }

    private function purge_cache_internal() {
        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = $settings['zone_id'] ?? '';
        if (empty($api_key) || empty($zone_id)) return false;

        $url = "https://api.bunny.net/pullzone/{$zone_id}/purgeCache";
        $response = wp_remote_request($url, [
            'headers' => ['AccessKey' => $api_key, 'Accept' => 'application/json'],
            'method'  => 'POST',
            'timeout' => 20
        ]);

        $user = wp_get_current_user();
        $username = $user ? $user->user_login : 'unknown';
        $log_entry = ['time' => current_time('mysql'), 'user' => $username, 'type' => 'full', 'tag' => '-'];

        if (is_wp_error($response)) {
            $log_entry['status'] = 'error';
            $log_entry['details'] = $response->get_error_message();
            $this->write_log($log_entry);
            return false;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $log_entry['status_code'] = $code;
        $log_entry['api_response'] = $body ?: 'No body returned.';

        if (in_array($code, [200, 204], true)) {
            $log_entry['status'] = 'success';
            $this->write_log($log_entry);
            return true;
        }

        $decoded = json_decode($body, true);
        $log_entry['status'] = 'failed';
        $log_entry['details'] = $decoded['Message'] ?? 'Unexpected response from CDN.';
        $this->write_log($log_entry);
        return false;
    }

    private function purge_url_internal($target_url) {
        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = $settings['zone_id'] ?? '';
        if (empty($api_key) || empty($zone_id)) return false;

        $endpoint = "https://api.bunny.net/pullzone/{$zone_id}/purgeCache?url=" . rawurlencode($target_url);
        $response = wp_remote_request($endpoint, [
            'headers' => ['AccessKey' => $api_key, 'Accept' => 'application/json'],
            'method'  => 'POST',
            'timeout' => 20
        ]);

        $user = wp_get_current_user();
        $username = $user ? $user->user_login : 'unknown';
        $log_entry = ['time' => current_time('mysql'), 'user' => $username, 'type' => 'url', 'tag' => $target_url];

        if (is_wp_error($response)) {
            $log_entry['status'] = 'error';
            $log_entry['details'] = $response->get_error_message();
            $this->write_log($log_entry);
            return false;
        }

        $code = wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $decoded = json_decode($body, true);
        $log_entry['status_code'] = $code;
        $log_entry['api_response'] = $body ?: 'No body returned.';

        if (in_array($code, [200, 204], true)) {
            $log_entry['status'] = 'success';
            $this->write_log($log_entry);
            return true;
        }

        $log_entry['status'] = 'failed';
        $log_entry['details'] = $decoded['Message'] ?? 'Unexpected response from CDN.';
        $this->write_log($log_entry);
        return false;
    }

    public function maybe_show_notice() {
        if (!isset($_GET['bunnycdn_purged'])) return;
        $success = $_GET['bunnycdn_purged'] === '1';
        $class = $success ? 'notice-success' : 'notice-error';
        $message = $success
            ? '<strong>BunnyCDN:</strong> CDN cache successfully purged.'
            : '<strong>BunnyCDN:</strong> Failed to purge CDN cache.';
        echo '<div class="notice ' . esc_attr($class) . ' is-dismissible"><p>' . wp_kses_post($message) . '</p></div>';
    }

    private function ensure_log_dir() {
        if (!file_exists($this->log_dir)) {
            wp_mkdir_p($this->log_dir);
            @chmod($this->log_dir, 0750);
            @file_put_contents($this->log_dir . '/index.php', "<?php // Silence is golden.");
            @file_put_contents($this->log_dir . '/.htaccess', "Require all denied");
        }
    }

    private function write_log($data) {
        $this->ensure_log_dir();
        $entry = '[' . $data['time'] . '] ' . strtoupper($data['status']) .
            ' User: ' . $data['user'] .
            ' | Type: ' . $data['type'] .
            ' | Tag: ' . ($data['tag'] ?? '-') .
            ' | Code: ' . ($data['status_code'] ?? '-') .
            ' | Details: ' . ($data['details'] ?? '') .
            ' | Response: ' . ($data['api_response'] ?? '') . PHP_EOL;
        file_put_contents($this->log_file, $entry, FILE_APPEND | LOCK_EX);
        @chmod($this->log_file, 0640);
    }

    private function tail_lines($filepath, $lines = 50) {
        if (!file_exists($filepath)) return '';
        $f = @fopen($filepath, "rb");
        if (!$f) return '';
        $buffer = '';
        $chunkSize = 4096;
        $lineCount = 0;
        fseek($f, 0, SEEK_END);
        $pos = ftell($f);
        while ($pos > 0 && $lineCount <= $lines) {
            $readSize = ($pos - $chunkSize) >= 0 ? $chunkSize : $pos;
            $pos -= $readSize;
            fseek($f, $pos);
            $buffer = fread($f, $readSize) . $buffer;
            $lineCount = substr_count($buffer, "\n");
        }
        fclose($f);
        $buffer_lines = explode("\n", $buffer);
        return implode("\n", array_slice($buffer_lines, -$lines));
    }

    public function add_settings_page() {
        add_options_page('CDN Cache Settings', 'CDN Cache', 'manage_options', 'bunnycdn-settings', [$this, 'render_settings_page']);
    }

    public function register_settings() {
        register_setting('bunnycdn_settings_group', $this->option_key, function($input) {
            if (!empty($input['api_key'])) {
                $input['api_key'] = $this->encrypt_api_key($input['api_key']);
            }
            return $input;
        });
    }

    public function render_settings_page() {
        if (!current_user_can('manage_options')) return;
        $this->ensure_log_dir();
        $settings = get_option($this->option_key);
        $api_key  = !empty($settings['api_key']) ? $this->decrypt_api_key($settings['api_key']) : '';
        $zone_id  = esc_attr($settings['zone_id'] ?? '');
        $recent = esc_textarea($this->tail_lines($this->log_file, 50));
        $download_url = wp_nonce_url(admin_url('admin-ajax.php?action=bunnycdn_download_log'), 'bunnycdn_download_log');
        ?>
        <div class="wrap">
            <h1>CDN Cache Settings</h1>
            <form method="post" action="options.php">
                <?php settings_fields('bunnycdn_settings_group'); ?>
                <table class="form-table">
                    <tr>
                        <th scope="row">API Key</th>
                        <td>
                            <input type="text" name="<?php echo $this->option_key; ?>[api_key]" value="<?php echo esc_attr($api_key); ?>" class="regular-text" />
                            <button type="button" class="button" id="bunnycdn-fetch-zones">Fetch Zones</button>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Pull Zone</th>
                        <td>
                            <select name="<?php echo $this->option_key; ?>[zone_id]" id="bunnycdn-zone-select">
                                <option value="">-- Select Zone --</option>
                                <?php if ($zone_id): ?>
                                    <option value="<?php echo $zone_id; ?>" selected>Zone ID: <?php echo $zone_id; ?></option>
                                <?php endif; ?>
                            </select>
                        </td>
                    </tr>
                </table>
                <?php submit_button(); ?>
            </form>

            <hr/>
            <h2>Recent Logs</h2>
            <textarea readonly rows="12" style="width:100%; font-family:monospace;"><?php echo $recent ? $recent : 'No logs yet.'; ?></textarea>
            <p><a href="<?php echo esc_url($download_url); ?>" class="button">Download Full Log</a></p>
        </div>
        <?php
    }

    public function fetch_zones() {
        check_ajax_referer('bunnycdn_fetch_zones_nonce');
        if (!current_user_can('manage_options')) wp_send_json(['success' => false, 'message' => 'Unauthorised.']);
        $api_key = sanitize_text_field($_POST['api_key'] ?? '');
        if (!$api_key) wp_send_json(['success' => false, 'message' => 'Missing API key.']);
        $response = wp_remote_get('https://api.bunny.net/pullzone', [
            'headers' => ['AccessKey' => $api_key, 'Accept' => 'application/json']
        ]);
        if (is_wp_error($response)) wp_send_json(['success' => false, 'message' => 'Request failed.']);
        $code = wp_remote_retrieve_response_code($response);
        $body = json_decode(wp_remote_retrieve_body($response));
        if ($code === 200 && !empty($body)) wp_send_json(['success' => true, 'zones' => $body]);
        else wp_send_json(['success' => false, 'message' => 'Could not fetch zones.']);
    }

    public function download_log() {
        check_admin_referer('bunnycdn_download_log');
        if (!current_user_can('manage_options')) wp_die('Unauthorised', 403);
        $this->ensure_log_dir();
        if (!file_exists($this->log_file)) {
            header('Content-Type: text/plain; charset=utf-8');
            header('Content-Disposition: attachment; filename="cdn-purge.log"');
            echo "No logs yet.";
            exit;
        }
        header('Content-Type: text/plain; charset=utf-8');
        header('Content-Disposition: attachment; filename="cdn-purge.log"');
        header('Content-Length: ' . filesize($this->log_file));
        readfile($this->log_file);
        exit;
    }
}

new BunnyCDNPurgePlugin();