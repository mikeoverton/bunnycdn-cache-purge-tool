(function($) {
    'use strict';

    const BunnyCDNPurge = {
        init: function() {
            this.bindEvents();
        },

        bindEvents: function() {
            // Admin page buttons
            $('#bunnycdn-purge-all-btn').on('click', this.purgeAll.bind(this));
            $('#bunnycdn-purge-url-btn').on('click', this.purgeUrl.bind(this));
            $('#bunnycdn-clear-log').on('click', this.clearLog.bind(this));

            // Refresh pull zones button
            $('#bunnycdn-refresh-pullzones').on('click', this.refreshPullzones.bind(this));

            // Watch API key field for changes
            $('#bunnycdn_api_key').on('change', this.onApiKeyChange.bind(this));
            
            // Edit API key button
            $('#bunnycdn-edit-api-key').on('click', this.onEditApiKey.bind(this));

            // Enter key on URL input
            $('#bunnycdn-purge-url').on('keypress', function(e) {
                if (e.which === 13) {
                    e.preventDefault();
                    BunnyCDNPurge.purgeUrl();
                }
            });
        },
        
        onEditApiKey: function() {
            const $input = $('#bunnycdn_api_key');
            const $btn = $('#bunnycdn-edit-api-key');
            
            // Clear the masked value and make editable
            $input.val('').prop('readonly', false).focus();
            $btn.hide();
            
            // Disable pull zone select until new key is validated
            $('#bunnycdn_pull_zone_id').prop('disabled', true);
            $('#bunnycdn-refresh-pullzones').prop('disabled', true);
        },

        onApiKeyChange: function() {
            const apiKey = $('#bunnycdn_api_key').val().trim();
            const $select = $('#bunnycdn_pull_zone_id');
            const $refreshBtn = $('#bunnycdn-refresh-pullzones');

            if (apiKey) {
                $select.prop('disabled', false);
                $refreshBtn.prop('disabled', false);
            } else {
                $select.prop('disabled', true);
                $refreshBtn.prop('disabled', true);
                $select.html('<option value="">— Select a pull zone —</option>');
            }
        },

        refreshPullzones: function() {
            const apiKey = $('#bunnycdn_api_key').val().trim();
            const $select = $('#bunnycdn_pull_zone_id');
            const $refreshBtn = $('#bunnycdn-refresh-pullzones');
            const currentValue = $select.val();

            if (!apiKey) {
                this.showNotice('error', 'Please enter an API key first.');
                return;
            }

            $refreshBtn.prop('disabled', true).addClass('spin');
            $select.prop('disabled', true);

            $.ajax({
                url: bunnyCDN.ajax_url,
                type: 'POST',
                data: {
                    action: 'bunnycdn_get_pullzones',
                    nonce: bunnyCDN.nonce,
                    api_key: apiKey
                },
                success: function(response) {
                    if (response.success && response.data.pullzones) {
                        $select.html('<option value="">— Select a pull zone —</option>');
                        
                        response.data.pullzones.forEach(function(zone) {
                            let label = zone.name;
                            if (zone.url) {
                                label += ' (' + zone.url + ')';
                            }
                            
                            const $option = $('<option></option>')
                                .val(zone.id)
                                .text(label);
                            
                            if (zone.id == currentValue) {
                                $option.prop('selected', true);
                            }
                            
                            $select.append($option);
                        });

                        BunnyCDNPurge.showNotice('success', 'Pull zones loaded successfully.');
                    } else {
                        BunnyCDNPurge.showNotice('error', response.data.message || 'Failed to load pull zones.');
                    }
                },
                error: function(xhr, status, error) {
                    BunnyCDNPurge.showNotice('error', 'Request failed: ' + error);
                },
                complete: function() {
                    $refreshBtn.prop('disabled', false).removeClass('spin');
                    $select.prop('disabled', false);
                }
            });
        },

        purgeAll: function() {
            if (!confirm('Are you sure you want to purge the entire BunnyCDN cache?')) {
                return;
            }

            this.setLoading(true);

            $.ajax({
                url: bunnyCDN.ajax_url,
                type: 'POST',
                data: {
                    action: 'bunnycdn_purge_all',
                    nonce: bunnyCDN.nonce
                },
                success: function(response) {
                    if (response.success) {
                        BunnyCDNPurge.showNotice('success', response.data.message);
                        BunnyCDNPurge.addLogEntry('Full cache purge', 'success');
                    } else {
                        BunnyCDNPurge.showNotice('error', response.data.message);
                        BunnyCDNPurge.addLogEntry('Full cache purge failed', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    BunnyCDNPurge.showNotice('error', 'Request failed: ' + error);
                },
                complete: function() {
                    BunnyCDNPurge.setLoading(false);
                }
            });
        },

        purgeUrl: function() {
            const url = $('#bunnycdn-purge-url').val().trim();

            if (!url) {
                this.showNotice('error', 'Please enter a URL to purge.');
                return;
            }

            if (!this.isValidUrl(url)) {
                this.showNotice('error', 'Please enter a valid URL.');
                return;
            }

            this.setLoading(true);

            $.ajax({
                url: bunnyCDN.ajax_url,
                type: 'POST',
                data: {
                    action: 'bunnycdn_purge_url',
                    nonce: bunnyCDN.nonce,
                    url: url
                },
                success: function(response) {
                    if (response.success) {
                        BunnyCDNPurge.showNotice('success', response.data.message);
                        BunnyCDNPurge.addLogEntry('URL purge: ' + url, 'success');
                        $('#bunnycdn-purge-url').val('');
                    } else {
                        BunnyCDNPurge.showNotice('error', response.data.message);
                        BunnyCDNPurge.addLogEntry('URL purge failed', 'error');
                    }
                },
                error: function(xhr, status, error) {
                    BunnyCDNPurge.showNotice('error', 'Request failed: ' + error);
                },
                complete: function() {
                    BunnyCDNPurge.setLoading(false);
                }
            });
        },

        isValidUrl: function(string) {
            try {
                new URL(string);
                return true;
            } catch (_) {
                return false;
            }
        },

        setLoading: function(loading) {
            const $buttons = $('.bunnycdn-wrap button, .bunnycdn-wrap .bunnycdn-btn-primary');
            $buttons.prop('disabled', loading);
        },

        showNotice: function(type, message) {
            // Remove existing notices
            $('#bunnycdn-toast').remove();

            const bgColor = type === 'success' ? '#10B981' : type === 'error' ? '#EF4444' : '#3B82F6';
            
            const $toast = $('<div>', {
                id: 'bunnycdn-toast',
                css: {
                    position: 'fixed',
                    top: '40px',
                    right: '20px',
                    zIndex: 999999,
                    background: bgColor,
                    color: '#fff',
                    padding: '12px 20px',
                    borderRadius: '8px',
                    boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
                    fontSize: '14px',
                    fontWeight: '500',
                    maxWidth: '320px',
                    animation: 'bunnycdn-slide-in 0.3s ease'
                }
            }).text(message);

            // Add animation keyframes if not exists
            if (!$('#bunnycdn-toast-styles').length) {
                $('head').append('<style id="bunnycdn-toast-styles">' +
                    '@keyframes bunnycdn-slide-in { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }' +
                '</style>');
            }

            $('body').append($toast);

            setTimeout(function() {
                $toast.css({
                    transition: 'opacity 0.3s ease',
                    opacity: '0'
                });
                setTimeout(function() { $toast.remove(); }, 300);
            }, 4000);
        },

        addLogEntry: function(message, status) {
            const $log = $('#bunnycdn-log');
            if (!$log.length) return;

            // Remove empty state message
            $log.find('.bunnycdn-log-empty').remove();

            const dotClass = status === 'error' ? 'error' : '';
            
            const $entry = $('<div>', { class: 'bunnycdn-log-entry' });
            $entry.append($('<div>', { class: 'bunnycdn-log-dot ' + dotClass }));
            $entry.append($('<span>', { class: 'bunnycdn-log-message' }).text(message));
            $entry.append($('<span>', { class: 'bunnycdn-log-time' }).text('Just now'));

            $log.prepend($entry);

            // Keep only last 10 visible entries
            $log.find('.bunnycdn-log-entry').slice(10).remove();
        },

        clearLog: function() {
            if (!confirm('Clear the activity log?')) {
                return;
            }

            $.ajax({
                url: bunnyCDN.ajax_url,
                type: 'POST',
                data: {
                    action: 'bunnycdn_clear_log',
                    nonce: bunnyCDN.nonce
                },
                success: function(response) {
                    if (response.success) {
                        $('#bunnycdn-log').html('<div class="bunnycdn-log-empty">No activity yet</div>');
                        BunnyCDNPurge.showNotice('success', 'Log cleared.');
                    } else {
                        BunnyCDNPurge.showNotice('error', response.data.message || 'Failed to clear log.');
                    }
                },
                error: function(xhr, status, error) {
                    BunnyCDNPurge.showNotice('error', 'Request failed: ' + error);
                }
            });
        }
    };

    // CDN Settings Handler
    const BunnyCDNSettings = {
        init: function() {
            this.bindEvents();
            this.initTagsInputs();
        },

        bindEvents: function() {
            // Toggle CDN settings visibility
            $('input[name="bunnycdn_cdn_enabled"]').on('change', function() {
                $('#bunnycdn-cdn-settings').toggle(this.checked);
            });

            // Toggle CORS extensions visibility
            $('input[name="bunnycdn_cors_enabled"]').on('change', function() {
                $('#cors-extensions-field').toggle(this.checked);
            });

            // Update hostname dropdown when pull zone changes
            $('#bunnycdn_pull_zone_id').on('change', this.updateHostnames.bind(this));
        },

        initTagsInputs: function() {
            // Included directories
            this.setupTagsInput(
                '#bunnycdn-add-directory',
                '#included-directories-list',
                '#bunnycdn_included_directories'
            );

            // Excluded paths
            this.setupTagsInput(
                '#bunnycdn-add-excluded',
                '#excluded-paths-list',
                '#bunnycdn_excluded_paths'
            );

            // CORS extensions
            this.setupTagsInput(
                '#bunnycdn-add-cors',
                '#cors-extensions-list',
                '#bunnycdn_cors_extensions'
            );
        },

        setupTagsInput: function(inputSelector, listSelector, hiddenSelector) {
            const $input = $(inputSelector);
            const $list = $(listSelector);
            const $hidden = $(hiddenSelector);
            const self = this;

            // Add tag on Enter or comma
            $input.on('keydown', function(e) {
                if (e.key === 'Enter' || e.key === ',') {
                    e.preventDefault();
                    e.stopPropagation();
                    const value = $input.val().trim().replace(/,/g, '');
                    if (value) {
                        self.addTag($list, $hidden, value);
                        $input.val('');
                    }
                    return false;
                }
            });
            
            // Also handle keypress for broader compatibility
            $input.on('keypress', function(e) {
                if (e.which === 13) { // Enter key
                    e.preventDefault();
                    e.stopPropagation();
                    const value = $input.val().trim();
                    if (value) {
                        self.addTag($list, $hidden, value);
                        $input.val('');
                    }
                    return false;
                }
            });

            // Add tag on blur (with slight delay to avoid conflicts)
            $input.on('blur', function() {
                setTimeout(function() {
                    const value = $input.val().trim();
                    if (value) {
                        self.addTag($list, $hidden, value);
                        $input.val('');
                    }
                }, 100);
            });

            // Remove tag
            $list.on('click', '.bunnycdn-tag-remove', function(e) {
                e.preventDefault();
                const $tag = $(this).closest('.bunnycdn-tag');
                $tag.remove();
                self.updateHiddenField($list, $hidden);
            });
        },

        addTag: function($list, $hidden, value) {
            // Check for duplicates using filter to avoid selector injection
            const exists = $list.find('.bunnycdn-tag').filter(function() {
                return $(this).attr('data-value') === value;
            }).length > 0;
            
            if (exists) {
                return;
            }

            const $tag = $('<span>', { class: 'bunnycdn-tag' }).attr('data-value', value);
            $tag.append(document.createTextNode(value));
            $tag.append($('<button>', { type: 'button', class: 'bunnycdn-tag-remove' }).html('&times;'));
            
            $list.append($tag);
            this.updateHiddenField($list, $hidden);
        },

        updateHiddenField: function($list, $hidden) {
            const values = [];
            $list.find('.bunnycdn-tag').each(function() {
                values.push($(this).data('value'));
            });
            $hidden.val(JSON.stringify(values));
        },

        updateHostnames: function() {
            const pullZoneId = $('#bunnycdn_pull_zone_id').val();
            const $hostnameSelect = $('#bunnycdn_cdn_hostname');
            
            if (!pullZoneId) {
                return;
            }

            // Get hostnames from the pull zones data stored by PHP
            // The hostname dropdown is populated server-side, but we can update it via AJAX if needed
            $.ajax({
                url: bunnyCDN.ajax_url,
                type: 'POST',
                data: {
                    action: 'bunnycdn_get_hostnames',
                    nonce: bunnyCDN.nonce,
                    pull_zone_id: pullZoneId
                },
                success: function(response) {
                    if (response.success && response.data.hostnames) {
                        $hostnameSelect.html('<option value="">— Select a hostname —</option>');
                        response.data.hostnames.forEach(function(hostname) {
                            $hostnameSelect.append(
                                $('<option></option>').val(hostname).text(hostname)
                            );
                        });
                    }
                }
            });
        }
    };

    $(document).ready(function() {
        BunnyCDNPurge.init();
        BunnyCDNSettings.init();
    });

})(jQuery);
