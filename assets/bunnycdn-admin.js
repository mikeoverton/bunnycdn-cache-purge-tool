(function($){
    $(function(){
        var btn = $('#bunnycdn-fetch-zones');
        if (!btn.length) { return; }

        btn.on('click', function(e){
            e.preventDefault();
            var apiKey = $('input[name="bunnycdn_settings[api_key]"]').val().trim();
            var select = $('#bunnycdn-zone-select');
            if (!apiKey) {
                alert('Please enter your BunnyCDN Account API Key first.');
                return;
            }

            select.html('<option>Loading...</option>');

            $.ajax({
                url: bunnycdnAjax.ajaxurl,
                method: 'POST',
                dataType: 'json',
                data: {
                    action: bunnycdnAjax.action,
                    _wpnonce: bunnycdnAjax.nonce,
                    api_key: apiKey
                }
            }).done(function(res){
                if (res && res.success && Array.isArray(res.zones)) {
                    select.empty().append('<option value="">-- Select Zone --</option>');
                    res.zones.forEach(function(zone){
                        select.append('<option value="'+ zone.Id +'">'+ zone.Name +' (ID: '+ zone.Id +')</option>');
                    });
                } else {
                    alert((res && res.message) ? res.message : 'Could not fetch zones.');
                    select.html('<option value="">-- Select Zone --</option>');
                }
            }).fail(function(){
                alert('Error fetching zones.');
                select.html('<option value="">-- Select Zone --</option>');
            });
        });
    });
})(jQuery);
