<?php
function sendAdminNotification($title, $message, $priority = 'high') {
    $ntfy_topic = getenv('NTFY_TOPIC') ?: 'your_secret_topic';
    $ntfy_url = getenv('NTFY_URL') ?: 'https://ntfy.sh';
    
    $headers = [
        'Title: ' . $title,
        'Priority: ' . $priority,
        'Tags: warning,skull'
    ];
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers) . "\r\n",
            'content' => $message
        ]
    ]);
    
    file_get_contents("$ntfy_url/$ntfy_topic", false, $context);
}