<?php
function notifyAdminAboutBreach($user_id, $breach_count) {
    $ntfy_topic = "riashe_breach_alerts";
    $ntfy_url = "https://ntfy.sh";

    $message = "🚨 Security Alert: User ID $user_id has a password found in $breach_count breaches!";
    
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: text/plain\r\n",
            'content' => $message
        ]
    ]);
    
    @file_get_contents("$ntfy_url/$ntfy_topic", false, $context);
}