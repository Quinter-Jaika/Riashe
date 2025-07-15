<?php
function checkPasswordStrength($password) {
    $score = 0;
    $feedback = [];
    
    // Length check
    if (strlen($password) >= 12) $score += 3;
    elseif (strlen($password) >= 8) $score += 2;
    elseif (strlen($password) >= 6) $score += 1;
    else $feedback[] = "Password is too short";
    
    // Complexity checks
    if (preg_match('/[A-Z]/', $password)) $score += 1;
    else $feedback[] = "Add uppercase letters";
    
    if (preg_match('/[a-z]/', $password)) $score += 1;
    else $feedback[] = "Add lowercase letters";
    
    if (preg_match('/[0-9]/', $password)) $score += 1;
    else $feedback[] = "Add numbers";
    
    if (preg_match('/[^A-Za-z0-9]/', $password)) $score += 2;
    else $feedback[] = "Add special characters";
    
    // Common password check
    if (isCommonPassword($password)) {
        $score = 0;
        $feedback[] = "Password is too common";
    }
    
    return [
        'score' => min($score, 10), // Cap at 10
        'feedback' => $feedback,
        'is_acceptable' => ($score >= 6)
    ];
}

function isCommonPassword($password) {
    $common = ['password', '123456', 'qwerty', 'letmein', 'welcome'];
    return in_array(strtolower($password), $common);
}
?>