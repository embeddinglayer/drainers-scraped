/*
Author: @embeddinglayer
Date: 1/9/2025
Description: Detect JavaScript code that uses `setInterval` to check for `window.ethereum`
*/
rule DetectEthereumInjectionCheck {
    strings:
        $setInterval = "setInterval(() => {"
        $injected_status = "document.getElementById('injected-status').innerHTML"
        $ethereum_check = "(typeof window.ethereum === 'object') ? 'true' : 'false'"
    condition:
        $setInterval and $injected_status and $ethereum_check
}
