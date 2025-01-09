/*
Author: @embeddinglayer
Date: 1/9/2025
Description: Detect malspam emails from inferno drainer. 
*/
rule InferoDrainerEmailRule {
    strings:
        $title_tag = "<title>Wallet Security Breach</title>" nocase
    condition:
        $title_tag
}
