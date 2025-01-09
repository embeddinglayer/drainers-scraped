/*
Author: @embeddinglayer
Date: 1/9/2025
Description: Phantom drainer landing page detection rule.
*/
rule DetectPhantomLanderRule {
    strings:
        $center_start = /<\s*center\s*>/ nocase
    condition:
        $center_start
}
