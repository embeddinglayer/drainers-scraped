/*
Author: @embeddinglayer
Date: 1/9/2025
Description: Match based off of obfuscation.
*/
rule InfernoDrainerRule {
    strings:
        $pattern = /_0x[a-zA-Z0-9]{6}/
        $part1 = "'tok'"
        $part2 = "'ens'"
        $part3 = "'id'"
    condition:
        $pattern and ($part1 or $part2 or $part3)
}
