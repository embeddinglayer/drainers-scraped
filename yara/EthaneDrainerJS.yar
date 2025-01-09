/*
Author: @embeddinglayer
Date: 1/9/2025
Description: Match specific keywords TRANSFER_NFT and TRANSFER_TOKEN
*/
rule EthaneDrainerRule {
    strings:
        $transfer_nft = "TRANSFER_NFT"
        $transfer_token = "TRANSFER_TOKEN"
    condition:
        $transfer_nft and $transfer_token
}
