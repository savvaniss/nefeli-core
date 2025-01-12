#include <iostream>
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "cryptonote_core/cryptonote_basic_impl.h"
#include "device/device.hpp"

int main()
{
    using namespace cryptonote;

    // 1. Create a fake miner address (or load from real keys).
    //    For test purposes, you can generate a random keypair.
    account_base miner_acc;
    miner_acc.generate();
    account_public_address miner_address = miner_acc.get_keys().m_account_address;
    
    // 2. Construct the genesis transaction
    transaction tx_genesis;
    construct_miner_tx(
        /*height=*/0,
        /*already_generated_coins=*/0,
        miner_address,
        tx_genesis,
        /*max_outs=*/1,
        /*version=*/1  // or current HF version
    );

    // 3. Convert to hex
    std::string genesis_tx_hex = epee::string_tools::buff_to_hex_nodelimer(
        t_serializable_object_to_blob(tx_genesis)
    );

    // 4. Print it
    std::cout << "GENESIS_COINBASE_TX_HEX = " << genesis_tx_hex << std::endl;
    return 0;
}
