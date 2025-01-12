#include <iostream>

// Headers for cryptonote
#include "cryptonote_basic/cryptonote_basic_impl.h"      // for construct_miner_tx, miner transaction utilities
#include "cryptonote_basic/cryptonote_format_utils.h"    // for t_serializable_object_to_blob
#include "crypto/crypto.h"                               // for crypto functions/structs
#include "device/device.hpp"                             // for account_base::generate (if needed)

// Header for epee::string_tools
#include "string_tools.h"     // for epee::string_tools::buff_to_hex_nodelimer

int main()
{
    using namespace cryptonote;

    // 1. Create a fake miner address (or load from real keys)
    account_base miner_acc;
    miner_acc.generate();  // uses device::device_default to generate random keys
    account_public_address miner_address = miner_acc.get_keys().m_account_address;

    // 2. Construct the genesis transaction
    transaction tx_genesis;
    construct_miner_tx(
        /*height=*/0,
        /*already_generated_coins=*/0,
        miner_address,
        tx_genesis,
        /*max_outs=*/1,
        /*hf_version=*/1 // or the hard fork version you want
    );

    // 3. Convert to hex
    std::string genesis_tx_blob = t_serializable_object_to_blob(tx_genesis);
    std::string genesis_tx_hex = epee::string_tools::buff_to_hex_nodelimer(genesis_tx_blob);

    // 4. Print it
    std::cout << "GENESIS_COINBASE_TX_HEX = " << genesis_tx_hex << std::endl;
    return 0;
}
