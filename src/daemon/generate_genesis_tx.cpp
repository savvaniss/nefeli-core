#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "crypto/crypto.h"
#include "string_tools.h"
#include <iostream>

using namespace cryptonote;

int main() {
    // Replace this with your public key (from your wallet viewkey)
    const std::string public_key_hex = "21cb1174f548421346c3a8f5e5896079fcb0d8a55958a05f50dbeaa263150226    ";
    crypto::public_key pub_key;

    // Convert the public key to the required format
    if (!epee::string_tools::hex_to_pod(public_key_hex, pub_key)) {
        std::cerr << "Failed to parse public key!" << std::endl;
        return 1;
    }

    // Construct the genesis transaction
    transaction tx = AUTO_VAL_INIT(tx);
    tx.version = 1;  // Transaction version
    tx.unlock_time = 0;  // No unlock time

    // Null input for genesis block
    tx.vin.resize(1);
    tx.vin[0] = txin_gen{0};  // Null input for genesis

    // Output to the public key
    tx.vout.resize(1);
    tx_out out;
    out.amount = 0;  // No amount in the genesis transaction
    out.target = txout_to_key{pub_key};  // Output to the public key
    tx.vout[0] = out;

    // Add extra field (optional metadata or public key)
    tx.extra.push_back(TX_EXTRA_TAG_PUBKEY);  // Indicate public key
    tx.extra.insert(tx.extra.end(), reinterpret_cast<const uint8_t*>(&pub_key), reinterpret_cast<const uint8_t*>(&pub_key) + sizeof(pub_key));

    // Serialize the transaction into hex
    std::string tx_blob;
    if (!t_serializable_object_to_blob(tx, tx_blob)) {
        std::cerr << "Failed to serialize transaction!" << std::endl;
        return 1;
    }

    // Output the genesis transaction hex
    std::cout << "GENESIS_TX:\n" << epee::string_tools::buff_to_hex_nodelimer(tx_blob) << std::endl;

    return 0;
}
