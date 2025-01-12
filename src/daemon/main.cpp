// Copyright (c) 2014-2022, The Monero Project
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of
//    conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <random>  // if you want a random nonce
#include <array>
#include <cstring> // for memcpy

#include "common/command_line.h"
#include "common/scoped_message_writer.h"
#include "common/password.h"
#include "common/util.h"

#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

#include "serialization/binary_utils.h"

// Must include a file that has buff_to_hex_nodelimer(...) or pod_to_hex(...)
#include "string_tools.h"

#include "cryptonote_basic/account.h"
#include "cryptonote_basic/miner.h"

#include "daemon/command_server.h"
#include "daemon/daemon.h"
#include "daemon/executor.h"
#include "daemonizer/daemonizer.h"

#include "misc_log_ex.h"
#include "net/parse.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_server.h"
#include "rpc/rpc_args.h"
#include "daemon/command_line_args.h"
#include "version.h"

#ifdef STACK_TRACE
#include "common/stack_trace.h"
#endif // STACK_TRACE

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "daemon"

namespace po = boost::program_options;
namespace bf = boost::filesystem;

//-----------------------------------------------------------------------------------------------
uint16_t parse_public_rpc_port(const po::variables_map &vm)
{
  const auto &public_node_arg = daemon_args::arg_public_node;
  const bool public_node = command_line::get_arg(vm, public_node_arg);
  if (!public_node)
  {
    return 0;
  }

  std::string rpc_port_str;
  std::string rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_bind_ip);
  const auto &restricted_rpc_port = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
  if (!command_line::is_arg_defaulted(vm, restricted_rpc_port))
  {
    rpc_port_str = command_line::get_arg(vm, restricted_rpc_port);
    rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_restricted_bind_ip);
  }
  else if (command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc))
  {
    rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
  }
  else
  {
    throw std::runtime_error("restricted RPC mode is required");
  }

  uint16_t rpc_port;
  if (!string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
  {
    throw std::runtime_error("invalid RPC port " + rpc_port_str);
  }

  const auto address = net::get_network_address(rpc_bind_address, rpc_port);
  if (!address) {
    throw std::runtime_error("failed to parse RPC bind address");
  }
  if (address->get_zone() != epee::net_utils::zone::public_)
  {
    throw std::runtime_error(std::string(zone_to_string(address->get_zone()))
      + " network zone is not supported, please check RPC server bind address");
  }

  if (address->is_loopback() || address->is_local())
  {
    MLOG_RED(el::Level::Warning, "--" << public_node_arg.name 
      << " is enabled, but RPC server " << address->str() 
      << " may be unreachable from outside, please check RPC server bind address");
  }

  return rpc_port;
}

#ifdef WIN32
bool isFat32(const wchar_t* root_path)
{
  std::vector<wchar_t> fs(MAX_PATH + 1);
  if (!::GetVolumeInformationW(root_path, nullptr, 0, nullptr, 0, nullptr, &fs[0], MAX_PATH))
  {
    MERROR("Failed to get '" << root_path << "' filesystem name. Error code: " << ::GetLastError());
    return false;
  }

  return wcscmp(L"FAT32", &fs[0]) == 0;
}
#endif

//------------------------------------------------------------------
// Option to print genesis TX and nonce
//------------------------------------------------------------------
static const command_line::arg_descriptor<bool> arg_print_genesis_info = {
    "print-genesis-info",
    "Print the genesis tx and nonce to console/file",
    false
};

//------------------------------------------------------------------
// Helper: Copy 32 bytes of a secret key into a hex string
//------------------------------------------------------------------
static std::string secret_key_to_hex(const crypto::secret_key &sec_key)
{
  // Confirm that this secret key is 32 bytes (which it normally is)
  static_assert(sizeof(sec_key) == 32, "secret_key must be 32 bytes");

  // Copy bytes into a trivial buffer
  std::array<uint8_t, 32> tmp{};
  memcpy(tmp.data(), &sec_key, 32);

  // Convert to hex
  // buff_to_hex_nodelimer expects a string or pointer + length
  const std::string raw(reinterpret_cast<const char*>(tmp.data()), tmp.size());
  return epee::string_tools::buff_to_hex_nodelimer(raw);
}

//------------------------------------------------------------------
// Function to generate & print genesis TX + nonce
//------------------------------------------------------------------
static void print_genesis_tx_and_nonce(uint8_t nettype)
{
  using namespace cryptonote;

  // ---------------------------------------------------------
  // 1) Generate a new miner account
  // ---------------------------------------------------------
  account_base miner_acc;
  miner_acc.generate();

  // We do manual copying to avoid the .unlocked() call
  // (which does not exist in your code)
  const std::string spend_key_hex = secret_key_to_hex(miner_acc.get_keys().m_spend_secret_key);
  const std::string view_key_hex  = secret_key_to_hex(miner_acc.get_keys().m_view_secret_key);

  // ---------------------------------------------------------
  // 2) Print the account information
  // ---------------------------------------------------------
  std::cout << "\n*** Generating miner wallet ***" << std::endl;
  std::cout << "Miner account address:\n"
            << get_account_address_as_str(static_cast<network_type>(nettype), false,
                                          miner_acc.get_keys().m_account_address)
            << std::endl;

  // Print the two secret keys
  std::cout << "Miner spend secret key:\n" << spend_key_hex << std::endl;
  std::cout << "Miner view secret key:\n"  << view_key_hex  << std::endl << std::endl;

  // ---------------------------------------------------------
  // 3) Save these keys to a file (optional, but recommended)
  // ---------------------------------------------------------
  auto t = std::time(nullptr);
  auto tm = *std::localtime(&t);
  std::stringstream key_file_ss;
  key_file_ss << "miner_keys_" << std::put_time(&tm, "%Y%m%d%H%M%S") << ".dat";
  const std::string key_file_name = key_file_ss.str();

  std::ofstream ofs(key_file_name);
  ofs << "Miner account address:\n"
      << get_account_address_as_str(static_cast<network_type>(nettype), false,
                                    miner_acc.get_keys().m_account_address)
      << std::endl
      << "Miner spend secret key:\n" << spend_key_hex << std::endl
      << "Miner view secret key:\n"  << view_key_hex  << std::endl;
  ofs.close();

  // ---------------------------------------------------------
  // 4) Construct the genesis transaction
  //    Make sure you're using the correct signature in your codebase
  // ---------------------------------------------------------
  transaction tx_genesis;
  bool r = construct_miner_tx(
      /* pb                    */ nullptr,  // no Blockchain pointer
      /* network_type         */ static_cast<network_type>(nettype),
      /* height               */ 0,
      /* median_weight        */ 0,
      /* already_generated_coins */ 0,
      /* current_block_weight */ 0,
      /* fee                  */ 0,
      miner_acc.get_keys().m_account_address,
      tx_genesis
      // The optional extra_nonce, max_outs, and hf_version use defaults
  );
  if (!r)
  {
    std::cerr << "Failed to construct genesis transaction" << std::endl;
    return;
  }

    //
  // >>>>>>> FORCE THE BLOCK-0 REWARD TO ZERO <<<<<<<
  //
  // If construct_miner_tx generated a non-zero coinbase,
  // we manually zero it out here:
  //
  if (!tx_genesis.vout.empty())
  {
    tx_genesis.vout[0].amount = 0;
  }

  // ---------------------------------------------------------
  // 5) Convert that tx to raw hex suitable for GENESIS_TX
  // ---------------------------------------------------------
  std::stringstream ss;
  binary_archive<true> ba(ss);
  ::serialization::serialize(ba, tx_genesis);
  std::string tx_hex = ss.str();

  // ---------------------------------------------------------
  // 6) Define or generate a nonce
  // ---------------------------------------------------------
  // Approach A: Fixed nonce (similar to the default Monero approach)
  uint32_t genesis_nonce = 10000;

  // Approach B: Generate a random nonce each time (uncomment if desired)
  /*
  std::random_device rd;
  std::mt19937 rng(rd());
  std::uniform_int_distribution<uint32_t> dist;
  uint32_t genesis_nonce = dist(rng);
  */

  // ---------------------------------------------------------
  // 7) Print everything needed for cryptonote_config.h
  // ---------------------------------------------------------
  std::cout << "*** Insert these lines into your coin config ***\n\n";

  // 1) GENESIS_TX
  std::cout << "std::string const GENESIS_TX = \""
            << epee::string_tools::buff_to_hex_nodelimer(tx_hex)
            << "\";\n";

  // 2) GENESIS_NONCE
  std::cout << "#define GENESIS_NONCE " << genesis_nonce << "\n\n";

  // Optionally show the JSON of the transaction
  std::cout << "*** Genesis transaction (JSON) ***\n"
            << obj_to_json_str(tx_genesis) << std::endl;
}

//------------------------------------------------------------------
int main(int argc, char const * argv[])
{
  try {

    // TODO parse the debug options like set log level right here at start
    tools::on_startup();
    epee::string_tools::set_module_name_and_folder(argv[0]);

    // Build argument description
    po::options_description all_options("All");
    po::options_description hidden_options("Hidden");
    po::options_description visible_options("Options");
    po::options_description core_settings("Settings");
    po::positional_options_description positional_options;
    {
      // Misc Options
      command_line::add_arg(visible_options, command_line::arg_help);
      command_line::add_arg(visible_options, command_line::arg_version);
      command_line::add_arg(visible_options, daemon_args::arg_os_version);
      command_line::add_arg(visible_options, daemon_args::arg_config_file);

      //  Add our new argument for printing genesis info:
      command_line::add_arg(visible_options, arg_print_genesis_info);

      // Settings
      command_line::add_arg(core_settings, daemon_args::arg_log_file);
      command_line::add_arg(core_settings, daemon_args::arg_log_level);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_file_size);
      command_line::add_arg(core_settings, daemon_args::arg_max_log_files);
      command_line::add_arg(core_settings, daemon_args::arg_max_concurrency);
      command_line::add_arg(core_settings, daemon_args::arg_proxy);
      command_line::add_arg(core_settings, daemon_args::arg_proxy_allow_dns_leaks);
      command_line::add_arg(core_settings, daemon_args::arg_public_node);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_bind_ip);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_bind_port);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_pub);
      command_line::add_arg(core_settings, daemon_args::arg_zmq_rpc_disabled);

      daemonizer::init_options(hidden_options, visible_options);
      daemonize::t_executor::init_options(core_settings);

      // Hidden options
      command_line::add_arg(hidden_options, daemon_args::arg_command);

      visible_options.add(core_settings);
      all_options.add(visible_options);
      all_options.add(hidden_options);

      // Positional
      positional_options.add(daemon_args::arg_command.name, -1); // -1 for unlimited arguments
    }

    // Do command line parsing
    po::variables_map vm;
    bool ok = command_line::handle_error_helper(visible_options, [&]()
    {
      boost::program_options::store(
        boost::program_options::command_line_parser(argc, argv)
          .options(all_options).positional(positional_options).run(),
        vm
      );
      return true;
    });
    if (!ok) return 1;

    if (command_line::get_arg(vm, command_line::arg_help))
    {
      std::cout << "Wownero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL << ENDL;
      std::cout << "Usage: " + std::string{argv[0]} + " [options|settings] [daemon_command...]" << std::endl << std::endl;
      std::cout << visible_options << std::endl;
      return 0;
    }

    // Monero Version
    if (command_line::get_arg(vm, command_line::arg_version))
    {
      std::cout << "Wownero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")" << ENDL;
      return 0;
    }

    // OS
    if (command_line::get_arg(vm, daemon_args::arg_os_version))
    {
      std::cout << "OS: " << tools::get_os_version_string() << ENDL;
      return 0;
    }

    std::string config = command_line::get_arg(vm, daemon_args::arg_config_file);
    boost::filesystem::path config_path(config);
    boost::system::error_code ec;
    if (bf::exists(config_path, ec))
    {
      try
      {
        po::store(po::parse_config_file<char>(config_path.string<std::string>().c_str(), core_settings), vm);
      }
      catch (const po::unknown_option &e)
      {
        std::string unrecognized_option = e.get_option_name();
        if (all_options.find_nothrow(unrecognized_option, false))
        {
          std::cerr << "Option '" << unrecognized_option << "' is not allowed in the config file, please use it as a command line flag." << std::endl;
        }
        else
        {
          std::cerr << "Unrecognized option '" << unrecognized_option << "' in config file." << std::endl;
        }
        return 1;
      }
      catch (const std::exception &e)
      {
        // log system isn't initialized yet
        std::cerr << "Error parsing config file: " << e.what() << std::endl;
        throw;
      }
    }
    else if (!command_line::is_arg_defaulted(vm, daemon_args::arg_config_file))
    {
      std::cerr << "Can't find config file " << config << std::endl;
      return 1;
    }

    const bool testnet = command_line::get_arg(vm, cryptonote::arg_testnet_on);
    const bool stagenet = command_line::get_arg(vm, cryptonote::arg_stagenet_on);
    const bool regtest  = command_line::get_arg(vm, cryptonote::arg_regtest_on);
    if (testnet + stagenet + regtest > 1)
    {
      std::cerr << "Can't specify more than one of --testnet and --stagenet and --regtest" << ENDL;
      return 1;
    }

    // Create data dir if it doesn't exist
    boost::filesystem::path data_dir = boost::filesystem::absolute(
        command_line::get_arg(vm, cryptonote::arg_data_dir));

#ifdef WIN32
    if (isFat32(data_dir.root_path().c_str()))
    {
      MERROR("Data directory resides on FAT32 volume that has 4GiB file size limit, blockchain might get corrupted.");
    }
#endif

    bf::path relative_path_base = data_dir; // Daemon's default data dir
    po::notify(vm);

    // ---------------------------------------------------------
    // If asked to print the genesis info, do so now & exit
    // ---------------------------------------------------------
    if (command_line::get_arg(vm, arg_print_genesis_info))
    {
      // 0 = MAINNET in many forks, or cryptonote::MAINNET if you prefer
      print_genesis_tx_and_nonce(0 /* or cryptonote::MAINNET */);
      return 0;
    }

    // log_file_path default
    bf::path log_file_path { data_dir / std::string(CRYPTONOTE_NAME ".log") };
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_file))
      log_file_path = command_line::get_arg(vm, daemon_args::arg_log_file);
    if (!log_file_path.has_parent_path())
      log_file_path = bf::absolute(log_file_path, relative_path_base);

    mlog_configure(
      log_file_path.string(),
      /* console = */ true,
      command_line::get_arg(vm, daemon_args::arg_max_log_file_size),
      command_line::get_arg(vm, daemon_args::arg_max_log_files)
    );

    // Set log level
    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_log_level))
    {
      mlog_set_log(command_line::get_arg(vm, daemon_args::arg_log_level).c_str());
    }

    // after logs initialized
    tools::create_directories_if_necessary(data_dir.string());

#ifdef STACK_TRACE
    tools::set_stack_trace_log(log_file_path.filename().string());
#endif // STACK_TRACE

    if (!command_line::is_arg_defaulted(vm, daemon_args::arg_max_concurrency))
      tools::set_max_concurrency(command_line::get_arg(vm, daemon_args::arg_max_concurrency));

    // logging is now set up
    MGINFO("Wownero '" << MONERO_RELEASE_NAME << "' (v" << MONERO_VERSION_FULL << ")");

    // If there are positional options, we're running a daemon command
    {
      auto command = command_line::get_arg(vm, daemon_args::arg_command);

      if (!command.empty())
      {
        const cryptonote::rpc_args::descriptors arg{};
        auto rpc_ip_str   = command_line::get_arg(vm, arg.rpc_bind_ip);
        auto rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);

        uint32_t rpc_ip;
        uint16_t rpc_port;
        if (!epee::string_tools::get_ip_int32_from_string(rpc_ip, rpc_ip_str))
        {
          std::cerr << "Invalid IP: " << rpc_ip_str << std::endl;
          return 1;
        }
        if (!epee::string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
        {
          std::cerr << "Invalid port: " << rpc_port_str << std::endl;
          return 1;
        }

        const char *env_rpc_login = nullptr;
        const bool has_rpc_arg = command_line::has_arg(vm, arg.rpc_login);
        const bool use_rpc_env = !has_rpc_arg && (env_rpc_login = getenv("RPC_LOGIN")) != nullptr && strlen(env_rpc_login) > 0;
        boost::optional<tools::login> login{};
        if (has_rpc_arg || use_rpc_env)
        {
          login = tools::login::parse(
            has_rpc_arg ? command_line::get_arg(vm, arg.rpc_login) : std::string(env_rpc_login),
            /*quiet=*/ false,
            [](bool verify) {
              PAUSE_READLINE();
              return tools::password_container::prompt(verify, "Daemon client password");
            }
          );
          if (!login)
          {
            std::cerr << "Failed to obtain password" << std::endl;
            return 1;
          }
        }

        auto ssl_options = cryptonote::rpc_args::process_ssl(vm, /*require_ssl=*/ true);
        if (!ssl_options)
          return 1;

        daemonize::t_command_server rpc_commands{rpc_ip, rpc_port, std::move(login), std::move(*ssl_options)};
        if (rpc_commands.process_command_vec(command))
        {
          return 0;
        }
        else
        {
          PAUSE_READLINE();
          std::cerr << "Unknown command: " << command.front() << std::endl;
          return 1;
        }
      }
    }

    MINFO("Moving from main() into the daemonize now.");
    return daemonizer::daemonize(argc, argv, daemonize::t_executor{parse_public_rpc_port(vm)}, vm) ? 0 : 1;
  }
  catch (const std::exception &ex)
  {
    LOG_ERROR("Exception in main! " << ex.what());
  }
  catch (...)
  {
    LOG_ERROR("Exception in main!");
  }
  return 1;
}
