# Copyright (c) 2014-2022, The Monero Project
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of
#    conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list
#    of conditions and the following disclaimer in the documentation and/or other
#    materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be
#    used to endorse or promote products derived from this software without specific
#    prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
# THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
# THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

set(daemon_sources
  command_parser_executor.cpp
  command_server.cpp
  daemon.cpp
  executor.cpp
  main.cpp
  rpc_command_executor.cpp
)

set(daemon_headers)

monero_find_all_headers(daemon_private_headers "${CMAKE_CURRENT_SOURCE_DIR}")

monero_private_headers(daemon
  ${daemon_private_headers})
monero_add_executable(daemon
  ${daemon_sources}
  ${daemon_headers}
  ${daemon_private_headers})
target_link_libraries(daemon
  PRIVATE
    rpc
    blockchain_db
    cryptonote_core
    cncrypto
    common
    p2p
    cryptonote_protocol
    daemonizer
    serialization
    daemon_rpc_server
    ${EPEE_READLINE}
    version
    ${Boost_CHRONO_LIBRARY}
    ${Boost_FILESYSTEM_LIBRARY}
    ${Boost_PROGRAM_OPTIONS_LIBRARY}
    ${Boost_REGEX_LIBRARY}
    ${Boost_SYSTEM_LIBRARY}
    ${CMAKE_THREAD_LIBS_INIT}
    ${ZMQ_LIB}
    ${GNU_READLINE_LIBRARY}
    ${EXTRA_LIBRARIES}
    ${Blocks})
set_property(TARGET daemon
  PROPERTY
    OUTPUT_NAME "nefelid")
install(TARGETS daemon DESTINATION bin)

# -------------------------------------------------------------------------
# Add a new executable target for generate_genesis_tx
add_executable(generate_genesis_tx
    generate_genesis_tx.cpp
)

target_link_libraries(generate_genesis_tx
    PRIVATE
      ${CMAKE_SOURCE_DIR}/src
    # Link any libs you need for the “construct_miner_tx” code to compile.
    # Typically, at minimum:
      cryptonote_core
      blockchain_db
      cncrypto
      common
      p2p
      cryptonote_protocol
      daemonizer
      serialization
      daemon_rpc_server
      epee           # Often needed for string_tools, etc.
      version

      # Boost libraries, threads, etc. - re-use the same ones from daemon
      ${Boost_CHRONO_LIBRARY}
      ${Boost_FILESYSTEM_LIBRARY}
      ${Boost_PROGRAM_OPTIONS_LIBRARY}
      ${Boost_REGEX_LIBRARY}
      ${Boost_SYSTEM_LIBRARY}
      ${CMAKE_THREAD_LIBS_INIT}
      ${ZMQ_LIB}
      ${GNU_READLINE_LIBRARY}
      ${EXTRA_LIBRARIES}
      ${Blocks}
)

# Optionally rename the executable (not strictly necessary):
set_property(TARGET generate_genesis_tx
  PROPERTY
    OUTPUT_NAME "generate_genesis_tx")
