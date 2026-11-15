#!/bin/bash
# Download the tournament circuits (public URLs) into circuits/
set -e
mkdir -p circuits
cd circuits
curl -sL -o gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm
curl -sL -o gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey
# Export the verification key (needs snarkjs)
node -e "require('snarkjs').zKey.exportVerificationKey('gatekeeper_final.zkey').then(vk => require('fs').writeFileSync('verification_key.json', JSON.stringify(vk, null, 2)))"
echo "circuits ready"
