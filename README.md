# stealthaddress

-- Workflow Overview

Receiver generates two key pairs: scan keys and spend keys.

Receiver publishes their public scan key and public spend key to the registry contract.

Sender fetches receiver's registered meta-address (scan and spend public keys).

Sender generates an ephemeral key pair.

Sender derives a shared secret using Diffie-Hellman between ephemeral private key and receiver's scan public key.

Sender encrypts the payload with this shared secret and computes the stealth address.

Sender announces the ephemeral public key and encrypted payload by calling the announcement contract.

Receiver scans announcements from the blockchain.

Receiver attempts to decrypt payloads using their private scan key and derives the stealth address.

Receiver verifies ownership of the stealth address using their spend private key.

-- Scripts
1. generateReceiverKeys.js

Generates scan and spend key pairs for the receiver.

Stores private keys and public keys in ./keys/receiver.json.

These keys are later used to derive stealth addresses.

2. generateStealthAddress.js

Loads receiver’s public scan and spend keys.

Generates an ephemeral key pair.

Derives a shared secret and stealth address.

Encrypts payload with the shared secret.

Stores announcement data (ephemeral public key, encrypted payload, stealth address) in ./keys/announcement.json.

3. reconstructStealthAddress.js

Loads receiver’s private scan and spend keys.

Reads the announcement file.

Reconstructs the stealth address.

Verifies that the derived stealth address matches the announced one.

-- Smart Contracts
--MetaAddressRegistry

Stores mapping of user addresses to their scan and spend public keys.

Users register their keys once.

Allows senders to fetch receiver meta-addresses from chain.

-- StealthAnnouncement

Allows senders to announce stealth transfers.

Emits event with ephemeral public key and encrypted payload.

Events are scanned by receivers to identify messages intended for them.

-- Usage

Run node generateReceiverKeys.js to generate receiver key pairs.

Deploy contracts and register receiver keys on-chain using MetaAddressRegistry.

Run node generateStealthAddress.js to create a stealth address and announcement.

Use StealthAnnouncement contract to publish the announcement event.

Receiver runs node reconstructStealthAddress.js to recover and verify the stealth address.
