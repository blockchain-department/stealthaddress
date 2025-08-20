// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title MetaAddressRegistry - Stores scan/spend public keys for stealth transfers
contract MetaAddressRegistry {
    struct MetaAddress {
        bytes32 scanPublicKey;
        bytes32 spendPublicKey;
    }

    mapping(address => MetaAddress) public registry;

    event MetaAddressRegistered(
        address indexed user,
        bytes32 scanPublicKey,
        bytes32 spendPublicKey,
        uint256 timestamp
    );

    /// @notice Register your scan and spend public keys
    /// @dev Prevents overwriting an existing registration
    function registerMetaAddress(bytes32 scanKey, bytes32 spendKey) external {
        require(scanKey != bytes32(0) && spendKey != bytes32(0), "Invalid keys");
        require(
            registry[msg.sender].scanPublicKey == bytes32(0) &&
            registry[msg.sender].spendPublicKey == bytes32(0),
            "Meta-address already registered"
        );

        registry[msg.sender] = MetaAddress(scanKey, spendKey);

        emit MetaAddressRegistered(msg.sender, scanKey, spendKey, block.timestamp);
    }

    /// @notice Retrieve the meta-address for a given user
    function getMetaAddress(address user) external view returns (MetaAddress memory) {
        return registry[user];
    }
}
