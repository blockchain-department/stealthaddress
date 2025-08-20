// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title StealthAnnouncement - Emits events for stealth ETH transfers
contract StealthAnnouncement {
    event StealthTransferAnnounced(
        address indexed sender,
        bytes32 ephemeralPublicKey,
        bytes encryptedPayload,
        uint256 timestamp
    );

    /// @notice Emit a stealth transfer announcement
    /// @dev Validates payload length to avoid empty announcements
    function announceStealthTransfer(
        bytes32 ephemeralPublicKey,
        bytes calldata encryptedPayload
    ) external {
        require(ephemeralPublicKey != bytes32(0), "Invalid ephemeral key");
        require(encryptedPayload.length > 0, "Empty payload");

        emit StealthTransferAnnounced(
            msg.sender,
            ephemeralPublicKey,
            encryptedPayload,
            block.timestamp
        );
    }
}
