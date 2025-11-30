# HypernativeGuard

A transaction guard for Safe Multisig that enforces flexible transaction approval policies with multiple security layers.

## Overview

HypernativeGuard is a security module that integrates with Safe smart accounts to provide granular control over transaction execution. It implements a multi layered approval system that combines keeper signatures, pre-approved transaction hashes, timelock mechanisms, and extensible policy enforcement through a plugin architecture.

## Architecture

### Core Components

```
┌──────────────────────────────────────────────────────────────────┐
│                          Safe Wallet                             │
│                                                                  │
│  Transaction Execution → checkTransaction() (Guard Hook)         │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      HypernativeGuard                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Validation Pipeline:                                           │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  1. Pass-through Mode Check                                │ │
│  │  2. Signature Extraction (keeper sig + context)            │ │
│  │  3. Policy Extensions Execution (sequential)               │ │
│  │  4. Transaction Approval Validation                        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  Transaction Approval Methods:                                  │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  • Keeper ECDSA Signature (real-time approval)             │ │
│  │  • Pre-approved Transaction Hash (with nonce, one-time)    │ │
│  │  • Pre-approved Nonce-free Hash (reusable)                 │ │
│  │  • Pre-approved Function Call Hash (by selector)           │ │
│  │  • Timelock-protected Operations (1-day delay)             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  Policy Extension System:                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                                                            │ │
│  │  [Extension 1] → [Extension 2] → ... → [Extension N]       │ │
│  │                                                            │ │
│  │  Custom validation logic via IGuardPolicyExtension         │ │
│  │  (spending limits, whitelists, time restrictions, etc.)    │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

### Key Features

#### 1. Multi-Method Transaction Approval

HypernativeGuard supports five distinct approval mechanisms, providing flexibility for different use cases:

- **Keeper Signature**: Real-time transaction approval via ECDSA signature from authorized keeper
- **Transaction Hash**: Pre-approved hash including nonce (one-time use)
- **Nonce-Free Hash**: Pre-approved hash without nonce (reusable across nonces)
- **Function Call Hash**: Approval based on function selector and target address
- **Timelock Protection**: Time-delayed approval for critical operations

#### 2. Role-Based Access Control

Built on OpenZeppelin's `AccessControlEnumerable`, the system implements:

- **Keeper Role**: Authorized accounts that can approve transactions and manage hashes
- **Safe-Only Functions**: Critical operations restricted to the Safe itself
- **Keeper-or-Safe Functions**: Flexible operations accessible by either party

#### 3. Pass-Through Mode

A special operational mode that:

- Bypasses all approval checks when enabled
- Requires timelock activation (1 day delay) to enable
- Can be disabled immediately by keeper or Safe
- Useful for emergency recovery or transitioning away from the guard

#### 4. Timelock Mechanisms

Two independent timelock systems protect critical operations:

- **Guard Revocation Timelock**: 1 day delay before the guard can be removed from the Safe
- **Pass-Through Mode Timelock**: 1 day delay before entering unrestricted mode

Both can be activated and disabled only by the Safe itself, ensuring that even compromised keepers cannot immediately disable security protections.

#### 5. Extensible Policy System

The guard supports dynamic addition of policy extensions through `IGuardPolicyExtension`:

- Custom validation logic can be added without modifying core contract
- Multiple extensions can be chained together
- Extensions are executed before approval validation
- Only the Safe can add policy extensions; keepers and Safe can remove them

### Transaction Flow

```
┌─────────────────────────────────────────────────────────────┐
│  Safe initiates transaction with keeper signature appended  │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  HypernativeGuard.checkTransaction() invoked                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
              ┌────────────────────────┐
              │ Pass-through mode?     │────YES────▶ Transaction executes
              └────────────┬───────────┘
                          NO
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Extract keeper signature from signatures field             │
│  Format: [safeSigs][keeperSig: 65][context][contextLen: 32] │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Execute all policy extensions in sequence                  │
│  (Each extension can revert to block transaction)           │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  Validate transaction approval:                             │
│                                                             │
│  1. Is it revocation with valid timelock?         ──YES──┐  │
│  2. Is it pass-through enable with timelock?      ──YES──┤  │
│  3. Does keeper signature match keeper role?      ──YES──┤  │
│  4. Is transaction hash pre-approved?             ──YES──┼──▶ Execute
│  5. Is nonce-free hash pre-approved?              ──YES──┤  │
│  6. Is function call hash pre-approved?           ──YES──┘  │
│                                                             │
│               All checks failed?                  ──YES──┐  │
│                                                          │  │
└──────────────────────────────────────────────────────────┼──┘
                                                           │
                                                           ▼
                                                    Revert: UnapprovedHash
```

## Core Contracts

### HypernativeGuard.sol

The main guard implementation that intercepts Safe transactions.

**Key Functions:**

- `checkTransaction()`: Main entry point for transaction validation
- `approveHash()` / `revokeHash()`: Manage transaction hash approvals
- `approveNonceFreeHash()` / `revokeNonceFreeHash()`: Manage nonce-free approvals
- `approveFunctionCallHash()` / `revokeFunctionCallHash()`: Manage function call approvals
- `activateTimelock()` / `disableTimelock()`: Control guard revocation timelock
- `activatePassThroughTimelock()` / `disablePassThroughTimelock()`: Control pass-through timelock
- `enablePassThroughMode()` / `disablePassThroughMode()`: Toggle unrestricted mode
- `grantKeeperRole()` / `revokeKeeperRole()`: Manage keeper permissions
- `addPolicyExtension()` / `removePolicyExtension()`: Manage policy plugins

**Transaction Hash Types:**

```solidity
// Regular transaction hash (EIP-712, includes nonce)
getTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)

// Nonce-free hash (excludes nonce, reusable)
getNonceFreeTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver)

// Function call hash (only 4-byte selector + params)
getFunctionCallHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver)
```

### IGuardPolicyExtension.sol

Interface for implementing custom validation policies.

```solidity
interface IGuardPolicyExtension {
    function checkPolicy(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address executor
    ) external view;

    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
```

**Example Use Cases:**

- Spending limits (daily/weekly caps)
- Whitelist/blacklist enforcement
- Time-based restrictions
- Multi-signature requirements
- Integration with external oracles or monitoring systems

### ISafe.sol

Minimal interface for interacting with Safe smart accounts.

## Signature Format

HypernativeGuard expects an extended signature format that appends keeper signature and optional context:

```
┌──────────────────────────────────────────────────────────────────┐
│ Safe Signatures (variable length)                                │
│ Standard Safe signature data for transaction approval            │
├──────────────────────────────────────────────────────────────────┤
│ Keeper Signature (65 bytes)                                      │
│ ECDSA signature: [r: 32 bytes][s: 32 bytes][v: 1 byte]           │
├──────────────────────────────────────────────────────────────────┤
│ Context Data (contextLength bytes)                               │
│ Optional application-specific data (reserved for future use)     │
├──────────────────────────────────────────────────────────────────┤
│ Context Length (32 bytes)                                        │
│ uint256 value indicating length of context data                  │
└──────────────────────────────────────────────────────────────────┘
```

**Minimum signature length**: 97 bytes (65 keeper sig + 32 length field + 0 context)

The `_extractSignatureComponents()` function safely parses this format with underflow protection.

## Security Model

### Trust Assumptions

1. **Safe Owners**: Control guard configuration but constrained by 1-day timelocks for critical operations
2. **Keepers**: Trusted to approve legitimate transactions in real-time
3. **Policy Extensions**: Can only blacklist/block transactions (cannot whitelist). Should be audited before addition 
4. **Timelock Period**: 1 day assumed sufficient for detection and response


### Critical Operations

Protected by `onlyGuardedSafe` modifier (can only be called by the Safe itself):

- Adding policy extensions
- Granting/revoking keeper roles
- Activating/disabling timelocks
- Enabling pass-through mode

This ensures that even if a keeper's key is compromised, critical security parameters cannot be modified without Safe owner consensus.


## Integration Example

### Basic Setup

```solidity
// 1. Deploy guard
HypernativeGuard guard = new HypernativeGuard(
    safeAddress,
    revokingHash,
    keeperAddress
);

// 2. Activate guard (executed by Safe)
safe.setGuard(address(guard));

// 3. Disable pass-through mode
guard.disablePassThroughMode();

// 4. Keeper approves transaction
bytes32 txHash = guard.getTransactionHash(
    to, value, data, operation,
    safeTxGas, baseGas, gasPrice,
    gasToken, refundReceiver, nonce
);
guard.approveHash(txHash);
```

### Adding a Policy Extension

```solidity
// Custom policy implementation
contract SpendingLimitPolicy is IGuardPolicyExtension {
    uint256 public dailyLimit = 1 ether;

    function checkPolicy(
        address to,
        uint256 value,
        bytes memory data,
        // ... other parameters
    ) external view override {
        require(value <= dailyLimit, "Exceeds daily limit");
    }

    function supportsInterface(bytes4 interfaceId)
        external view override returns (bool) {
        return interfaceId == type(IGuardPolicyExtension).interfaceId;
    }
}

// Add extension (executed by Safe)
safe.execTransaction(
    guardAddress,
    0,
    abi.encodeWithSelector(
        guard.addPolicyExtension.selector,
        address(spendingLimitPolicy)
    ),
    // ... other Safe parameters
);
```

## Events

```solidity
event HashApproved(bytes32 hash, HashType hashType);
event HashRevoked(bytes32 hash, HashType hashType);
event TimelockActivated(uint256 timestamp);
event TimelockDisabled(uint256 timestamp);
event PassThroughTimelockActivated(uint256 timestamp);
event PassThroughTimelockDisabled(uint256 timestamp);
event PolicyExtensionAdded(address policyExtension);
event PolicyExtensionRemoved(address policyExtension);
event PassThroughModeEnabled();
event PassThroughModeDisabled();
```