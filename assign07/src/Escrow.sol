// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title  Escrow between a buyer and a seller, with an arbiter for disputes
/// @author 2611MC03
/// @notice One deal per contract. See docs/specification.md for the full rules.
///         Created -> Funded | Cancelled;  Funded -> Released | Disputed;
///         Disputed -> ResolvedToBuyer | ResolvedToSeller;  terminal states never change.
///         Money moves only by pull payments (credits + withdraw).
contract Escrow is ReentrancyGuard, EIP712 {
    // ------------------------------------------------------------------ types
    enum State {
        Created,
        Funded,
        Released,
        Disputed,
        ResolvedToBuyer,
        ResolvedToSeller,
        Cancelled
    }

    // ------------------------------------------------------------------ errors
    error ZeroAddress();
    error RoleOverlap();
    error ZeroAmount();
    error ZeroTimeout();
    error Unauthorized(address caller);
    error InvalidState(State current);
    error WrongAmount(uint256 sent, uint256 expected);
    error AlreadyApproved(address party);
    error DisputeNotExpired(uint256 deadline);
    error SignatureExpired(uint256 deadline);
    error InvalidSignature();
    error NothingToWithdraw();
    error TransferFailed();
    error DirectPaymentRejected();

    // ------------------------------------------------------------------ events
    event StateChanged(State indexed from, State indexed to);
    event Funded(address indexed buyer, uint256 amount);
    event CancelApproved(address indexed by);
    event Released(address indexed by);
    event DisputeRaised(address indexed by);
    event DisputeResolved(address indexed by, bool toSeller);
    event Credited(address indexed payee, uint256 amount);
    event Withdrawn(address indexed payee, address indexed to, uint256 amount);

    // ------------------------------------------------------------------ storage
    bytes32 public constant RELEASE_TYPEHASH = keccak256("Release(uint256 nonce,uint256 deadline)");

    address public immutable buyer;
    address public immutable seller;
    address public immutable arbiter;
    uint256 public immutable amount;
    uint256 public immutable disputeTimeout;

    State public state;
    uint64 public disputedAt;
    bool public buyerApprovedCancel;
    bool public sellerApprovedCancel;
    uint256 public releaseNonce;
    uint256 public totalCredits;
    mapping(address => uint256) public credits;

    // ------------------------------------------------------------------ modifiers
    modifier inState(State required) {
        if (state != required) revert InvalidState(state);
        _;
    }

    modifier only(address who) {
        if (msg.sender != who) revert Unauthorized(msg.sender);
        _;
    }

    modifier onlyParties() {
        if (msg.sender != buyer && msg.sender != seller) revert Unauthorized(msg.sender);
        _;
    }

    // ------------------------------------------------------------------ setup
    constructor(address buyer_, address seller_, address arbiter_, uint256 amount_, uint256 disputeTimeout_)
        EIP712("Escrow", "1")
    {
        if (buyer_ == address(0) || seller_ == address(0) || arbiter_ == address(0)) revert ZeroAddress();
        if (buyer_ == seller_ || arbiter_ == buyer_ || arbiter_ == seller_) revert RoleOverlap();
        if (amount_ == 0) revert ZeroAmount();
        if (disputeTimeout_ == 0) revert ZeroTimeout();
        buyer = buyer_;
        seller = seller_;
        arbiter = arbiter_;
        amount = amount_;
        disputeTimeout = disputeTimeout_;
    }

    // ------------------------------------------------------------------ Created
    /// @notice Buyer deposits exactly `amount`. Only once, only in Created.
    function fund() external payable only(buyer) inState(State.Created) {
        if (msg.value != amount) revert WrongAmount(msg.value, amount);
        _setState(State.Funded);
        emit Funded(msg.sender, msg.value);
    }

    /// @notice Mutual cancellation before funding: both buyer and seller must approve.
    function approveCancel() external onlyParties inState(State.Created) {
        if (msg.sender == buyer) {
            if (buyerApprovedCancel) revert AlreadyApproved(msg.sender);
            buyerApprovedCancel = true;
        } else {
            if (sellerApprovedCancel) revert AlreadyApproved(msg.sender);
            sellerApprovedCancel = true;
        }
        emit CancelApproved(msg.sender);
        if (buyerApprovedCancel && sellerApprovedCancel) _setState(State.Cancelled);
    }

    // ------------------------------------------------------------------ Funded
    /// @notice Buyer is satisfied: the seller may withdraw `amount`.
    function release() external only(buyer) inState(State.Funded) {
        _release();
    }

    /// @notice Gas-sponsored release: anyone submits the buyer's EIP-712 signature.
    function releaseWithSig(uint256 deadline, bytes calldata signature) external inState(State.Funded) {
        if (block.timestamp > deadline) revert SignatureExpired(deadline);
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(RELEASE_TYPEHASH, releaseNonce, deadline)));
        if (ECDSA.recover(digest, signature) != buyer) revert InvalidSignature();
        releaseNonce += 1;
        _release();
    }

    /// @notice Either party disagrees: the arbiter will decide.
    function raiseDispute() external onlyParties inState(State.Funded) {
        disputedAt = uint64(block.timestamp);
        _setState(State.Disputed);
        emit DisputeRaised(msg.sender);
    }

    // ------------------------------------------------------------------ Disputed
    /// @notice Arbiter decides who receives the deposit.
    function resolve(bool toSeller) external only(arbiter) inState(State.Disputed) {
        _resolve(toSeller);
    }

    /// @notice If the arbiter has not acted within `disputeTimeout`, either party can refund the buyer.
    function resolveAfterTimeout() external onlyParties inState(State.Disputed) {
        uint256 deadline = disputeDeadline();
        if (block.timestamp < deadline) revert DisputeNotExpired(deadline);
        _resolve(false);
    }

    // ------------------------------------------------------------------ withdrawals
    /// @notice Pull your credit to yourself.
    function withdraw() external {
        _withdraw(payable(msg.sender));
    }

    /// @notice Pull your credit to another address (if your own address cannot receive ETH).
    function withdrawTo(address payable to) external {
        if (to == address(0)) revert ZeroAddress();
        _withdraw(to);
    }

    // ------------------------------------------------------------------ views
    /// @notice ETH the contract owes: the deposit while undecided plus all unpaid credits.
    function liabilities() public view returns (uint256) {
        bool held = state == State.Funded || state == State.Disputed;
        return (held ? amount : 0) + totalCredits;
    }

    function isTerminal() public view returns (bool) {
        return state == State.Released || state == State.ResolvedToBuyer || state == State.ResolvedToSeller
            || state == State.Cancelled;
    }

    function disputeDeadline() public view returns (uint256) {
        return uint256(disputedAt) + disputeTimeout;
    }

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    // ------------------------------------------------------------------ internals
    function _release() private {
        _setState(State.Released);
        emit Released(msg.sender);
        _credit(seller);
    }

    function _resolve(bool toSeller) private {
        _setState(toSeller ? State.ResolvedToSeller : State.ResolvedToBuyer);
        emit DisputeResolved(msg.sender, toSeller);
        _credit(toSeller ? seller : buyer);
    }

    function _credit(address payee) private {
        credits[payee] += amount;
        totalCredits += amount;
        emit Credited(payee, amount);
    }

    /// Checks-effects-interactions + reentrancy guard. A failed transfer reverts the whole call,
    /// so the credit is restored and can be withdrawn later (or elsewhere with withdrawTo).
    function _withdraw(address payable to) private nonReentrant {
        uint256 owed = credits[msg.sender];
        if (owed == 0) revert NothingToWithdraw(); //               checks
        credits[msg.sender] = 0; //                                  effects
        totalCredits -= owed;
        emit Withdrawn(msg.sender, to, owed);
        (bool ok,) = to.call{value: owed}(""); //                     interaction (result checked)
        if (!ok) revert TransferFailed();
    }

    function _setState(State next) private {
        emit StateChanged(state, next);
        state = next;
    }

    receive() external payable {
        revert DirectPaymentRejected();
    }

    fallback() external payable {
        revert DirectPaymentRejected();
    }
}
