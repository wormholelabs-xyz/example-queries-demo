// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {
    QueryPushPullDemo,
    InvalidContractAddress,
    InvalidForeignChainID,
    InvalidOwner,
    AlreadyReceived,
    InvalidDestinationChain,
    UnexpectedCallData,
    InvalidFinality
} from "../src/QueryPushPullDemo.sol";
import {
    EthCallWithFinalityQueryResponse,
    ParsedQueryResponse,
    QueryResponse
} from "wormhole-solidity-sdk/QueryResponse.sol";
import {MockWormhole} from "./mocks/MockWormhole.sol";
import {QueryTestHelpers, PerChainData} from "./helpers/QueryTestHelpers.sol";
import {IWormhole} from "wormhole-solidity-sdk/interfaces/IWormhole.sol";
import {WormholeSimulator} from "wormhole-solidity-sdk/testing/helpers/WormholeSimulator.sol";
import {QueryTest} from "wormhole-solidity-sdk/testing/helpers/QueryTest.sol";

contract QueryResponseContract is QueryResponse {
    constructor(address _wormhole) QueryResponse(_wormhole) {}
    function test() public {}
}

contract QueryPushPullDemoTest is Test, QueryTestHelpers {
    QueryPushPullDemo public demo;
    WormholeSimulator public simulator;
    MockWormhole public wormhole;
    address public owner;

    uint16 public constant MY_CHAIN_ID = 1;
    uint16 public constant FOREIGN_CHAIN_ID = 3;
    address public constant FOREIGN_CHAIN_CA = address(0x3);
    uint16 public constant INVALID_DEST_CHAIN_ID = 4;
    address public constant INVALID_CONTRACT_ADDRESS = address(0x4);
    uint8 public constant CONSISTENCY_LEVEL = 200;
    string public constant MESSAGE = "Gm Wormhole!";

    event pullMessagePublished(uint8 payloadID, uint64 sequence, uint16 destinationChainID, string message);
    event pullMessageReceived(
        uint16 sourceChainID, uint8 payloadID, uint64 sequence, uint16 destinationChainID, string message
    );
    event pushMessageReceived(
        uint16 sourceChainID, uint8 payloadID, uint64 sequence, uint16 destinationChainID, string message
    );

    function setUp() public {
        owner = address(this);
        wormhole = new MockWormhole(1, 2);
        demo = new QueryPushPullDemo(owner, address(wormhole), MY_CHAIN_ID);
        simulator = new WormholeSimulator(address(wormhole), DEVNET_GUARDIAN_PRIVATE_KEY);
        queryResponse = new QueryResponseContract(address(wormhole));

        // Register some test chains
        demo.updateRegistration(2, addressToBytes32(address(0x2)));
        demo.updateRegistration(3, addressToBytes32(address(0x3)));
    }

    // === Test for constructor ===

    // Test if the constructor initializes the sequence to 0
    function test_Constructor() public {
        demo = new QueryPushPullDemo(owner, address(wormhole), MY_CHAIN_ID);

        // Test that the sequence is initialized to 0
        assertEq(demo.sequence(), 0);
    }

    // Test if the constructor reverts when given a zero address for the owner
    function test_RevertWhen_ZeroAddressOnConstructor() public {
        vm.expectRevert(InvalidOwner.selector);
        new QueryPushPullDemo(address(0), address(wormhole), MY_CHAIN_ID);
    }

    // === Test for `EncodeMessage` ===

    // Test if the encodeMessage function correctly encodes a message
    function test_EncodeMessage() public view {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 12345, 2, MESSAGE);
        // Additional checks
        assertEq(encodedMessage.length, 25, "Encoded message length is incorrect");

        // Check individual components
        assertEq(uint8(encodedMessage[0]), 1, "PayloadID is incorrect");

        // Decode sequence
        uint64 decodedSequence;
        assembly {
            decodedSequence := mload(add(encodedMessage, 9))
        }
        decodedSequence = uint64(decodedSequence);
        assertEq(decodedSequence, 12345, "Sequence is incorrect");

        // Decode destinationChainID
        uint16 decodedChainID = uint16(uint8(encodedMessage[9])) << 8 | uint16(uint8(encodedMessage[10]));
        assertEq(decodedChainID, 2, "DestinationChainID is incorrect");

        // Decode message length
        uint16 decodedLength = uint16(uint8(encodedMessage[11])) << 8 | uint16(uint8(encodedMessage[12]));
        assertEq(decodedLength, 12, "Message length is incorrect");

        // Decode message content
        bytes memory messageBytes = new bytes(12);
        for (uint256 i = 0; i < 12; i++) {
            messageBytes[i] = encodedMessage[i + 13];
        }
        string memory decodedMessage = string(messageBytes);
        assertEq(decodedMessage, MESSAGE, "Message content is incorrect");
    }

    // === Test for `DecodeMessage` ===

    // Test if the decodeMessage function correctly decodes various message types
    function test_DecodeMessage() public {
        // Test case 1: Normal message
        QueryPushPullDemo.Message memory originalMessage =
            QueryPushPullDemo.Message({payloadID: 1, sequence: 12345, destinationChainID: 2, message: MESSAGE});
        _test_DecodeMessage(originalMessage);

        // Test case 2: Empty message
        originalMessage.message = "";
        _test_DecodeMessage(originalMessage);

        // Test case 3: Long message
        originalMessage.message =
            "This is a much longer message that tests the encoding and decoding of larger strings in our system.";
        _test_DecodeMessage(originalMessage);

        // Test case 4: Max values for sequence and destinationChainID
        originalMessage.sequence = type(uint64).max;
        originalMessage.destinationChainID = type(uint16).max;
        originalMessage.message = "Testing max values";
        _test_DecodeMessage(originalMessage);

        // Test case 5: Invalid payloadID
        bytes memory encodedInvalidMessage = createAndEncodeTestMessage(2, 1, 1, "Invalid");
        vm.expectRevert("invalid payloadID");
        demo.decodeMessage(encodedInvalidMessage);

        // Test case 6: Message too long
        bytes memory tooLongMessage = abi.encodePacked(
            uint8(1), // payloadID
            uint64(1), // sequence
            uint16(1), // destinationChainID
            uint16(4), // Correct length
            MESSAGE, // Correct message
            "Extra" // Extra data
        );
        vm.expectRevert("invalid message length");
        demo.decodeMessage(tooLongMessage);
    }

    function _test_DecodeMessage(QueryPushPullDemo.Message memory originalMessage) internal view {
        bytes memory encodedMessage = demo.encodeMessage(originalMessage);
        QueryPushPullDemo.Message memory decodedMessage = demo.decodeMessage(encodedMessage);

        assertEq(decodedMessage.payloadID, originalMessage.payloadID, "PayloadID mismatch");
        assertEq(decodedMessage.sequence, originalMessage.sequence, "Sequence mismatch");
        assertEq(decodedMessage.destinationChainID, originalMessage.destinationChainID, "DestinationChainID mismatch");
        assertEq(decodedMessage.message, originalMessage.message, "Message content mismatch");
    }

    // === Tests for `SendPushMessage` ===

    // Test if sendPushMessage correctly sends a message and returns the sequence
    function test_SendPushMessage() public {
        uint16 destinationChainID = 2;
        uint256 wormholeFee = wormhole.messageFee();

        // Call sendPushMessage
        uint64 returnedSequence = demo.sendPushMessage{value: wormholeFee}(destinationChainID, MESSAGE);

        // Check that the returned sequence matches the expected sequence
        assertEq(returnedSequence, 0);
    }

    // Test if sendPushMessage reverts when incorrect fee is provided
    function test_RevertWhen_IncorrectFeeOnSendPushMessage() public {
        uint16 destinationChainID = 2;
        simulator.setMessageFee(100);

        // Try to send with the wrong fee
        vm.expectRevert("incorrect fee amount");
        demo.sendPushMessage{value: 99}(destinationChainID, MESSAGE);

        // Try to send with the wrong fee
        vm.expectRevert("incorrect fee amount");
        demo.sendPushMessage{value: 101}(destinationChainID, MESSAGE);
    }

    // Test if sendPushMessage reverts when the message is too large
    function test_RevertWhen_LargeMessageOnSendPushMessage() public {
        uint16 destinationChainID = 2;
        string memory largeMessage = new string(type(uint16).max);

        uint256 wormholeFee = wormhole.messageFee();

        // Try to send a message that's too large
        vm.expectRevert("message too large");
        demo.sendPushMessage{value: wormholeFee}(destinationChainID, largeMessage);
    }

    // === Tests for `SendPullMessage` ===

    // Test if sendPullMessage correctly sends a message and updates the sequence
    function test_SendPullMessage() public {
        uint16 destinationChainID = 2;

        uint64 initialSequence = demo.sequence();

        vm.expectEmit(true, true, true, true);
        emit pullMessagePublished(1, initialSequence + 1, destinationChainID, MESSAGE);

        uint64 returnedSequence = demo.sendPullMessage(destinationChainID, MESSAGE);

        assertEq(returnedSequence, initialSequence + 1);
        assertEq(demo.sequence(), initialSequence + 1);

        // Verify that the message was marked as sent
        bytes memory encodedMessage = createAndEncodeTestMessage(1, returnedSequence, destinationChainID, MESSAGE);
        bytes32 digest =
            keccak256(abi.encodePacked(MY_CHAIN_ID, addressToBytes32(address(demo)), keccak256(encodedMessage)));
        assertTrue(demo.hasSentMessage(digest));
    }

    // Test if sendPullMessage can be called multiple times with correct sequence updates
    function test_SendPullMessageMultipleTimes() public {
        uint16 destinationChainID = 2;

        uint64 initialSequence = demo.sequence();

        for (uint256 i = 1; i <= 3; i++) {
            uint64 returnedSequence = demo.sendPullMessage(destinationChainID, MESSAGE);
            assertEq(returnedSequence, initialSequence + i);
            assertEq(demo.sequence(), initialSequence + i);
        }
    }

    // Test if sendPullMessage works correctly for different destination chains
    function test_SendPullMessageDifferentChains() public {
        uint64 sequence1 = demo.sendPullMessage(2, MESSAGE);
        uint64 sequence2 = demo.sendPullMessage(3, MESSAGE);

        assertEq(sequence2, sequence1 + 1);

        bytes memory encodedMessage1 = createAndEncodeTestMessage(1, sequence1, 2, MESSAGE);
        bytes memory encodedMessage2 = createAndEncodeTestMessage(1, sequence2, 3, MESSAGE);

        bytes32 digest1 =
            keccak256(abi.encodePacked(MY_CHAIN_ID, addressToBytes32(address(demo)), keccak256(encodedMessage1)));
        bytes32 digest2 =
            keccak256(abi.encodePacked(MY_CHAIN_ID, addressToBytes32(address(demo)), keccak256(encodedMessage2)));

        assertTrue(demo.hasSentMessage(digest1));
        assertTrue(demo.hasSentMessage(digest2));
    }

    // Test if sendPullMessage reverts when the message is too large
    function test_RevertWhen_LargeMessageOnSendPullMessage() public {
        uint16 destinationChainID = 2;
        string memory largeMessage = new string(type(uint16).max);

        vm.expectRevert("message too large");
        demo.sendPullMessage(destinationChainID, largeMessage);
    }

    // === Tests for `ReceivePushMessage` ===

    // Test if receivePushMessage correctly processes a received message
    function test_ReceivePushMessage() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 0, MY_CHAIN_ID, MESSAGE);

        bytes32 emitterAddress = addressToBytes32(FOREIGN_CHAIN_CA);
        uint64 sequence = 1;

        IWormhole.VM memory vm_ = createWormholeVM(FOREIGN_CHAIN_ID, emitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        vm.expectEmit(true, true, true, true);
        emit pushMessageReceived(
            FOREIGN_CHAIN_ID,
            1, // payloadID
            sequence,
            MY_CHAIN_ID,
            MESSAGE
        );
        demo.receivePushMessage(wormholeVM);

        // Check that the message has been marked as received
        bytes memory body = abi.encodePacked(
            uint32(block.timestamp),
            uint32(0), // nonce
            uint16(FOREIGN_CHAIN_ID),
            emitterAddress,
            sequence,
            CONSISTENCY_LEVEL,
            encodedMessage
        );
        bytes32 hash = keccak256(abi.encodePacked(keccak256(body)));
        assertTrue(demo.hasReceivedPushMessage(hash), "Message should be marked as received");
    }

    // Test if receivePushMessage reverts when given an invalid foreign chain ID
    function test_RevertWhen_InvalidForeignChainIDOnReceivePushMessage() public {
        bytes memory encodedMessage = createEncodedMessage(uint16(MY_CHAIN_ID));

        bytes32 emitterAddress = addressToBytes32(FOREIGN_CHAIN_CA);
        uint64 sequence = 1;
        uint16 invalidForeignChainID = 4; // This chain ID is not registered

        IWormhole.VM memory vm_ = createWormholeVM(invalidForeignChainID, emitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        vm.expectRevert(InvalidForeignChainID.selector);
        demo.receivePushMessage(wormholeVM);
    }

    // Test if receivePushMessage reverts when given an invalid contract address
    function test_RevertWhen_InvalidContractAddressOnReceivePushMessage() public {
        bytes memory encodedMessage = createEncodedMessage(uint16(MY_CHAIN_ID));

        bytes32 invalidEmitterAddress = addressToBytes32(INVALID_CONTRACT_ADDRESS);
        uint64 sequence = 1;

        IWormhole.VM memory vm_ = createWormholeVM(FOREIGN_CHAIN_ID, invalidEmitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        vm.expectRevert(InvalidContractAddress.selector);
        demo.receivePushMessage(wormholeVM);
    }

    // Test if receivePushMessage reverts when given an invalid Wormhole message
    function test_RevertWhen_InvalidWormholeMessageOnReceivePullMessages() public {
        bytes memory encodedMessage = createEncodedMessage(uint16(MY_CHAIN_ID));

        bytes32 emitterAddress = addressToBytes32(address(0x2));
        uint64 sequence = 1;

        IWormhole.VM memory vm_ = createWormholeVM(FOREIGN_CHAIN_ID, emitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        // invalidate VM
        wormhole.invalidateVM(wormholeVM);

        // Expect the call to revert with the reason provided by Wormhole
        vm.expectRevert();
        demo.receivePushMessage(wormholeVM);
    }

    // Test if receivePushMessage reverts when trying to receive the same message twice
    function test_RevertWhen_MessageAlreadyReceivedOnReceivePullMessages() public {
        bytes memory encodedMessage = createEncodedMessage(uint16(MY_CHAIN_ID));

        bytes32 emitterAddress = addressToBytes32(FOREIGN_CHAIN_CA);
        uint64 sequence = 1;

        IWormhole.VM memory vm_ = createWormholeVM(FOREIGN_CHAIN_ID, emitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        // First call should succeed
        demo.receivePushMessage(wormholeVM);

        // Second call with the same message should revert
        bytes memory body = abi.encodePacked(
            uint32(block.timestamp),
            uint32(0), // nonce
            uint16(FOREIGN_CHAIN_ID),
            emitterAddress,
            sequence,
            CONSISTENCY_LEVEL,
            encodedMessage
        );
        bytes32 hash = keccak256(abi.encodePacked(keccak256(body)));

        vm.expectRevert(abi.encodeWithSelector(AlreadyReceived.selector, hash));
        demo.receivePushMessage(wormholeVM);
    }

    // === Tests for `ReceivePullMessages` ===

    // Test if receivePullMessages correctly processes a received message
    function test_ReceivePullMessages() public {
        uint64 sequence = 1;
        bytes memory encodedMessage = createAndEncodeTestMessage(1, sequence, MY_CHAIN_ID, MESSAGE);
        (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) =
            preparePullMessageInputs(encodedMessage, FOREIGN_CHAIN_ID, FOREIGN_CHAIN_CA, 1);

        // Check initial state
        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));
        assertFalse(demo.hasReceivedMessage(digest), "Message should not be marked as received initially");

        // Expect the pullMessageReceived event to be emitted
        vm.expectEmit(true, true, true, true);
        emit pullMessageReceived(FOREIGN_CHAIN_ID, 1, sequence, MY_CHAIN_ID, MESSAGE);

        // Execute receivePullMessages
        demo.receivePullMessages(response, signatures, messages);

        // Check post-execution state
        assertTrue(demo.hasReceivedMessage(digest), "Message should be marked as received after execution");
    }

    // Test if receivePushMessage reverts when given an invalid destination chain
    function test_RevertWhen_InvalidDestinationChainOnReceivePushMessages() public {
        // `INVALID_DEST_CHAIN_ID` is not registered
        bytes memory encodedMessage = createEncodedMessage(uint16(INVALID_DEST_CHAIN_ID));

        bytes32 emitterAddress = addressToBytes32(FOREIGN_CHAIN_CA);
        uint64 sequence = 1;

        IWormhole.VM memory vm_ = createWormholeVM(FOREIGN_CHAIN_ID, emitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        vm.expectRevert(InvalidDestinationChain.selector);
        demo.receivePushMessage(wormholeVM);
    }

    // Test if receivePullMessages reverts when given an invalid foreign chain ID
    function test_RevertWhen_InvalidForeignChainIDOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);
        (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) =
            preparePullMessageInputs(encodedMessage, INVALID_DEST_CHAIN_ID, FOREIGN_CHAIN_CA, 1);

        vm.expectRevert(InvalidForeignChainID.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when given an invalid contract address
    function test_RevertWhen_InvalidContractAddressOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);
        (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) =
            preparePullMessageInputs(encodedMessage, FOREIGN_CHAIN_ID, INVALID_CONTRACT_ADDRESS, 1);

        vm.expectRevert(InvalidContractAddress.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when trying to receive an already received message
    function test_RevertWhen_AlreadyReceivedOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);
        (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) =
            preparePullMessageInputs(encodedMessage, FOREIGN_CHAIN_ID, FOREIGN_CHAIN_CA, 1);

        // First call should succeed
        demo.receivePullMessages(response, signatures, messages);

        // Second call with the same message should revert
        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));
        vm.expectRevert(abi.encodeWithSelector(AlreadyReceived.selector, digest));
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when given unexpected call data
    function test_RevertWhen_UnexpectedCallDataOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);

        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));

        // Use an invalid function selector
        bytes memory invalidCallData = abi.encodeWithSelector(bytes4(keccak256("invalidFunction(bytes32)")), digest);

        PerChainData[] memory perChainData =
            buildSinglePerChainData(FOREIGN_CHAIN_ID, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), FOREIGN_CHAIN_CA, 1);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            invalidCallData,
            bytes4(0), // empty bytes4 for selector
            finality
        );

        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        vm.expectRevert(UnexpectedCallData.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when given invalid call data length
    function test_RevertWhen_InvalidCallDataLengthOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);

        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));

        // Create an invalid callData with length != 36
        bytes memory invalidCallData =
            abi.encodeWithSelector(bytes4(keccak256("hasSentMessage(bytes32)")), digest, uint256(1));

        PerChainData[] memory perChainData =
            buildSinglePerChainData(FOREIGN_CHAIN_ID, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), FOREIGN_CHAIN_CA, 1);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            invalidCallData,
            bytes4(0), // empty bytes4 for selector
            finality
        );

        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        vm.expectRevert("invalid callData length");
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when given an invalid finality
    function test_RevertWhen_InvalidFinalityOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);

        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));

        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("hasSentMessage(bytes32)")), digest);

        PerChainData[] memory perChainData =
            buildSinglePerChainData(FOREIGN_CHAIN_ID, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), FOREIGN_CHAIN_CA, 1);
        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            callData,
            bytes4(0), // empty bytes4 for selector
            bytes("final")
        );

        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        vm.expectRevert(InvalidFinality.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when given an invalid result length
    function test_RevertWhen_InvalidResultLengthOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);

        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));

        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("hasSentMessage(bytes32)")), digest);

        // Create a PerChainData with an invalid result length (not 32 bytes)
        PerChainData[] memory perChainData = new PerChainData[](1);
        perChainData[0] = PerChainData({
            chainId: FOREIGN_CHAIN_ID,
            blockNum: BLOCK_NUM,
            blockHash: bytes32(blockhash(BLOCK_NUM)),
            blockTime: uint64(BLOCK_TIME * 1e6),
            contractAddress: FOREIGN_CHAIN_CA,
            result: new bytes[](1)
        });
        perChainData[0].result[0] = abi.encodePacked(uint8(1)); // Invalid result length

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            callData,
            bytes4(0), // empty bytes4 for selector
            finality
        );

        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        vm.expectRevert("result is not a bool");
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when the result is not true
    function test_RevertWhen_ResultNotTrueOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);
        (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) =
            preparePullMessageInputs(encodedMessage, FOREIGN_CHAIN_ID, FOREIGN_CHAIN_CA, 0); // Result is false

        vm.expectRevert("result is not true");
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if receivePullMessages reverts when given an invalid destination chain
    function test_RevertWhen_InvalidDestinationChainOnReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, INVALID_DEST_CHAIN_ID, MESSAGE);
        (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) =
            preparePullMessageInputs(encodedMessage, FOREIGN_CHAIN_ID, FOREIGN_CHAIN_CA, 1);

        vm.expectRevert(InvalidDestinationChain.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if hasSentMessage correctly identifies sent messages
    function test_HasSentMessage() public {
        // Send a pull message
        uint64 sequence = demo.sendPullMessage(2, MESSAGE);

        bytes memory encodedMessage = createAndEncodeTestMessage(1, sequence, 2, MESSAGE);
        bytes32 digest =
            keccak256(abi.encodePacked(MY_CHAIN_ID, addressToBytes32(address(demo)), keccak256(encodedMessage)));

        // Check that hasSentMessage returns true for the sent message
        assertTrue(demo.hasSentMessage(digest), "hasSentMessage should return true for sent message");

        // Check that hasSentMessage returns false for a random digest
        bytes32 randomDigest = keccak256(abi.encodePacked("random"));
        assertFalse(demo.hasSentMessage(randomDigest), "hasSentMessage should return false for random digest");
    }

    // Test if hasReceivedMessage correctly identifies received messages
    function test_HasReceivedMessage() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 1, MY_CHAIN_ID, MESSAGE);

        bytes32 digest =
            keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, addressToBytes32(FOREIGN_CHAIN_CA), keccak256(encodedMessage)));

        // Prepare and execute receivePullMessages
        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("hasSentMessage(bytes32)")), digest);
        PerChainData[] memory perChainData =
            buildSinglePerChainData(FOREIGN_CHAIN_ID, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), FOREIGN_CHAIN_CA, 1);
        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            callData,
            bytes4(0), // empty bytes4 for selector
            finality
        );
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;
        demo.receivePullMessages(response, signatures, messages);

        // Check that hasReceivedMessage returns true for the received message
        assertTrue(demo.hasReceivedMessage(digest), "hasReceivedMessage should return true for received message");

        // Check that hasReceivedMessage returns false for a random digest
        bytes32 randomDigest = keccak256(abi.encodePacked("random"));
        assertFalse(demo.hasReceivedMessage(randomDigest), "hasReceivedMessage should return false for random digest");
    }

    // Test if hasReceivedPushMessage correctly identifies received push messages
    function test_HasReceivedPushMessage() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 0, MY_CHAIN_ID, MESSAGE);

        bytes32 emitterAddress = addressToBytes32(FOREIGN_CHAIN_CA);
        uint64 sequence = 1;

        IWormhole.VM memory vm_ = createWormholeVM(3, emitterAddress, sequence, encodedMessage);

        bytes memory wormholeVM = simulator.encodeAndSignMessage(vm_);

        // Execute receivePushMessage
        demo.receivePushMessage(wormholeVM);

        // Calculate the digest
        bytes memory body = abi.encodePacked(
            uint32(block.timestamp),
            uint32(0), // nonce
            uint16(FOREIGN_CHAIN_ID),
            emitterAddress,
            sequence,
            CONSISTENCY_LEVEL,
            encodedMessage
        );
        bytes32 digest = keccak256(abi.encodePacked(keccak256(body)));

        // Check that hasReceivedPushMessage returns true for the received message
        assertTrue(
            demo.hasReceivedPushMessage(digest), "hasReceivedPushMessage should return true for received push message"
        );

        // Check that hasReceivedPushMessage returns false for a random digest
        bytes32 randomDigest = keccak256(abi.encodePacked("random"));
        assertFalse(
            demo.hasReceivedPushMessage(randomDigest), "hasReceivedPushMessage should return false for random digest"
        );
    }

    // Test if the address truncation works correctly in receivePullMessages
    function test_TruncateAddressThroughReceivePullMessages() public {
        bytes memory encodedMessage = createAndEncodeTestMessage(1, 0, MY_CHAIN_ID, MESSAGE);

        // Register a valid address for FOREIGN_CHAIN_ID
        // We registered this in `setUp()` but doing this again for display purposes
        bytes32 validAddress = addressToBytes32(FOREIGN_CHAIN_CA);
        demo.updateRegistration(FOREIGN_CHAIN_ID, validAddress);

        bytes32 digest = keccak256(abi.encodePacked(FOREIGN_CHAIN_ID, validAddress, keccak256(encodedMessage)));

        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("hasSentMessage(bytes32)")), digest);

        PerChainData[] memory perChainData =
            buildSinglePerChainData(FOREIGN_CHAIN_ID, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), FOREIGN_CHAIN_CA, 1);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            callData,
            bytes4(0), // empty bytes4 for selector
            finality
        );

        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        // This should succeed with the valid address
        demo.receivePullMessages(response, signatures, messages);

        // Now test with an invalid address (non-zero in first 12 bytes)
        bytes32 invalidAddress = bytes32(uint256(1) << 160);
        demo.updateRegistration(FOREIGN_CHAIN_ID, invalidAddress);

        (response, signatures) = prepareResponses(
            perChainData,
            callData,
            bytes4(0), // empty bytes4 for selector
            finality
        );

        vm.expectRevert("invalid EVM address");
        demo.receivePullMessages(response, signatures, messages);
    }

    // Test if the onlyOwner modifier works correctly
    function test_OnlyOwner() public {
        // Test function that uses onlyOwner modifier
        demo.updateRegistration(2, addressToBytes32(address(0x2)));

        // Test with non-owner address
        address nonOwner = address(0x1234);
        vm.prank(nonOwner);
        vm.expectRevert(InvalidOwner.selector);
        demo.updateRegistration(3, addressToBytes32(FOREIGN_CHAIN_CA));

        // Test with owner address
        vm.prank(owner);
        demo.updateRegistration(3, addressToBytes32(FOREIGN_CHAIN_CA));
    }

    // === Helper functions ===

    // Helper function to create a basic encoded QueryPushPullDemo message
    function createAndEncodeTestMessage(
        uint8 payloadID,
        uint64 sequence,
        uint16 destinationChainID,
        string memory message
    ) internal view returns (bytes memory) {
        QueryPushPullDemo.Message memory testMessage = QueryPushPullDemo.Message({
            payloadID: payloadID,
            sequence: sequence,
            destinationChainID: destinationChainID,
            message: message
        });
        return demo.encodeMessage(testMessage);
    }

    // Helper function to create a basic encoded message
    function createEncodedMessage(uint16 destinationChainID) internal pure returns (bytes memory) {
        return abi.encodePacked(
            uint8(1), // payloadID
            uint64(0), // sequence (not used in push messages)
            destinationChainID,
            uint16(bytes(MESSAGE).length),
            MESSAGE
        );
    }

    // Helper function to create a basic Wormhole VM
    function createWormholeVM(uint16 emitterChainId, bytes32 emitterAddress, uint64 sequence, bytes memory payload)
        internal
        view
        returns (IWormhole.VM memory)
    {
        return IWormhole.VM({
            version: 1,
            timestamp: uint32(block.timestamp),
            nonce: 0,
            emitterChainId: emitterChainId,
            emitterAddress: emitterAddress,
            sequence: sequence,
            consistencyLevel: CONSISTENCY_LEVEL,
            payload: payload,
            guardianSetIndex: 0,
            signatures: new IWormhole.Signature[](0),
            hash: bytes32(0)
        });
    }

    // Helper function to prepare receivePullMessages
    function preparePullMessageInputs(
        bytes memory encodedMessage,
        uint16 foreignChainID,
        address contractAddress,
        uint8 result
    ) internal view returns (bytes memory response, IWormhole.Signature[] memory signatures, bytes[] memory messages) {
        bytes32 digest =
            keccak256(abi.encodePacked(foreignChainID, addressToBytes32(contractAddress), keccak256(encodedMessage)));

        bytes memory callData = abi.encodeWithSelector(bytes4(keccak256("hasSentMessage(bytes32)")), digest);
        PerChainData[] memory perChainData =
            buildSinglePerChainData(foreignChainID, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), contractAddress, result);
        (response, signatures) = prepareResponses(perChainData, callData, bytes4(0), finality);
        messages = new bytes[](1);
        messages[0] = encodedMessage;
    }
}
