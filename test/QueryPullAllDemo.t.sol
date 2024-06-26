// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {
    QueryPullAllDemo,
    InvalidOwner,
    InvalidForeignChainID,
    InvalidDestinationChain,
    InvalidContractAddress,
    InvalidFinality,
    InvalidResultHash,
    UnexpectedResultsLen,
    UnexpectedCallData,
    AlreadyRegistered
} from "../src/QueryPullAllDemo.sol";
import {MockWormhole} from "./mocks/MockWormhole.sol";
import {
    QueryResponse, ParsedPerChainQueryResponse, ParsedQueryResponse
} from "wormhole-solidity-sdk/QueryResponse.sol";
import {QueryTestHelpers, PerChainData, QueryResponseContract} from "./helpers/QueryTestHelpers.sol";
import {IWormhole} from "wormhole-solidity-sdk/interfaces/IWormhole.sol";

contract QueryPullAllDemoTest is Test, QueryTestHelpers {
    QueryPullAllDemo public demo;
    MockWormhole public wormhole;
    address private owner;

    uint16 constant MY_CHAIN_ID = 1;
    uint16 constant FOREIGN_CHAIN_ID = 2;
    address constant FOREIGN_CHAIN_CA = address(0x2);
    string constant TEST_MESSAGE = "Gm, Wormhole!";

    uint8 constant VALID_PAYLOAD_ID = 1;
    uint16 constant INVALID_CHAIN_ID = 999;
    string constant FINALIZED_STATUS = "finalized";
    string constant INVALID_FINALITY_STATUS = "safe";
    bytes4 constant LATEST_SENT_MESSAGE_SELECTOR = bytes4(keccak256("latestSentMessage(uint16)"));
    bytes4 constant INVALID_FUNCTION_SELECTOR = bytes4(keccak256("wrongFunction(uint16)"));
    uint256 constant VALID_RESULT_LENGTH = 32;
    uint256 constant INVALID_RESULT_LENGTH = 16;

    event pullMessageReceived(
        bytes32 previousHash,
        bytes32 latestHash,
        uint16 sourceChainID,
        uint8 payloadID,
        uint16 destinationChainID,
        string message
    );

    function setUp() public {
        wormhole = new MockWormhole(1, 2);
        owner = address(this);
        demo = new QueryPullAllDemo(owner, address(wormhole), MY_CHAIN_ID);
        queryResponse = new QueryResponseContract(address(wormhole));

        demo.updateRegistration(1, addressToBytes32(address(0x1)));
        demo.updateRegistration(2, addressToBytes32(address(0x2)));
        demo.updateRegistration(3, addressToBytes32(address(0x3)));
    }

    // === Tests for constructor ===

    function test_Constructor() public {
        // Attempt to send a message to the chain ID used in constructor
        bytes32 result = demo.sendPullMessage(MY_CHAIN_ID, TEST_MESSAGE);

        // The result should not be empty, indicating that the message was accepted
        assertFalse(result == bytes32(0), "Should accept message to own chain ID");

        // Verify that latestSentMessage returns the correct hash for MY_CHAIN_ID
        assertEq(demo.latestSentMessage(MY_CHAIN_ID), result, "Latest sent message hash mismatch");

        // Testing setting owner indirectly through updateRegistration because no other way to do it directly
        // Test that the owner is set correctly. If the owner is not set correctly, this should fail
        demo.updateRegistration(0x4, addressToBytes32(address(0x4)));
    }

    function test_RevertWhen_ZeroAddressOwnerOnConstructor() public {
        vm.expectRevert(InvalidOwner.selector);
        new QueryPullAllDemo(address(0), address(wormhole), MY_CHAIN_ID);
    }

    // === Tests for updateRegistration ===

    function test_UpdateRegistration() public {
        demo.updateRegistration(0x4, addressToBytes32(address(0x4)));
        assertEq(demo.chainRegistrations(4), addressToBytes32(address(0x4)));
    }

    function test_RevertWhen_AlreadyRegistered() public {
        vm.expectRevert(AlreadyRegistered.selector);
        demo.updateRegistration(FOREIGN_CHAIN_ID, bytes32(uint256(uint160(FOREIGN_CHAIN_CA))));
    }

    // === Tests for encodeMessage ===

    function test_EncodeMessage() public view {
        QueryPullAllDemo.Message memory message = QueryPullAllDemo.Message({
            payloadID: VALID_PAYLOAD_ID,
            destinationChainID: FOREIGN_CHAIN_ID,
            message: TEST_MESSAGE
        });

        bytes memory encoded = demo.encodeMessage(message);

        // Check the length of the encoded message
        assertEq(encoded.length, 1 + 2 + 2 + bytes(TEST_MESSAGE).length, "Incorrect encoded length");

        // Check the payloadID
        assertEq(uint8(encoded[0]), 1, "Incorrect payloadID");

        // Check the destinationChainID
        uint16 encodedChainID = uint16(uint8(encoded[1])) << 8 | uint16(uint8(encoded[2]));
        assertEq(encodedChainID, FOREIGN_CHAIN_ID, "Incorrect destinationChainID");

        // Check the message length
        uint16 encodedLength = uint16(uint8(encoded[3])) << 8 | uint16(uint8(encoded[4]));
        assertEq(encodedLength, bytes(TEST_MESSAGE).length, "Incorrect message length");

        // Check the message content
        bytes memory encodedMessage = new bytes(encodedLength);
        for (uint256 i = 0; i < encodedLength; i++) {
            encodedMessage[i] = encoded[i + 5];
        }
        assertEq(string(encodedMessage), TEST_MESSAGE, "Incorrect message content");
    }

    function test_EncodeMessage_EmptyString() public view {
        QueryPullAllDemo.Message memory message =
            QueryPullAllDemo.Message({payloadID: VALID_PAYLOAD_ID, destinationChainID: FOREIGN_CHAIN_ID, message: ""});

        bytes memory encoded = demo.encodeMessage(message);

        assertEq(encoded.length, 5, "Incorrect encoded length for empty string");
        assertEq(uint16(uint8(encoded[3])) << 8 | uint16(uint8(encoded[4])), 0, "Incorrect length for empty string");
    }

    function test_EncodeMessage_LongString() public view {
        string memory longMessage = new string(65535); // Max length for uint16
        for (uint256 i = 0; i < 65535; i++) {
            assembly {
                mstore8(add(longMessage, add(32, i)), 65) // ASCII 'A'
            }
        }

        QueryPullAllDemo.Message memory message = QueryPullAllDemo.Message({
            payloadID: VALID_PAYLOAD_ID,
            destinationChainID: FOREIGN_CHAIN_ID,
            message: longMessage
        });

        bytes memory encoded = demo.encodeMessage(message);

        assertEq(encoded.length, 1 + 2 + 2 + 65535, "Incorrect encoded length for long string");
        uint16 encodedLength = uint16(uint8(encoded[3])) << 8 | uint16(uint8(encoded[4]));
        assertEq(encodedLength, 65535, "Incorrect length for long string");
    }

    // === Tests for decodeMessage ===

    function test_DecodeMessage() public view {
        QueryPullAllDemo.Message memory originalMessage = QueryPullAllDemo.Message({
            payloadID: VALID_PAYLOAD_ID,
            destinationChainID: FOREIGN_CHAIN_ID,
            message: TEST_MESSAGE
        });

        bytes memory encoded = demo.encodeMessage(originalMessage);
        QueryPullAllDemo.Message memory decoded = demo.decodeMessage(encoded);

        assertEq(decoded.payloadID, originalMessage.payloadID, "Incorrect payloadID");
        assertEq(decoded.destinationChainID, originalMessage.destinationChainID, "Incorrect destinationChainID");
        assertEq(decoded.message, originalMessage.message, "Incorrect message");
    }

    function test_DecodeMessage_EmptyString() public view {
        QueryPullAllDemo.Message memory originalMessage =
            QueryPullAllDemo.Message({payloadID: VALID_PAYLOAD_ID, destinationChainID: FOREIGN_CHAIN_ID, message: ""});

        bytes memory encoded = demo.encodeMessage(originalMessage);
        QueryPullAllDemo.Message memory decoded = demo.decodeMessage(encoded);

        assertEq(decoded.payloadID, originalMessage.payloadID, "Incorrect payloadID");
        assertEq(decoded.destinationChainID, originalMessage.destinationChainID, "Incorrect destinationChainID");
        assertEq(decoded.message, originalMessage.message, "Incorrect message");
        assertEq(bytes(decoded.message).length, 0, "Message should be empty");
    }

    function test_DecodeMessage_LongString() public view {
        string memory longMessage = new string(65535); // Max length for uint16
        for (uint256 i = 0; i < 65535; i++) {
            assembly {
                mstore8(add(longMessage, add(32, i)), 65) // ASCII 'A'
            }
        }

        QueryPullAllDemo.Message memory originalMessage = QueryPullAllDemo.Message({
            payloadID: VALID_PAYLOAD_ID,
            destinationChainID: FOREIGN_CHAIN_ID,
            message: longMessage
        });

        bytes memory encoded = demo.encodeMessage(originalMessage);
        QueryPullAllDemo.Message memory decoded = demo.decodeMessage(encoded);

        assertEq(decoded.payloadID, originalMessage.payloadID, "Incorrect payloadID");
        assertEq(decoded.destinationChainID, originalMessage.destinationChainID, "Incorrect destinationChainID");
        assertEq(decoded.message, originalMessage.message, "Incorrect message");
        assertEq(bytes(decoded.message).length, 65535, "Incorrect message length");
    }

    function test_RevertWhen_InvalidPayloadIDOnDecodeMessage() public {
        bytes memory encoded = abi.encodePacked(
            uint8(2), // Invalid payloadID
            uint16(FOREIGN_CHAIN_ID),
            uint16(bytes(TEST_MESSAGE).length),
            bytes(TEST_MESSAGE)
        );

        vm.expectRevert("invalid payloadID");
        demo.decodeMessage(encoded);
    }

    function test_RevertWhen_InvalidLengthOnDecodeMessage() public {
        bytes memory encoded = abi.encodePacked(
            uint8(1),
            uint16(FOREIGN_CHAIN_ID),
            uint16(bytes(TEST_MESSAGE).length + 1), // Incorrect length
            bytes(TEST_MESSAGE)
        );

        vm.expectRevert("invalid message length");
        demo.decodeMessage(encoded);
    }

    // === Tests for sendPullMessage ===

    function test_SendPullMessage() public {
        bytes32 result = demo.sendPullMessage(FOREIGN_CHAIN_ID, TEST_MESSAGE);
        assertEq(result, demo.latestSentMessage(FOREIGN_CHAIN_ID));
    }

    function test_RevertWhen_MessageTooLargeOnSendPullMessage() public {
        string memory largeMessage = new string(type(uint16).max);
        vm.expectRevert("message too large");
        demo.sendPullMessage(FOREIGN_CHAIN_ID, largeMessage);
    }

    // === Tests for latestSentMessage ===

    function test_LatestSentMessage() public {
        // Initially, latest sent message should be bytes32(0)
        assertEq(demo.latestSentMessage(FOREIGN_CHAIN_ID), bytes32(0), "Initial latest sent message should be zero");

        // Send a message
        bytes32 sentHash = demo.sendPullMessage(FOREIGN_CHAIN_ID, TEST_MESSAGE);

        // Check that latestSentMessage returns the correct hash
        assertEq(demo.latestSentMessage(FOREIGN_CHAIN_ID), sentHash, "Latest sent message hash mismatch");

        // Send another message
        bytes32 newSentHash = demo.sendPullMessage(FOREIGN_CHAIN_ID, "Another message");

        // Check that latestSentMessage returns the new hash
        assertEq(demo.latestSentMessage(FOREIGN_CHAIN_ID), newSentHash, "Latest sent message hash not updated");

        // Check that latestSentMessage for a different chain ID is still zero
        assertEq(
            demo.latestSentMessage(INVALID_CHAIN_ID), bytes32(0), "Latest sent message for unused chain should be zero"
        );
    }

    // === Tests for lastReceivedMessage ===

    function test_LastReceivedMessage() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;

        // Check initial state
        assertEq(demo.lastReceivedMessage(sourceChainID), bytes32(0), "Initial last received message should be zero");

        // Send and receive first message
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage1 = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        (bytes memory response1, IWormhole.Signature[] memory signatures1) = preparePullMessageInputs(
            hash1, sourceChainID, FOREIGN_CHAIN_CA, FINALIZED_STATUS, 1, "", VALID_RESULT_LENGTH
        );

        bytes[] memory messages1 = new bytes[](1);
        messages1[0] = encodedMessage1;
        demo.receivePullMessages(response1, signatures1, messages1);
        assertEq(demo.lastReceivedMessage(sourceChainID), hash1, "Last received message should be updated to hash1");

        // Send and receive second message
        bytes32 hash2 = demo.sendPullMessage(destinationChainID, "Message 2");
        bytes memory encodedMessage2 = createAndEncodeTestMessage(1, destinationChainID, "Message 2");
        (bytes memory response2, IWormhole.Signature[] memory signatures2) = preparePullMessageInputs(
            hash2, sourceChainID, FOREIGN_CHAIN_CA, FINALIZED_STATUS, 1, "", VALID_RESULT_LENGTH
        );
        bytes[] memory messages2 = new bytes[](1);
        messages2[0] = encodedMessage2;
        demo.receivePullMessages(response2, signatures2, messages2);
        assertEq(demo.lastReceivedMessage(sourceChainID), hash2, "Last received message should be updated to hash2");

        // Try receiving the first message again (should not change the state)
        vm.expectRevert(InvalidResultHash.selector);
        demo.receivePullMessages(response1, signatures1, messages1);
        assertEq(demo.lastReceivedMessage(sourceChainID), hash2, "Last received message should still be hash2");

        // Check for a different chain ID
        uint16 anotherChainID = 3;
        assertEq(
            demo.lastReceivedMessage(anotherChainID),
            bytes32(0),
            "Last received message for another chain should be zero"
        );
    }

    // === Tests for receivePullMessages ===

    function test_ReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;

        // Send a few messages first
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes32 hash2 = demo.sendPullMessage(destinationChainID, "Message 2");
        bytes32 hash3 = demo.sendPullMessage(destinationChainID, "Message 3");

        // Create encoded messages
        bytes memory encodedMessage1 = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes memory encodedMessage2 = createAndEncodeTestMessage(1, destinationChainID, "Message 2");
        bytes memory encodedMessage3 = createAndEncodeTestMessage(1, destinationChainID, "Message 3");

        bytes[] memory messages = new bytes[](3);
        messages[0] = encodedMessage1;
        messages[1] = encodedMessage2;
        messages[2] = encodedMessage3;

        // Prepare the query response
        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash3, // Use the latest hash as the target
            sourceChainID,
            FOREIGN_CHAIN_CA,
            FINALIZED_STATUS,
            1,
            "",
            32
        );

        // Check initial state
        assertEq(demo.lastReceivedMessage(sourceChainID), bytes32(0), "Initial last received message should be zero");

        // Expect events to be emitted
        vm.expectEmit(true, true, true, true);
        emit pullMessageReceived(bytes32(0), hash1, sourceChainID, 1, destinationChainID, "Message 1");
        vm.expectEmit(true, true, true, true);
        emit pullMessageReceived(hash1, hash2, sourceChainID, 1, destinationChainID, "Message 2");
        vm.expectEmit(true, true, true, true);
        emit pullMessageReceived(hash2, hash3, sourceChainID, 1, destinationChainID, "Message 3");

        // Execute receivePullMessages
        demo.receivePullMessages(response, signatures, messages);

        // Check post-execution state
        assertEq(demo.lastReceivedMessage(sourceChainID), hash3, "Last received message should be updated");
    }

    function test_RevertWhen_InvalidForeignChainIDOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1, INVALID_CHAIN_ID, FOREIGN_CHAIN_CA, FINALIZED_STATUS, 1, "", VALID_RESULT_LENGTH
        );
        vm.expectRevert(InvalidForeignChainID.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    function test_RevertWhen_InvalidFinalityOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1,
            sourceChainID,
            FOREIGN_CHAIN_CA,
            INVALID_FINALITY_STATUS, // Invalid finality
            1,
            "",
            32
        );

        vm.expectRevert(InvalidFinality.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    function test_RevertWhen_UnexpectedResultsLenOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1,
            sourceChainID,
            FOREIGN_CHAIN_CA,
            FINALIZED_STATUS,
            2, // More than one result
            "",
            32
        );

        vm.expectRevert(UnexpectedResultsLen.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    function test_RevertWhen_InvalidContractAddressOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1,
            sourceChainID,
            address(0x1234), // Wrong contract address
            FINALIZED_STATUS,
            1,
            "",
            32
        );
        vm.expectRevert(InvalidContractAddress.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    function test_RevertWhen_UnexpectedCallDataOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1,
            sourceChainID,
            FOREIGN_CHAIN_CA,
            FINALIZED_STATUS,
            1,
            abi.encodeWithSelector(INVALID_FUNCTION_SELECTOR, MY_CHAIN_ID), // Wrong function selector
            32
        );
        vm.expectRevert(UnexpectedCallData.selector);
        demo.receivePullMessages(response, signatures, messages);
    }

    function test_RevertWhen_InvalidCallDataLengthOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1,
            sourceChainID,
            FOREIGN_CHAIN_CA,
            FINALIZED_STATUS,
            1,
            abi.encodeWithSelector(LATEST_SENT_MESSAGE_SELECTOR, MY_CHAIN_ID, 123), // Extra parameter
            32
        );
        vm.expectRevert("invalid callData length");
        demo.receivePullMessages(response, signatures, messages);
    }

    function test_RevertWhen_InvalidDestinationChainOnReceivePullMessages() public {
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        uint16 wrongDestinationChainID = INVALID_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(wrongDestinationChainID, "Message 1");
        bytes memory invalidEncodedMessage = createAndEncodeTestMessage(1, wrongDestinationChainID, "Message 1");
        bytes[] memory invalidMessages = new bytes[](1);
        invalidMessages[0] = invalidEncodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1, sourceChainID, FOREIGN_CHAIN_CA, FINALIZED_STATUS, 1, "", VALID_RESULT_LENGTH
        );
        vm.expectRevert(InvalidDestinationChain.selector);
        demo.receivePullMessages(response, signatures, invalidMessages);
    }

    function test_RevertWhen_InvalidResultLengthOnReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;

        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1, sourceChainID, FOREIGN_CHAIN_CA, FINALIZED_STATUS, 1, "", INVALID_RESULT_LENGTH
        );

        vm.expectRevert("result is not a bytes32");
        demo.receivePullMessages(response, signatures, messages);
    }

    // === Test for _truncateAddress ===

    function test_TruncateAddressThroughReceivePullMessages() public {
        uint16 destinationChainID = MY_CHAIN_ID;
        uint16 sourceChainID = FOREIGN_CHAIN_ID;

        // Test with valid address. We do not need to register the address for FOREIGN_CHAIN_ID since it's
        // already registered in `setUp`
        bytes32 hash1 = demo.sendPullMessage(destinationChainID, "Message 1");
        bytes memory encodedMessage = createAndEncodeTestMessage(1, destinationChainID, "Message 1");
        bytes[] memory messages = new bytes[](1);
        messages[0] = encodedMessage;
        (bytes memory response, IWormhole.Signature[] memory signatures) = preparePullMessageInputs(
            hash1, sourceChainID, FOREIGN_CHAIN_CA, FINALIZED_STATUS, 1, "", VALID_RESULT_LENGTH
        );

        // This should succeed with the valid address
        demo.receivePullMessages(response, signatures, messages);

        // Now test with an invalid address (non-zero in first 12 bytes)
        bytes32 invalidAddress = bytes32(uint256(1) << 160);
        vm.prank(owner);
        demo.updateRegistration(4, invalidAddress);
        (response, signatures) = preparePullMessageInputs(
            hash1, 4, address(uint160(uint256(invalidAddress))), FINALIZED_STATUS, 1, "", VALID_RESULT_LENGTH
        );

        vm.expectRevert("invalid EVM address");
        demo.receivePullMessages(response, signatures, messages);
    }

    // === Test for onlyOwner ===

    function test_OnlyOwner() public {
        uint16 chainID = 4;
        bytes32 validAddress = addressToBytes32(address(0x1234));

        // Test with owner
        vm.prank(owner);
        demo.updateRegistration(chainID, validAddress);

        // Test with non-owner
        address nonOwner = address(0x5678);
        vm.prank(nonOwner);
        vm.expectRevert(InvalidOwner.selector);
        demo.updateRegistration(chainID, validAddress);
    }

    // === Helper functions ===

    // Helper function to create and encode a test message for QueryPullAllDemo
    function createAndEncodeTestMessage(uint8 payloadID, uint16 destinationChainID, string memory message)
        internal
        pure
        returns (bytes memory)
    {
        QueryPullAllDemo.Message memory testMessage =
            QueryPullAllDemo.Message({payloadID: payloadID, destinationChainID: destinationChainID, message: message});
        return abi.encodePacked(
            testMessage.payloadID,
            testMessage.destinationChainID,
            uint16(bytes(testMessage.message).length),
            testMessage.message
        );
    }

    function preparePullMessageInputs(
        bytes32 targetHash,
        uint16 foreignChainID,
        address contractAddress,
        string memory finality,
        uint256 numResults,
        bytes memory callData,
        uint256 resultLength
    ) internal view returns (bytes memory response, IWormhole.Signature[] memory signatures) {
        if (callData.length == 0) {
            callData = abi.encodeWithSelector(LATEST_SENT_MESSAGE_SELECTOR, MY_CHAIN_ID);
        }
        PerChainData[] memory perChainData = new PerChainData[](1);
        perChainData[0] = PerChainData({
            chainId: foreignChainID,
            blockNum: BLOCK_NUM,
            blockHash: bytes32(blockhash(BLOCK_NUM)),
            blockTime: uint64(BLOCK_TIME * 1e6),
            contractAddress: contractAddress,
            result: new bytes[](numResults)
        });
        for (uint256 i = 0; i < numResults; i++) {
            perChainData[0].result[i] = new bytes(resultLength);
            for (uint256 j = 0; j < resultLength && j < 32; j++) {
                perChainData[0].result[i][j] = targetHash[j];
            }
        }
        (response, signatures) = prepareResponses(perChainData, callData, bytes4(0), bytes(finality));
    }
}
