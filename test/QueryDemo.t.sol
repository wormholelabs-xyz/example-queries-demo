// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {
    QueryDemo,
    InvalidOwner,
    InvalidForeignChainID,
    UnexpectedResultLength,
    UnexpectedResultMismatch
} from "../src/QueryDemo.sol";
import {
    StaleBlockNum,
    StaleBlockTime,
    InvalidFunctionSignature,
    InvalidContractAddress,
    QueryResponse
} from "wormhole-solidity-sdk/QueryResponse.sol";
import {QueryTestHelpers, PerChainData} from "./helpers/QueryTestHelpers.sol";
import {WormholeMock} from "wormhole-solidity-sdk/testing/helpers/WormholeMock.sol";
import {IWormhole} from "wormhole-solidity-sdk/interfaces/IWormhole.sol";
import {QueryTest} from "wormhole-solidity-sdk/testing/helpers/QueryTest.sol";

contract QueryResponseContract is QueryResponse {
    constructor(address _wormhole) QueryResponse(_wormhole) {}
    function test() public {}
}

struct QueryResponseParams {
    uint8 version;
    uint16 senderChainId;
    bytes signature;
    bytes concatenatedPerChainQueries;
    uint8 numPerChainResponses;
    bytes concatenatedPerChainResponses;
}

contract QueryDemoTest is Test, QueryTestHelpers {
    QueryDemo public demo;
    WormholeMock wormholeMock;

    uint16 constant myChainId = 2;
    address constant addr1 = address(0x1234);
    bytes4 constant selector = bytes4(hex"916d5743");

    function setUp() public {
        wormholeMock = new WormholeMock();
        demo = new QueryDemo(address(this), address(wormholeMock), myChainId);
        queryResponse = new QueryResponseContract(address(wormholeMock));
    }

    // === Tests for constructor ===

    function test_Constructor() public view {
        // Test that the initial state for myChainID is set correctly
        QueryDemo.ChainEntry[] memory state = demo.getState();
        assertEq(state.length, 1);
        assertEq(state[0].chainID, myChainId);
        assertEq(state[0].contractAddress, address(demo));
        assertEq(state[0].counter, 0);
        assertEq(state[0].blockNum, 0);
        assertEq(state[0].blockTime, 0);

        // Test that GetMyCounter is set correctly
        assertEq(demo.GetMyCounter(), bytes4(hex"916d5743"));
    }

    function test_RevertWhen_ZeroAddressOnConstructor() public {
        vm.expectRevert(InvalidOwner.selector);
        new QueryDemo(address(0), address(wormholeMock), myChainId);
    }

    // === Tests for `updateRegistration` ===

    // Test that the updateRegistration function works correctly when updating an existing registration
    function test_updateExistingRegistration() public {
        QueryDemo.ChainEntry[] memory state = demo.getState();
        assertEq(state[0].contractAddress, address(demo));

        demo.updateRegistration(2, addr1);
        state = demo.getState();
        assertEq(state[0].contractAddress, addr1);
    }

    // Test that the updateRegistration function works correctly when adding a new registration
    function test_addNewRegistration() public {
        QueryDemo.ChainEntry[] memory state = demo.getState();
        assertEq(state.length, 1);

        demo.updateRegistration(3, addr1);
        state = demo.getState();
        assertEq(state[1].contractAddress, addr1);
    }

    // === Tests for `getMyCounter` ===

    function test_getMyCounter() public view {
        assertEq(demo.getMyCounter(), 0);
    }

    // Test that the getMyCounter function works correctly after an update
    function test_getMyCounterAfterUpdate() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        PerChainData[] memory perChainData =
            buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x1), 100);
        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        assertEq(demo.getMyCounter(), 0);

        demo.updateCounters(response, signatures);

        assertEq(demo.getMyCounter(), 1);
    }

    // === Tests for `updateCounters` ===

    // Test that the updateCounters function works correctly when updating the counter with responses one after
    function test_updateCountersWithOneResponse() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        PerChainData[] memory perChainData =
            buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x1), 100);
        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        demo.updateCounters(response, signatures);

        QueryDemo.ChainEntry[] memory state = demo.getState();
        assertEq(state[0].counter, 1);
        assertEq(state[0].blockNum, BLOCK_NUM);
        assertEq(state[0].blockTime, BLOCK_TIME);
        assertEq(state[1].counter, 100);
        assertEq(state[1].blockNum, BLOCK_NUM);
        assertEq(state[1].blockTime, BLOCK_TIME);

        perChainData = buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x1), 101);

        (response, signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        demo.updateCounters(response, signatures);

        state = demo.getState();
        assertEq(state[0].counter, 2);
        assertEq(state[0].blockNum, BLOCK_NUM);
        assertEq(state[0].blockTime, BLOCK_TIME);
        assertEq(state[1].counter, 101);
        assertEq(state[1].blockNum, BLOCK_NUM);
        assertEq(state[1].blockTime, BLOCK_TIME);
    }

    // Test that the updateCounters function works correctly when updating the counter with multiple responses
    function test_updateCountersWithMultipleResponses() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));
        demo.updateRegistration(3, address(0x3));

        uint16[] memory chainIds = new uint16[](2);
        chainIds[0] = 1;
        chainIds[1] = 3;

        address[] memory addresses = new address[](2);
        addresses[0] = address(0x1);
        addresses[1] = address(0x3);

        uint256[] memory results = new uint256[](2);
        results[0] = 101;
        results[1] = 103;

        PerChainData[] memory perChainData = buildMultiplePerChainData(chainIds, BLOCK_NUM, addresses, results);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        demo.updateCounters(response, signatures);

        QueryDemo.ChainEntry[] memory state = demo.getState();
        assertEq(state[0].counter, 1);
        assertEq(state[0].blockNum, BLOCK_NUM);
        assertEq(state[0].blockTime, BLOCK_TIME);
        assertEq(state[1].counter, 101);
        assertEq(state[1].blockNum, BLOCK_NUM);
        assertEq(state[1].blockTime, BLOCK_TIME);
        assertEq(state[2].counter, 103);
        assertEq(state[2].blockNum, BLOCK_NUM);
        assertEq(state[2].blockTime, BLOCK_TIME);
    }

    // Test that the updateCounters function reverts when the responses do not follow the foreign chain id sequences
    function test_RevertWhen_UnsequencedChainIDsInUpdateCounters() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));
        demo.updateRegistration(3, address(0x3));

        uint16[] memory chainIds = new uint16[](2);
        chainIds[0] = 3;
        chainIds[1] = 1;

        address[] memory addresses = new address[](2);
        addresses[0] = address(0x3);
        addresses[1] = address(0x1);

        uint256[] memory results = new uint256[](2);
        results[0] = 103;
        results[1] = 101;

        PerChainData[] memory perChainData = buildMultiplePerChainData(chainIds, BLOCK_NUM, addresses, results);
        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert(InvalidForeignChainID.selector);
        demo.updateCounters(response, signatures);
    }

    // Tests `numResponses != foreignChainIDs.length`
    function test_RevertWhen_ExcessiveResponsesInUpdateCounters() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        // Register a smaller number of chain IDs than the responses we will send
        demo.updateRegistration(1, address(0x1));

        // Prepare responses for three chains, which is more than the number of registrations
        uint16[] memory chainIds = new uint16[](2);
        chainIds[0] = 1;
        chainIds[1] = 3;

        address[] memory addresses = new address[](2);
        addresses[0] = address(0x1);
        addresses[1] = address(0x3);

        uint256[] memory results = new uint256[](2);
        results[0] = 101;
        results[1] = 103;

        PerChainData[] memory perChainData = buildMultiplePerChainData(chainIds, BLOCK_NUM, addresses, results);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        // Expect the function to revert due to an unexpected number of responses
        vm.expectRevert(UnexpectedResultLength.selector);
        demo.updateCounters(response, signatures);
    }

    // Test that the updateCounters function reverts when block number in subsequent responses is less than the previous one
    function test_RevertWhen_BlockNumIsStaleInUpdateCounters() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        PerChainData[] memory perChainData =
            buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x1), 100);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        demo.updateCounters(response, signatures);

        // try to update counter with a stale block number
        perChainData = buildSinglePerChainData(0x01, BLOCK_NUM - 1, uint64(BLOCK_TIME * 1e6), address(0x1), 100);

        (response, signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert(StaleBlockNum.selector);
        demo.updateCounters(response, signatures);
    }

    // Test that the updateCounters function reverts when block time in subsequent responses is 301 seconds less than the previous one
    function test_RevertWhen_BlockTimeIsStaleInUpdateCounters() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        // update counter with a certain block time
        PerChainData[] memory perChainData =
            buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x1), 100);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        demo.updateCounters(response, signatures);

        // try to update counter with a stale block time
        perChainData = buildSinglePerChainData(0x01, BLOCK_NUM, uint64((BLOCK_TIME - 301) * 1e6), address(0x1), 100);

        (response, signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert(StaleBlockTime.selector);
        demo.updateCounters(response, signatures);
    }

    // Test that the updateCounters function reverts when the function signature in the response is not GetMyCounter
    function test_RevertWhen_InvalidFunctionSignature() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        // Use an invalid function signature
        bytes4 invalidSignature = bytes4(keccak256("invalidFunction()"));

        PerChainData[] memory perChainData =
            buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x1), 100);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            invalidSignature,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert(InvalidFunctionSignature.selector);
        demo.updateCounters(response, signatures);
    }

    // Test that the updateCounters function reverts when the contract address in the response is not registered
    function test_RevertWhen_InvalidContractAddress() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        PerChainData[] memory perChainData =
            buildSinglePerChainData(0x01, BLOCK_NUM, uint64(BLOCK_TIME * 1e6), address(0x3), 100);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert(InvalidContractAddress.selector);
        demo.updateCounters(response, signatures);
    }

    // Test that the updateCounters function reverts when the result in the response is not a uint256
    function test_RevertWhen_ResultIsNotUint256() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(0x1));

        // Create a result that's not 32 bytes long
        bytes[] memory results = new bytes[](1);
        results[0] = abi.encodePacked(uint128(100));

        PerChainData[] memory perChainData = new PerChainData[](1);
        perChainData[0] = PerChainData({
            chainId: 0x01,
            blockNum: BLOCK_NUM,
            blockHash: bytes32(blockhash(BLOCK_NUM)),
            blockTime: uint64(block.timestamp * 1e6),
            contractAddress: address(0x1),
            result: results
        });

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert("result is not a uint256");
        demo.updateCounters(response, signatures);
    }

    // Test that updateCounters reverts when there are multiple results in the response
    function test_RevertWhen_MultipleResultsInUpdateCounters() public {
        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        demo.updateRegistration(1, address(demo));

        bytes[] memory results = new bytes[](2);
        results[0] = abi.encodePacked(uint256(100));
        results[1] = abi.encodePacked(uint256(200));

        PerChainData[] memory perChainData = new PerChainData[](1);
        perChainData[0] = PerChainData({
            chainId: 0x01,
            blockNum: BLOCK_NUM,
            blockHash: bytes32(blockhash(BLOCK_NUM)),
            blockTime: uint64(block.timestamp * 1e6),
            contractAddress: address(demo),
            result: results
        });

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        vm.expectRevert(UnexpectedResultMismatch.selector);
        demo.updateCounters(response, signatures);
    }

    // === Tests for `onlyOwner` ===

    // Test that the updateRegistration function reverts when the caller is not the owner
    function test_RevertWhen_CallerIsNotOwner() public {
        // This should revert because `0` is not the owner
        vm.expectRevert(InvalidOwner.selector);
        vm.prank(address(0));
        demo.updateRegistration(3, address(0x123));
    }

    // === Fuzz testing ===

    function testFuzz_updateCountersWithMultipleResponses(
        uint16 chainId2,
        uint16 chainId3,
        uint256 result2,
        uint256 result3
    ) public {
        vm.assume(chainId2 != chainId3);
        vm.assume(chainId2 != 2);
        vm.assume(chainId3 != 2);
        vm.assume(chainId2 > 0 && chainId2 < 65535);
        vm.assume(chainId3 > 0 && chainId3 < 65535);

        vm.roll(BLOCK_NUM);
        vm.warp(BLOCK_TIME);

        address addr2 = address(0x1);
        address addr3 = address(0x3);

        demo.updateRegistration(chainId2, addr2);
        demo.updateRegistration(chainId3, addr3);

        uint16[] memory chainIds = new uint16[](2);
        chainIds[0] = chainId2;
        chainIds[1] = chainId3;

        address[] memory addresses = new address[](2);
        addresses[0] = addr2;
        addresses[1] = addr3;

        uint256[] memory results = new uint256[](2);
        results[0] = result2;
        results[1] = result3;

        PerChainData[] memory perChainData = buildMultiplePerChainData(chainIds, BLOCK_NUM, addresses, results);

        (bytes memory response, IWormhole.Signature[] memory signatures) = prepareResponses(
            perChainData,
            new bytes(0), // empty bytes for callData
            selector,
            new bytes(0) // empty bytes for finality
        );

        demo.updateCounters(response, signatures);

        QueryDemo.ChainEntry[] memory state = demo.getState();
        assertEq(state[0].counter, 1);
        assertEq(state[0].blockNum, BLOCK_NUM);
        assertEq(state[0].blockTime, BLOCK_TIME);
        assertEq(state[1].counter, result2);
        assertEq(state[1].blockNum, BLOCK_NUM);
        assertEq(state[1].blockTime, BLOCK_TIME);
        assertEq(state[2].counter, result3);
        assertEq(state[2].blockNum, BLOCK_NUM);
        assertEq(state[2].blockTime, BLOCK_TIME);
    }
}
