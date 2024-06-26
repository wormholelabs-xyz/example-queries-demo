// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {IWormhole} from "wormhole-solidity-sdk/interfaces/IWormhole.sol";
import {QueryResponse} from "wormhole-solidity-sdk/QueryResponse.sol";
import {QueryTest} from "wormhole-solidity-sdk/testing/helpers/QueryTest.sol";

struct PerChainData {
    uint16 chainId;
    uint64 blockNum;
    bytes32 blockHash;
    uint64 blockTime;
    address contractAddress;
    bytes[] result;
}

struct ResponseData {
    bytes response;
    IWormhole.Signature[] signatures;
}

contract QueryResponseContract is QueryResponse {
    constructor(address _wormhole) QueryResponse(_wormhole) {}
    function test() public {}
}

contract QueryTestHelpers is Test {
    uint8 constant VERSION = 0x01;
    uint16 constant SENDER_CHAIN_ID = 0x0000;
    uint32 constant NONCE = 0xdd9914c6;
    bytes constant SIGNATURE =
        hex"ff0c222dc9e3655ec38e212e9792bf1860356d1277462b6bf747db865caca6fc08e6317b64ee3245264e371146b1d315d38c867fe1f69614368dc4430bb560f200";
    uint256 constant DEVNET_GUARDIAN_PRIVATE_KEY = 0xcfb12303a19cde580bb4dd771639b0d26bc68353645571a8cff516ab2ee113a0;
    uint64 constant BLOCK_NUM = 44440260;
    uint64 constant BLOCK_TIME = 1687961579;
    bytes constant finality = bytes("safe");

    QueryResponse queryResponse;

    function test() public {}

    function getSignature(bytes memory response) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 responseDigest = queryResponse.getResponseDigest(response);
        (v, r, s) = vm.sign(DEVNET_GUARDIAN_PRIVATE_KEY, responseDigest);
    }

    function prepareResponses(
        PerChainData[] memory perChainData,
        bytes memory callData,
        bytes4 selector,
        bytes memory _finality
    ) internal view returns (bytes memory response, IWormhole.Signature[] memory signatures) {
        require(perChainData.length > 0, "Array length cannot be zero");

        bytes[] memory perChainResponses = new bytes[](perChainData.length);
        bytes[] memory perChainQueries = new bytes[](perChainData.length);

        bool useFinality = _finality.length > 0;

        for (uint256 i = 0; i < perChainData.length; i++) {
            perChainResponses[i] = buildPerChainResponse(
                perChainData[i].chainId,
                perChainData[i].blockNum,
                perChainData[i].blockHash,
                perChainData[i].blockTime,
                perChainData[i].result,
                useFinality
            );
            perChainQueries[i] = buildPerChainQuery(
                perChainData[i].chainId,
                perChainData[i].blockNum,
                perChainData[i].contractAddress,
                uint8(perChainData[i].result.length),
                callData,
                selector,
                _finality
            );
        }

        ResponseData memory responseData = buildResponseData(perChainQueries, perChainResponses);
        return (responseData.response, responseData.signatures);
    }

    // Builds the response data from per-chain queries and responses
    function buildResponseData(bytes[] memory perChainQueries, bytes[] memory perChainResponses)
        internal
        view
        returns (ResponseData memory)
    {
        bytes memory concatenatedPerChainQueries = concatenateBytesArrays(perChainQueries);
        bytes memory concatenatedPerChainResponses = concatenateBytesArrays(perChainResponses);

        bytes memory response = concatenateQueryResponseBytesOffChain(
            VERSION,
            SENDER_CHAIN_ID,
            SIGNATURE,
            VERSION,
            NONCE,
            uint8(perChainQueries.length),
            concatenatedPerChainQueries,
            uint8(perChainResponses.length),
            concatenatedPerChainResponses
        );

        (uint8 sigV, bytes32 sigR, bytes32 sigS) = getSignature(response);
        IWormhole.Signature[] memory signatures = new IWormhole.Signature[](1);
        signatures[0] = IWormhole.Signature({r: sigR, s: sigS, v: sigV, guardianIndex: 0});

        return ResponseData({response: response, signatures: signatures});
    }

    // wrapper method to `buildPerChainResponseBytes`
    function buildPerChainResponse(
        uint16 _chainId,
        uint64 _blockNum,
        bytes32 _blockHash,
        uint64 _blockTime,
        bytes[] memory _results,
        bool useFinality
    ) internal view returns (bytes memory) {
        bytes memory ethCallResults = new bytes(0);
        for (uint256 i = 0; i < _results.length; i++) {
            ethCallResults = abi.encodePacked(ethCallResults, QueryTest.buildEthCallResultBytes(_results[i]));
        }

        if (useFinality) {
            return QueryTest.buildPerChainResponseBytes(
                _chainId,
                queryResponse.QT_ETH_CALL_WITH_FINALITY(),
                QueryTest.buildEthCallWithFinalityResponseBytes(
                    _blockNum, _blockHash, _blockTime, uint8(_results.length), ethCallResults
                )
            );
        } else {
            return QueryTest.buildPerChainResponseBytes(
                _chainId,
                queryResponse.QT_ETH_CALL(),
                QueryTest.buildEthCallResponseBytes(
                    _blockNum, _blockHash, _blockTime, uint8(_results.length), ethCallResults
                )
            );
        }
    }

    // wrapper method to `buildPerChainRequestBytes`
    function buildPerChainQuery(
        uint16 _chainId,
        uint64 _blockNum,
        address _contractAddress,
        uint8 numCalls,
        bytes memory callData,
        bytes4 selector,
        bytes memory _finality
    ) internal view returns (bytes memory) {
        bytes[] memory callDatas = new bytes[](numCalls);
        for (uint8 i = 0; i < numCalls; i++) {
            if (selector != bytes4(0)) {
                callDatas[i] = QueryTest.buildEthCallDataBytes(_contractAddress, abi.encodeWithSelector(selector));
            } else {
                callDatas[i] = QueryTest.buildEthCallDataBytes(_contractAddress, callData);
            }
        }

        bytes memory concatenatedCallData = concatenateCallData(callDatas);

        if (_finality.length > 0) {
            // With finality
            bytes memory ethCallWithFinalityRequest = QueryTest.buildEthCallWithFinalityRequestBytes(
                abi.encodePacked(_blockNum), _finality, numCalls, concatenatedCallData
            );

            return QueryTest.buildPerChainRequestBytes(
                _chainId, queryResponse.QT_ETH_CALL_WITH_FINALITY(), ethCallWithFinalityRequest
            );
        } else {
            // Without finality
            bytes memory ethCallRequest =
                QueryTest.buildEthCallRequestBytes(abi.encodePacked(_blockNum), numCalls, concatenatedCallData);

            return QueryTest.buildPerChainRequestBytes(_chainId, queryResponse.QT_ETH_CALL(), ethCallRequest);
        }
    }

    // Helper function to concatenate call data arrays
    function concatenateCallData(bytes[] memory callDatas) internal pure returns (bytes memory concatenated) {
        uint256 totalLength = 0;
        for (uint256 i = 0; i < callDatas.length; i++) {
            totalLength += callDatas[i].length;
        }

        concatenated = new bytes(totalLength);
        uint256 offset = 0;
        for (uint256 i = 0; i < callDatas.length; i++) {
            bytes memory data = callDatas[i];
            for (uint256 j = 0; j < data.length; j++) {
                concatenated[offset + j] = data[j];
            }
            offset += data.length;
        }
    }

    // Concatenates an array of `bytes` arrays into a single `bytes` array without encoding metadata.
    function concatenateBytesArrays(bytes[] memory arrays) internal pure returns (bytes memory concatenated) {
        uint256 totalLength = 0;
        for (uint256 i = 0; i < arrays.length; i++) {
            totalLength += arrays[i].length;
        }

        concatenated = new bytes(totalLength);
        uint256 offset = 0;
        for (uint256 i = 0; i < arrays.length; i++) {
            bytes memory array = arrays[i];
            for (uint256 j = 0; j < array.length; j++) {
                concatenated[offset + j] = array[j];
            }
            offset += array.length;
        }
    }

    // Concatenates query request and response bytes off-chain
    function concatenateQueryResponseBytesOffChain(
        uint8 _version,
        uint16 _senderChainId,
        bytes memory _signature,
        uint8 _queryRequestVersion,
        uint32 _queryRequestNonce,
        uint8 _numPerChainQueries,
        bytes memory _perChainQueries,
        uint8 _numPerChainResponses,
        bytes memory _perChainResponses
    ) internal pure returns (bytes memory) {
        bytes memory queryRequest = QueryTest.buildOffChainQueryRequestBytes(
            _queryRequestVersion, _queryRequestNonce, _numPerChainQueries, _perChainQueries
        );
        return QueryTest.buildQueryResponseBytes(
            _version, _senderChainId, _signature, queryRequest, _numPerChainResponses, _perChainResponses
        );
    }

    // === Builder functions ===
    function buildSinglePerChainData(
        uint16 chainId,
        uint64 blockNum,
        uint64 blockTime,
        address contractAddress,
        uint256 result
    ) internal view returns (PerChainData[] memory) {
        PerChainData[] memory perChainData = new PerChainData[](1);
        perChainData[0] = PerChainData({
            chainId: chainId,
            blockNum: blockNum,
            blockHash: bytes32(blockhash(blockNum)),
            blockTime: blockTime,
            contractAddress: contractAddress,
            result: new bytes[](1)
        });
        perChainData[0].result[0] = abi.encodePacked(result);
        return perChainData;
    }

    function buildMultiplePerChainData(
        uint16[] memory chainIds,
        uint64 blockNum,
        address[] memory contractAddresses,
        uint256[] memory results
    ) internal view returns (PerChainData[] memory) {
        require(
            chainIds.length == results.length && chainIds.length == contractAddresses.length,
            "Mismatch in array lengths"
        );
        PerChainData[] memory perChainData = new PerChainData[](chainIds.length);
        for (uint256 i = 0; i < chainIds.length; i++) {
            perChainData[i] = PerChainData({
                chainId: chainIds[i],
                blockNum: blockNum,
                blockHash: bytes32(blockhash(blockNum)),
                blockTime: uint64(block.timestamp * 1e6),
                contractAddress: contractAddresses[i],
                result: new bytes[](1)
            });
            perChainData[i].result[0] = abi.encodePacked(results[i]);
        }
        return perChainData;
    }

    function addressToBytes32(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }
}
